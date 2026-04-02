// SPDX-License-Identifier: MIT
//! Parallel restore engine.
//!
//! [`RestoreEngine`] drives the full restore pipeline in three phases:
//!
//! **Phase 1 — Walk:** Traverse backup trees on a dedicated thread, collecting
//! all [`RestoreItem`]s into a `Vec`.  Tree blobs are read sequentially to
//! avoid disk thrashing on spinning media.
//!
//! **Phase 2 — Sort:** Sort the collected items by `(pack_path, offset)` so
//! every pack file is read sequentially from start to finish, eliminating the
//! random-seek penalty that otherwise causes 10–13× read amplification.
//!
//! **Phase 3 — Restore:** Process items in sorted order, controlled by
//! `pack_concurrency`:
//! - `1` (default, recommended for spinning/USB disks): one pack at a time,
//!   fully sequential — zero seek overhead.
//! - `N > 1` (SSDs, fast network storage): up to N pack groups in flight
//!   simultaneously, keeping the CPU/decrypt pipeline saturated.

use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Instant;

use anyhow::{Context, Result};
use filetime::{FileTime, set_file_times};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::{debug, warn};

use crate::format::arq7::BackupRecord;
use crate::restore::tree_cache::TreeCache;
use crate::restore::tree_walker::{RestoreItem, TreeParseFn, reset_tree_counter, walk_tree};
use crate::storage::{BlobReader, DecryptFn, Storage};

/// Summary statistics returned from a restore operation.
pub struct RestoreStats {
    pub files_restored: usize,
    pub dirs_created: usize,
    pub bytes_written: u64,
    /// Number of items that failed (missing blobs, read errors, etc.).
    pub files_failed: usize,
}

/// Drives a full parallel restore from an Arq backup.
pub struct RestoreEngine {
    storage: Arc<dyn Storage>,
    decrypt: Option<DecryptFn>,
    dest_root: PathBuf,
    /// If `true`, simulate the restore without writing anything to disk.
    dry_run: bool,
    /// If `true`, print detailed phase timing and I/O stats after the restore.
    verbose: bool,
    /// Optional persistent tree cache to speed up repeated walks.
    cache: Option<TreeCache>,
    /// Pluggable tree-parsing function (Arq7 or Arq5).
    parse_tree: TreeParseFn,
    /// Number of pack groups to process concurrently.
    ///
    /// `1` = fully sequential (best for spinning disks / USB storage).
    /// `N > 1` = up to N packs in flight simultaneously (better for SSDs).
    pack_concurrency: usize,
}

impl RestoreEngine {
    /// Create a new `RestoreEngine`.
    ///
    /// - `storage`: the backup storage backend (local or cloud).
    /// - `decrypt`: decryption closure, or `None` for unencrypted backups.
    /// - `dest_root`: the directory under which restored files will be written.
    /// - `dry_run`: if `true`, parse and decrypt everything but write nothing to disk.
    /// - `verbose`: if `true`, print detailed timing and I/O stats after the restore.
    /// - `cache`: optional persistent tree cache; pass `None` to disable.
    /// - `parse_tree`: pluggable function that parses raw tree blob bytes into a [`Tree`].
    /// - `pack_concurrency`: number of packs to process concurrently (1 = fully sequential).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<dyn Storage>,
        decrypt: Option<DecryptFn>,
        dest_root: PathBuf,
        dry_run: bool,
        verbose: bool,
        cache: Option<TreeCache>,
        parse_tree: TreeParseFn,
        pack_concurrency: usize,
    ) -> Self {
        Self {
            storage,
            decrypt,
            dest_root,
            dry_run,
            verbose,
            cache,
            parse_tree,
            pack_concurrency: pack_concurrency.max(1),
        }
    }

    /// Restore all files from a single [`BackupRecord`].
    ///
    /// **Phase 1**: Walk trees (sequential) → collect all [`RestoreItem`]s.
    /// **Phase 2**: Sort by `(pack_path, offset)` → sequential reads per pack.
    /// **Phase 3**: Restore in sorted order with configurable pack concurrency.
    pub fn restore(&self, record: &BackupRecord) -> Result<RestoreStats> {
        let root_loc = record
            .root_tree_blob_loc
            .as_ref()
            .context("backup record has no root_tree_blob_loc — cannot restore")?;

        // Detect whether stderr is a real terminal.  When running under
        // `nohup`, SSH without a pty, or redirected to a log file, indicatif's
        // steady-tick thread would block trying to write escape sequences to a
        // non-TTY, hanging the process.  Use a hidden draw target instead.
        use std::io::IsTerminal;
        let is_tty = std::io::stderr().is_terminal();

        // When not a TTY (nohup, SSH pipe, log redirect) skip MultiProgress
        // entirely — even hidden MultiProgress deadlocks with thread::scope.
        // Use a plain hidden ProgressBar instead.
        let pb_walk = if is_tty {
            let mp = MultiProgress::new();
            let pb = mp.add(ProgressBar::new_spinner());
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.cyan} Phase 1/3: Walking trees...  {pos} trees  ({per_sec})",
                )
                .unwrap(),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(200));
            pb
        } else {
            ProgressBar::hidden()
        };

        // ---------------------------------------------------------------
        // Phase 1: Walk all trees, collect RestoreItems
        // ---------------------------------------------------------------
        reset_tree_counter();
        let walk_start = Instant::now();
        if !is_tty {
            eprintln!("phase=1/3 walking trees...");
        }

        // Unbounded channel: walker sends all items; main thread collects after join.
        // sync_channel would deadlock once the buffer fills (walker blocks on send
        // while main thread waits in join() instead of draining the receiver).
        let (tx, rx) = channel::<RestoreItem>();

        // Use thread::scope so the walker thread can borrow non-'static refs.
        let (walk_res, blob_reader_walk) = std::thread::scope(|s| {
            let blob_reader_walk = BlobReader::new(self.storage.clone(), self.decrypt.clone());
            let root_loc_ref = root_loc;
            let dest_root_ref = &self.dest_root;
            let cache_ref = self.cache.as_ref();
            let parse_tree_ref = &self.parse_tree;
            let pb_walk_ref = &pb_walk;

            let walker = s.spawn(move || {
                let res = walk_tree(
                    &blob_reader_walk,
                    root_loc_ref,
                    dest_root_ref,
                    cache_ref,
                    &tx,
                    pb_walk_ref,
                    parse_tree_ref,
                );
                pb_walk_ref.finish_and_clear();
                drop(tx);
                (res, blob_reader_walk)
            });

            walker.join().expect("walker thread panicked")
        });

        let walk_elapsed = walk_start.elapsed();

        if let Err(e) = walk_res {
            warn!("tree walk encountered an error: {e:#}");
        }

        // Collect all items from the channel (walker has finished by now).
        let all_items: Vec<RestoreItem> = rx.into_iter().collect();

        if self.verbose {
            eprintln!();
            eprintln!(
                "phase=walk items={} elapsed_s={:.3}",
                all_items.len(),
                walk_elapsed.as_secs_f64()
            );
            blob_reader_walk.print_stats("walk");
        }

        // Print tree cache hit/miss statistics (verbose only).
        if self.verbose
            && let Some(ref c) = self.cache
        {
            c.print_stats();
        }

        self.restore_items(all_items)
    }

    /// Restore a pre-collected list of [`RestoreItem`]s using the sort-by-pack pipeline.
    ///
    /// Skips Phase 1 (tree walk) and runs Phase 2 (sort) + Phase 3 (restore) directly.
    /// This is used by `restore --from-csv` where items are collected via a targeted
    /// tree walk rather than a full backup tree traversal.
    pub fn restore_items(&self, all_items: Vec<RestoreItem>) -> Result<RestoreStats> {
        use std::io::IsTerminal;
        let is_tty = std::io::stderr().is_terminal();
        let total_items = all_items.len();

        // ---------------------------------------------------------------
        // Phase 2: Sort by (pack_path, offset)
        // ---------------------------------------------------------------
        // they each require their own storage read anyway — no benefit from
        // sorting them relative to each other.
        //
        // For packed blobs, the primary key is the pack path so all reads
        // within a given pack file are contiguous, and the secondary key is
        // the offset so those reads are sequential within the pack.
        let sort_start = Instant::now();
        let mut all_items = all_items;
        all_items.sort_unstable_by(|a, b| {
            let a_key = sort_key(a);
            let b_key = sort_key(b);
            a_key.cmp(&b_key)
        });
        let sort_elapsed = sort_start.elapsed();

        if self.verbose {
            eprintln!("phase=sort elapsed_s={:.3}", sort_elapsed.as_secs_f64());
        }

        // ---------------------------------------------------------------
        // Phase 3: Restore in sorted (pack) order
        // ---------------------------------------------------------------

        // Count unique packs for progress display (dirs and standalone blobs
        // are grouped under a synthetic "" pack key).
        let total_bytes_est: u64 = all_items.iter().map(|item| item.node.item_size).sum();

        // Group items by pack key.  Items without a packed blob (dirs,
        // standalone blobs) share a synthetic "" bucket.
        let pack_groups: Vec<Vec<&RestoreItem>> = {
            let mut groups: Vec<(String, Vec<&RestoreItem>)> = Vec::new();
            let mut last_key: Option<String> = None;
            for item in &all_items {
                let key = pack_group_key(item);
                if last_key.as_deref() != Some(&key) {
                    groups.push((key.clone(), Vec::new()));
                    last_key = Some(key);
                }
                groups.last_mut().unwrap().1.push(item);
            }
            groups.into_iter().map(|(_, v)| v).collect()
        };
        let total_packs = pack_groups.len();

        let pb_restore = if is_tty {
            let pb = ProgressBar::new(total_items as u64);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} Phase 2/3: Restoring... \
                     pack {msg} · {pos}/{len} files · ETA {eta}",
                )
                .unwrap_or_else(|_| {
                    ProgressStyle::with_template(
                        "{spinner:.green} Restoring... {pos}/{len} files  ETA {eta}",
                    )
                    .unwrap()
                }),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(200));
            pb
        } else {
            eprintln!(
                "phase=2/3 restoring {total_items} items across {total_packs} packs (pack_concurrency={})...",
                self.pack_concurrency
            );
            ProgressBar::hidden()
        };

        // Track bytes written separately (progress bar doesn't have a built-in
        // bytes_written variable in all indicatif versions, use message for pack info).
        let bytes_written_atomic = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let restore_start = Instant::now();

        let blob_reader_restore = BlobReader::new(self.storage.clone(), self.decrypt.clone());

        // Use pack_concurrency to control parallelism: chunk the groups and
        // process each chunk in parallel (rayon), items within a group sequentially.
        let pack_concurrency = self.pack_concurrency;
        let pb_ref = &pb_restore;
        let bytes_ref = &bytes_written_atomic;
        let bw = &blob_reader_restore;
        let dry_run = self.dry_run;

        // Atomic counter for how many pack groups have been started.
        let pack_idx_atomic = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pack_idx_ref = &pack_idx_atomic;

        let results: Vec<ItemStats> = if pack_concurrency <= 1 {
            // Fully sequential: process one pack group at a time, items within
            // each group also sequential.  Best for spinning / USB storage.
            pack_groups
                .iter()
                .enumerate()
                .flat_map(|(gi, group)| {
                    let pack_num = gi + 1;
                    pb_ref.set_message(format!("{pack_num}/{total_packs}"));
                    group.iter().map(move |item| {
                        let stat = process_item(item, bw, dry_run);
                        pb_ref.inc(1);
                        bytes_ref.fetch_add(stat.bytes, std::sync::atomic::Ordering::Relaxed);
                        stat
                    })
                })
                .collect()
        } else {
            // Parallel across pack groups (chunks of pack_concurrency groups),
            // sequential within each group.
            //
            // Each chunk is a slice of groups; we process each chunk in a rayon
            // worker, then iterate groups+items sequentially within it.
            pack_groups
                .par_chunks(pack_concurrency)
                .flat_map_iter(|chunk| {
                    chunk.iter().flat_map(|group| {
                        let pack_num = pack_idx_ref
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        pb_ref.set_message(format!("{pack_num}/{total_packs}"));
                        group.iter().map(move |item| {
                            let stat = process_item(item, bw, dry_run);
                            pb_ref.inc(1);
                            bytes_ref.fetch_add(
                                stat.bytes,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            stat
                        })
                    })
                })
                .collect()
        };

        pb_restore.finish_and_clear();
        let restore_elapsed = restore_start.elapsed();

        let total_bytes_written = bytes_written_atomic.load(std::sync::atomic::Ordering::Relaxed);

        if self.verbose {
            eprintln!();
            eprintln!(
                "phase=restore items={total_items} packs={total_packs} \
                 bytes_written={total_bytes_written} elapsed_s={:.3}",
                restore_elapsed.as_secs_f64()
            );
            let _ = total_bytes_est; // suppress unused warning when verbose=false
            blob_reader_restore.print_stats("restore");
        }

        // ---------------------------------------------------------------
        // Aggregate results
        // ---------------------------------------------------------------
        let mut files_restored = 0usize;
        let mut dirs_created = 0usize;
        let mut bytes_written = 0u64;
        let mut files_failed = 0usize;
        let mut failure_counts: HashMap<String, usize> = HashMap::new();

        for s in results {
            files_restored += s.files;
            dirs_created += s.dirs;
            bytes_written += s.bytes;
            files_failed += s.failed;
            if let Some(cat) = s.failure_category {
                *failure_counts.entry(cat).or_insert(0) += 1;
            }
        }

        if !failure_counts.is_empty() {
            let mut cats: Vec<(String, usize)> = failure_counts.into_iter().collect();
            cats.sort_by(|a, b| b.1.cmp(&a.1));
            eprintln!("--- failure categories ({files_failed} total failures) ---");
            for (cat, count) in cats.iter().take(20) {
                eprintln!("  {count:>6}x  {cat}");
            }
            if cats.len() > 20 {
                eprintln!("  ... and {} more categories", cats.len() - 20);
            }
        }

        Ok(RestoreStats {
            files_restored,
            dirs_created,
            bytes_written,
            files_failed,
        })
    }
}

// ---------------------------------------------------------------------------
// Sort helpers
// ---------------------------------------------------------------------------

/// Returns a sortable key for a `RestoreItem`.
///
/// The key is `(is_unpacked, pack_path, offset)` where:
/// - `is_unpacked = 0` for packed blobs → sorted first, by path then offset
/// - `is_unpacked = 1` for dirs and standalone blobs → sorted last
///
/// This ensures all packed blobs are read sequentially through each pack
/// file before we do any standalone reads.
fn sort_key(item: &RestoreItem) -> (u8, &str, u64) {
    // Use the first data blob loc if available (most files have exactly one).
    if let Some(loc) = item.node.data_blob_locs.first()
        && loc.is_packed
    {
        let path = loc.relative_path.as_deref().unwrap_or(&loc.identifier);
        return (0, path, loc.offset);
    }
    // Directories and standalone blobs sort last.
    (1, "", 0)
}

/// Returns the pack group key for an item (used to build pack groups).
///
/// Items in the same pack share the same key.  Dirs and standalone blobs
/// each get a unique key so they form singleton groups.
fn pack_group_key(item: &RestoreItem) -> String {
    if let Some(loc) = item.node.data_blob_locs.first()
        && loc.is_packed
    {
        return loc
            .relative_path
            .clone()
            .unwrap_or_else(|| loc.identifier.clone());
    }
    // Unique key per item for non-packed items (each is its own "group").
    format!("__standalone__{}", item.dest_path.display())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Per-item statistics accumulated during parallel processing.
struct ItemStats {
    files: usize,
    dirs: usize,
    bytes: u64,
    failed: usize,
    /// Short failure category key (for counting, not full message), if any.
    failure_category: Option<String>,
}

/// Process a single [`RestoreItem`]: create a directory or write a file.
///
/// When `dry_run` is `true`, blobs are still read and decrypted (to validate
/// the backup) but nothing is written to disk — and no accumulation buffer
/// is allocated.
///
/// Blob read failures (missing files, corrupt data) are logged as warnings
/// and counted as failures rather than aborting the entire restore.
fn process_item(item: &RestoreItem, blob_reader: &BlobReader, dry_run: bool) -> ItemStats {
    macro_rules! fail {
        ($category:expr) => {
            return ItemStats {
                files: 0,
                dirs: 0,
                bytes: 0,
                failed: 1,
                failure_category: Some($category),
            }
        };
    }

    if item.node.is_tree {
        if !dry_run {
            // Directory: create the full path.
            if let Err(e) = fs::create_dir_all(&item.dest_path) {
                warn!("failed to create directory {:?}: {e}", item.dest_path);
                fail!(format!("mkdir: {e}"));
            }

            // Restore Unix permissions if available.
            #[cfg(unix)]
            apply_unix_permissions(&item.dest_path, item.node.mac_st_mode);
        }

        debug!(
            "{}dir {:?}",
            if dry_run {
                "[dry-run] would create "
            } else {
                "created "
            },
            item.dest_path
        );
        ItemStats {
            files: 0,
            dirs: 1,
            bytes: 0,
            failed: 0,
            failure_category: None,
        }
    } else {
        if !dry_run {
            // File: ensure parent directory exists.
            if let Some(parent) = item.dest_path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                warn!("failed to create parent dir {:?}: {e}", parent);
                fail!(format!("mkdir parent: {e}"));
            }
        }

        if dry_run {
            // Dry-run: read and decrypt each blob for validation but discard
            // immediately — no accumulation buffer needed.
            let mut bytes: u64 = 0;
            for (i, blob_loc) in item.node.data_blob_locs.iter().enumerate() {
                match blob_reader.read_blob(blob_loc) {
                    Ok(chunk) => bytes += chunk.len() as u64,
                    Err(e) => {
                        let cat = e
                            .to_string()
                            .lines()
                            .next()
                            .unwrap_or("unknown")
                            .to_string();
                        warn!("dry-run blob[{i}] {:?}: {e:#}", item.dest_path);
                        fail!(cat);
                    }
                }
            }
            debug!(
                "[dry-run] would restore file {:?} ({} bytes)",
                item.dest_path, bytes
            );
            ItemStats {
                files: 1,
                dirs: 0,
                bytes,
                failed: 0,
                failure_category: None,
            }
        } else {
            // Real restore: stream-write each blob chunk directly to a temp file,
            // then rename into place — no full-file accumulation buffer.
            let bytes = match write_file_streaming(
                &item.dest_path,
                item.node.data_blob_locs.iter(),
                blob_reader,
            ) {
                Ok(n) => n,
                Err(e) => {
                    warn!("failed to write {:?}: {e}", item.dest_path);
                    fail!(format!("write: {e}"));
                }
            };

            // Restore Unix permissions if available.
            #[cfg(unix)]
            apply_unix_permissions(&item.dest_path, item.node.mac_st_mode);

            // Restore timestamps (mtime and atime).
            restore_file_times(&item.dest_path, &item.node);

            debug!("restored file {:?} ({} bytes)", item.dest_path, bytes);
            ItemStats {
                files: 1,
                dirs: 0,
                bytes,
                failed: 0,
                failure_category: None,
            }
        }
    }
}

/// Global counter for generating unique temp-file suffixes.
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write blob chunks for `dest` to a temp file, then rename into place.
///
/// Streams each chunk directly to a `BufWriter` — never holds the full file
/// contents in memory simultaneously.  Returns total bytes written.
fn write_file_streaming<'a>(
    dest: &std::path::Path,
    blob_locs: impl Iterator<Item = &'a crate::format::arq7::BlobLoc>,
    blob_reader: &BlobReader,
) -> Result<u64> {
    let parent = dest.parent().unwrap_or(dest);
    let unique = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = parent.join(format!(
        ".arqfastrestore_tmp_{}_{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        unique,
    ));

    let mut bytes_written: u64 = 0;
    {
        let f = fs::File::create(&tmp_path)
            .with_context(|| format!("create temp file {:?}", tmp_path))?;
        let mut w = BufWriter::new(f);
        for (i, loc) in blob_locs.enumerate() {
            let chunk = blob_reader
                .read_blob(loc)
                .with_context(|| format!("read blob[{i}]"))?;
            w.write_all(&chunk)
                .with_context(|| format!("write blob[{i}] to {:?}", tmp_path))?;
            bytes_written += chunk.len() as u64;
        }
        w.flush().with_context(|| format!("flush {:?}", tmp_path))?;
    }

    fs::rename(&tmp_path, dest).with_context(|| format!("rename {:?} -> {:?}", tmp_path, dest))?;

    Ok(bytes_written)
}

/// Set Unix permission bits on `path` using the stored `st_mode`.
///
/// Only the lower 12 bits (permission + sticky/setuid/setgid) are applied.
#[cfg(unix)]
fn apply_unix_permissions(path: &std::path::Path, st_mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mode = st_mode & 0o7777;
    if mode == 0 {
        return;
    }
    let perms = fs::Permissions::from_mode(mode);
    if let Err(e) = fs::set_permissions(path, perms) {
        warn!("failed to set permissions on {:?}: {e}", path);
    }
}

/// Restore mtime (and atime) on `path` from the node's stored timestamps.
///
/// Uses `mtime_sec`/`mtime_nsec` for mtime; sets atime to the same value
/// since Arq does not store a separate atime.
fn restore_file_times(path: &std::path::Path, node: &crate::format::arq7::Node) {
    if node.mtime_sec == 0 {
        return;
    }
    let mtime = FileTime::from_unix_time(node.mtime_sec, node.mtime_nsec as u32);
    let atime = mtime;
    if let Err(e) = set_file_times(path, atime, mtime) {
        warn!("failed to set timestamps on {:?}: {e}", path);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::format::arq7::{BlobLoc, Node, Tree};
    use crate::restore::tree_walker::RestoreItem;
    use crate::storage::Storage;

    // ------------------------------------------------------------------
    // Minimal mock storage for engine tests
    // ------------------------------------------------------------------

    struct MockStorage {
        files: HashMap<String, Vec<u8>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                files: HashMap::new(),
            }
        }

        fn insert(&mut self, path: impl Into<String>, data: Vec<u8>) {
            self.files.insert(path.into(), data);
        }
    }

    impl Storage for MockStorage {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .with_context(|| format!("MockStorage: not found: {path}"))
        }

        fn list(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn exists(&self, path: &str) -> Result<bool> {
            Ok(self.files.contains_key(path))
        }
    }

    // ------------------------------------------------------------------
    // Helper: build a minimal BlobLoc (uncompressed, not packed, no encrypt)
    // ------------------------------------------------------------------

    fn simple_blob_loc(relative_path: &str, length: u64) -> BlobLoc {
        BlobLoc {
            identifier: relative_path.to_owned(),
            is_packed: false,
            is_large_pack: false,
            relative_path: Some(relative_path.to_owned()),
            offset: 0,
            length,
            stretch_encryption_key: false,
            compression_type: 0,
            is_arq5_pack_entry: false,
        }
    }

    // ------------------------------------------------------------------
    // Helper: build a minimal Node for a regular file
    // ------------------------------------------------------------------

    fn file_node(data_path: &str, data_len: u64) -> Node {
        Node {
            is_tree: false,
            tree_blob_loc: None,
            computer_os_type: 1,
            data_blob_locs: vec![simple_blob_loc(data_path, data_len)],
            acl_blob_loc: None,
            xattrs_blob_locs: vec![],
            item_size: data_len,
            contained_files_count: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            create_time_sec: 0,
            create_time_nsec: 0,
            username: None,
            group_name: None,
            deleted: false,
            mac_st_dev: 0,
            mac_st_ino: 0,
            mac_st_mode: 0o644,
            mac_st_nlink: 1,
            mac_st_uid: 0,
            mac_st_gid: 0,
            mac_st_rdev: 0,
            mac_st_flags: 0,
            win_attrs: 0,
            win_reparse_tag: None,
            win_reparse_point_is_directory: None,
        }
    }

    // ------------------------------------------------------------------
    // Helper: build a minimal Node for a directory
    // ------------------------------------------------------------------

    fn dir_node() -> Node {
        Node {
            is_tree: true,
            tree_blob_loc: None,
            computer_os_type: 1,
            data_blob_locs: vec![],
            acl_blob_loc: None,
            xattrs_blob_locs: vec![],
            item_size: 0,
            contained_files_count: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            create_time_sec: 0,
            create_time_nsec: 0,
            username: None,
            group_name: None,
            deleted: false,
            mac_st_dev: 0,
            mac_st_ino: 0,
            mac_st_mode: 0o755,
            mac_st_nlink: 1,
            mac_st_uid: 0,
            mac_st_gid: 0,
            mac_st_rdev: 0,
            mac_st_flags: 0,
            win_attrs: 0,
            win_reparse_tag: None,
            win_reparse_point_is_directory: None,
        }
    }

    // ------------------------------------------------------------------
    // Test: process_item creates a directory
    // ------------------------------------------------------------------

    #[test]
    fn process_item_creates_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("subdir");

        let storage = MockStorage::new();
        let reader = BlobReader::new(Arc::new(storage), None);

        let item = RestoreItem {
            dest_path: dest.clone(),
            node: dir_node(),
        };
        let stats = process_item(&item, &reader, false);

        assert!(dest.is_dir(), "directory should have been created");
        assert_eq!(stats.dirs, 1);
        assert_eq!(stats.files, 0);
        assert_eq!(stats.bytes, 0);
        assert_eq!(stats.failed, 0);
    }

    // ------------------------------------------------------------------
    // Test: process_item writes file data
    // ------------------------------------------------------------------

    #[test]
    fn process_item_writes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("hello.txt");

        let content = b"hello restore world".to_vec();
        let mut storage = MockStorage::new();
        storage.insert("blobs/hello", content.clone());

        let reader = BlobReader::new(Arc::new(storage), None);

        let item = RestoreItem {
            dest_path: dest.clone(),
            node: file_node("blobs/hello", content.len() as u64),
        };
        let stats = process_item(&item, &reader, false);

        assert!(dest.is_file(), "file should have been written");
        assert_eq!(fs::read(&dest).unwrap(), content);
        assert_eq!(stats.files, 1);
        assert_eq!(stats.bytes, content.len() as u64);
        assert_eq!(stats.failed, 0);
    }

    // ------------------------------------------------------------------
    // Test: process_item creates parent directories for files
    // ------------------------------------------------------------------

    #[test]
    fn process_item_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("a").join("b").join("c").join("file.bin");

        let content = b"nested file".to_vec();
        let mut storage = MockStorage::new();
        storage.insert("obj/nested", content.clone());

        let reader = BlobReader::new(Arc::new(storage), None);

        let item = RestoreItem {
            dest_path: dest.clone(),
            node: file_node("obj/nested", content.len() as u64),
        };
        process_item(&item, &reader, false);

        assert!(dest.is_file());
        assert_eq!(fs::read(&dest).unwrap(), content);
    }

    // ------------------------------------------------------------------
    // Test: no root_tree_blob_loc returns error
    // ------------------------------------------------------------------

    #[test]
    fn restore_without_root_loc_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(MockStorage::new());
        let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));
        let engine = RestoreEngine::new(
            storage,
            None,
            tmp.path().to_path_buf(),
            false,
            false,
            None,
            parse_tree,
            1, // pack_concurrency
        );

        let record = BackupRecord {
            timestamp: 0,
            root_tree_blob_loc: None,
            local_path: String::new(),
            arq_version: String::new(),
            is_complete: false,
        };

        assert!(engine.restore(&record).is_err());
    }

    // ------------------------------------------------------------------
    // Test: sort_key puts packed blobs before standalone
    // ------------------------------------------------------------------

    #[test]
    fn sort_key_packed_before_standalone() {
        let packed_item = RestoreItem {
            dest_path: PathBuf::from("/dest/file.bin"),
            node: Node {
                is_tree: false,
                tree_blob_loc: None,
                computer_os_type: 1,
                data_blob_locs: vec![BlobLoc {
                    identifier: "abc".to_string(),
                    is_packed: true,
                    is_large_pack: false,
                    relative_path: Some("packs/pack1.pack".to_string()),
                    offset: 100,
                    length: 50,
                    stretch_encryption_key: false,
                    compression_type: 0,
                    is_arq5_pack_entry: false,
                }],
                acl_blob_loc: None,
                xattrs_blob_locs: vec![],
                item_size: 50,
                contained_files_count: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
                create_time_sec: 0,
                create_time_nsec: 0,
                username: None,
                group_name: None,
                deleted: false,
                mac_st_dev: 0,
                mac_st_ino: 0,
                mac_st_mode: 0o644,
                mac_st_nlink: 1,
                mac_st_uid: 0,
                mac_st_gid: 0,
                mac_st_rdev: 0,
                mac_st_flags: 0,
                win_attrs: 0,
                win_reparse_tag: None,
                win_reparse_point_is_directory: None,
            },
        };

        let standalone_item = RestoreItem {
            dest_path: PathBuf::from("/dest/standalone.bin"),
            node: file_node("standalone/obj", 10),
        };

        let (packed_first, _, _) = sort_key(&packed_item);
        let (standalone_first, _, _) = sort_key(&standalone_item);
        assert!(
            packed_first < standalone_first,
            "packed blobs should sort before standalone"
        );
    }
}
