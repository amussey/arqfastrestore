// SPDX-License-Identifier: MIT
//! Scan command: walk all snapshots across all backup folders, collect file
//! metadata, deduplicate by content SHA, and emit a CSV for user review.
//!
//! ## What scan does
//!
//! For each backup folder (plan) in the backup root, scan walks every snapshot
//! (backup record) and every file in its tree.  It collects:
//!
//! - `path`            — the original file path
//! - `size_bytes`      — file size
//! - `mtime`           — last-modified timestamp (ISO 8601)
//! - `blob_sha`        — SHA of the first data blob (content fingerprint)
//! - `backup_uuid`     — UUID of the backup folder
//! - `snapshot_ts`     — Unix timestamp of the snapshot this file came from
//!
//! After walking all snapshots, it groups rows by `blob_sha`:
//!
//! - **Same blob_sha** → one CSV row.  `first_seen`/`last_seen` span the
//!   earliest/latest snapshots containing this exact content.  `snapshot_count`
//!   is the total.  `sources` is a deduplicated, comma-separated list of
//!   backup UUIDs that hold this blob.
//!
//! - **Same path, different blob_sha** → separate rows (content changed
//!   between snapshots).
//!
//! The output CSV has an empty `action` column for the user to fill in:
//!   `restore` / `skip` / `latest` / `largest` / `all`
//!
//! ## Glob filter
//!
//! `--filter` accepts a comma-separated list of glob patterns applied to the
//! **filename** component (not the full path).  For example:
//! `--filter '*.mov,*.mp4,*.jpg'` will only emit rows for files whose name
//! matches one of those patterns.  If `--filter` is omitted, all files are
//! included.
//!
//! ## Memory optimizations
//!
//! - **Compact SHA**: blob identifiers are stored as `[u8; 32]` (32 bytes)
//!   rather than a 64-char hex `String` (88 bytes). Hex encoding only happens
//!   at CSV-output time.
//! - **String interning**: `source_root`, `computer_name`, `backup_name`, and
//!   backup UUIDs appear in every `Accum` entry but have only 5–20 unique
//!   values across an entire scan.  A `StringPool` stores one copy of each
//!   and replaces per-entry `String` fields with `u16` indices.
//! - **Eager tree serialization**: instead of cloning each parsed `Tree` struct
//!   into a `pending_cache` Vec (which holds an entire snapshot's worth of
//!   large heap-allocated structs), we serialize each tree to compact bytes
//!   immediately after parsing and drop the struct graph.  One `fdatasync`
//!   per snapshot is still achieved by batching the raw-byte writes.
//! - **jemalloc**: declared in `main.rs`; returns freed pages to the OS
//!   aggressively, avoiding glibc arena growth during millions of small allocs.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::warn;

use crate::format::arq7::{BlobLoc, Node};
use crate::restore::{TreeCache, TreeParseFn};
use crate::storage::{BlobReader, DecryptFn};

/// Map from folder UUID → decryption function for that backup set.
///
/// Different backup sets may be encrypted with different keys.  Using a per-UUID
/// map ensures each set's tree blobs are decrypted with the correct key.
pub type DecryptMap = HashMap<String, DecryptFn>;

// ---------------------------------------------------------------------------
// String pool — intern repeated metadata strings
// ---------------------------------------------------------------------------

/// A compact string interner.  Each unique string is stored exactly once;
/// callers receive a `u16` index (supports up to 65,535 unique strings —
/// far more than the 5–20 distinct metadata values we expect in practice).
struct StringPool {
    strings: Vec<String>,
    index: HashMap<String, u16>,
}

impl StringPool {
    fn new() -> Self {
        Self {
            strings: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Return the index for `s`, inserting it if not already present.
    fn intern(&mut self, s: &str) -> u16 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = self.strings.len() as u16;
        self.strings.push(s.to_owned());
        self.index.insert(s.to_owned(), idx);
        idx
    }

    /// Retrieve the string for an index.
    fn get(&self, idx: u16) -> &str {
        &self.strings[idx as usize]
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Configuration for a scan run.
pub struct ScanConfig {
    /// Root path of the backup storage (parent of all plan UUID directories).
    /// Used as the default for any folder UUID not in `storage_root_map`.
    pub storage_root: PathBuf,
    /// Per-folder-UUID storage roots.  Arq5 backup sets use the UUID directory
    /// itself as the storage root (BlobLoc paths are relative to it), while
    /// Arq7 sets use the parent.  Any UUID absent from this map falls back to
    /// `storage_root`.
    pub storage_root_map: HashMap<String, PathBuf>,
    /// Per-folder-UUID decryption functions.  Each backup set may have a
    /// different encryption key; the map ensures the correct key is used for
    /// each UUID's tree blobs.  An absent entry means no decryption is needed.
    pub decrypt_map: DecryptMap,
    /// Default tree-parse function (used when folder UUID is absent from
    /// `parse_tree_map`).
    pub parse_tree: TreeParseFn,
    /// Per-folder-UUID tree-parse functions.  Arq5 buckets require a custom
    /// parse_tree that resolves pack indexes for that bucket; Arq7 folders
    /// share a single generic parser.  Any UUID absent from this map falls
    /// back to `parse_tree`.
    pub parse_tree_map: HashMap<String, TreeParseFn>,
    /// Comma-separated glob patterns to filter by filename.  `None` = all files.
    pub filter: Option<String>,
    /// If true, skip directory entries (they have no blob_sha).
    #[allow(dead_code)]
    pub files_only: bool,
    /// Optional persistent tree cache.  When provided, parsed tree blobs are
    /// cached so repeated walks of the same snapshot (or different snapshots
    /// sharing unchanged subtrees) skip the read→decrypt→parse pipeline.
    pub tree_cache: Option<Arc<TreeCache>>,
}

/// Compact SHA-256 representation: 32 bytes instead of a 64-char hex String.
///
/// This halves the per-entry cost of storing the content fingerprint.
type Sha256 = [u8; 32];

/// Incremental accumulator for a unique (path, blob_sha) pair.
///
/// `path` and `blob_sha` are NOT stored here — they live as the HashMap key,
/// so `into_iter()` at materialization time gives us ownership without cloning.
/// All repeated metadata strings are stored as `u16` indices into a `StringPool`.
struct Accum {
    size_bytes: u64,
    mtime_sec: i64,
    /// Interned index into `StringPool` for the `source_root` value.
    source_root_idx: u16,
    /// Interned index into `StringPool` for `computer_name`.
    computer_name_idx: u16,
    /// Interned index into `StringPool` for `backup_name`.
    backup_name_idx: u16,
    /// Interned indices into `StringPool` for each backup UUID that holds
    /// this blob.  At most ~20 backup sets, so a small Vec is fine.
    uuid_idxs: Vec<u16>,
    first_seen: u64,
    last_seen: u64,
    snapshot_count: usize,
}

/// One deduplicated output row.
#[derive(Debug)]
pub struct ScanRow {
    pub source_root: String,
    pub computer_name: String,
    pub backup_name: String,
    pub path: String,
    pub size_bytes: u64,
    pub mtime: String,
    pub blob_sha: String,
    /// Semicolon-separated list of backup folder UUIDs that contain this blob.
    pub sources: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub snapshot_count: usize,
    /// How many rows share the same `path` (content changed over time).
    pub path_count: usize,
    /// How many rows share the same `blob_sha` (same content, different names/locations).
    pub sha_count: usize,
    pub action: String,
}

/// Walk all backup folders, collect file metadata from every snapshot, and
/// write deduplicated CSV rows to `out`.
///
/// Memory is bounded to the number of unique (path, blob_sha) pairs — not
/// the total observations across all snapshots.  Each observation is merged
/// into the in-memory map immediately and then discarded.
pub fn run_scan<W: Write>(
    config: &ScanConfig,
    folders: &[(String, String, Vec<crate::format::arq7::BackupRecord>)],
    plan_meta: &HashMap<String, (String, String)>,
    out: &mut W,
) -> Result<()> {
    let is_tty = {
        use std::io::IsTerminal;
        std::io::stderr().is_terminal()
    };

    // Write CSV header — source_root first per user request.
    writeln!(
        out,
        "source_root,computer_name,backup_name,path,size_bytes,mtime,blob_sha,sources,first_seen,last_seen,snapshot_count,path_count,sha_count,action"
    )?;

    // Incremental dedup map: (path, Sha256) → Accum.
    // Merging happens inline as each file is visited — no Vec<Observation>.
    let mut dedup: HashMap<(String, Sha256), Accum> = HashMap::new();

    // String pool for metadata fields shared across many entries.
    let mut pool = StringPool::new();

    let total_snapshots: usize = folders.iter().map(|(_, _, recs)| recs.len()).sum();
    let mut snap_idx = 0usize;

    for (folder_uuid, local_path, records) in folders {
        let (computer_name, backup_name) = plan_meta
            .get(folder_uuid.as_str())
            .cloned()
            .unwrap_or_default();
        let mut visited_trees: HashSet<String> = HashSet::new();
        for record in records {
            snap_idx += 1;
            if !is_tty {
                eprintln!(
                    "scan: snapshot {snap_idx}/{total_snapshots} uuid={folder_uuid} ts={} unique_so_far={}",
                    record.timestamp,
                    dedup.len(),
                );
            } else {
                eprint!(
                    "\rscan: {snap_idx}/{total_snapshots} snapshots  {} unique files    ",
                    dedup.len(),
                );
            }

            let root_loc = match &record.root_tree_blob_loc {
                Some(loc) => loc.clone(),
                None => {
                    warn!("skipping snapshot ts={}: no root_tree_blob_loc", record.timestamp);
                    continue;
                }
            };

            let storage_root = config
                .storage_root_map
                .get(folder_uuid.as_str())
                .unwrap_or(&config.storage_root);
            let storage: Arc<dyn crate::storage::Storage> =
                Arc::new(crate::storage::LocalStorage::new(storage_root));
            let decrypt = config.decrypt_map.get(folder_uuid.as_str()).cloned();
            let blob_reader = BlobReader::new(storage, decrypt);

            let parse_tree = config
                .parse_tree_map
                .get(folder_uuid.as_str())
                .unwrap_or(&config.parse_tree);

            // Pending tree cache entries: store as serialized bytes rather than
            // cloned Tree structs to avoid holding large heap graphs.
            // One fdatasync per snapshot is achieved by flushing all at the end.
            let mut pending_cache_bytes: Vec<(String, Vec<u8>)> = Vec::new();

            let collect_result = collect_into_map(
                &blob_reader,
                &root_loc,
                "",
                parse_tree,
                config.tree_cache.as_deref(),
                folder_uuid,
                local_path,
                &computer_name,
                &backup_name,
                record.timestamp,
                config.filter.as_deref(),
                &mut dedup,
                &mut pool,
                &mut pending_cache_bytes,
                &mut visited_trees,
            );

            if let Err(e) = collect_result {
                warn!("scan: error walking snapshot ts={}: {e:#}", record.timestamp);
            }

            // Flush pending tree cache writes in a single transaction.
            if let Some(ref cache) = config.tree_cache
                && !pending_cache_bytes.is_empty()
            {
                cache.put_batch_raw(&pending_cache_bytes);
            }
        }
    }

    if is_tty {
        eprintln!(); // newline after \r progress
    }

    eprintln!(
        "scan: {} unique (path, blob) pairs across {} snapshots",
        dedup.len(),
        total_snapshots
    );

    // Materialise and sort. Using into_iter() gives ownership of (path, sha)
    // keys without an extra clone — path lives in the key, not duplicated in Accum.
    let mut rows: Vec<ScanRow> = dedup
        .into_iter()
        .map(|((path, sha), a)| {
            let mut uuid_strs: Vec<&str> = a
                .uuid_idxs
                .iter()
                .map(|&idx| pool.get(idx))
                .collect();
            uuid_strs.sort();
            ScanRow {
                source_root: pool.get(a.source_root_idx).to_owned(),
                computer_name: pool.get(a.computer_name_idx).to_owned(),
                backup_name: pool.get(a.backup_name_idx).to_owned(),
                path,
                size_bytes: a.size_bytes,
                mtime: format_ts(a.mtime_sec),
                blob_sha: hex::encode(sha),
                sources: uuid_strs.join(";"),
                first_seen: a.first_seen,
                last_seen: a.last_seen,
                snapshot_count: a.snapshot_count,
                path_count: 0,
                sha_count: 0,
                action: String::new(),
            }
        })
        .collect();

    // Sort: by path ascending, then by mtime ascending (earliest version first).
    rows.sort_by(|a, b| a.path.cmp(&b.path).then(a.mtime.cmp(&b.mtime)));

    // Compute path_count: how many rows share the same path.
    {
        let mut path_counts: HashMap<String, usize> = HashMap::new();
        for row in &rows {
            *path_counts.entry(row.path.clone()).or_insert(0) += 1;
        }
        for row in &mut rows {
            row.path_count = *path_counts.get(&row.path).unwrap_or(&1);
        }
    }

    // Compute sha_count: how many rows share the same blob_sha.
    {
        let mut sha_counts: HashMap<String, usize> = HashMap::new();
        for row in &rows {
            *sha_counts.entry(row.blob_sha.clone()).or_insert(0) += 1;
        }
        for row in &mut rows {
            row.sha_count = *sha_counts.get(&row.blob_sha).unwrap_or(&1);
        }
    }

    eprintln!("scan: writing {} CSV rows", rows.len());

    for row in &rows {
        write_csv_row(out, row)?;
    }

    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tree walking (metadata only — no blob data reads)
// ---------------------------------------------------------------------------

/// Recursively walk a tree blob, merging file metadata directly into the
/// deduplication map.  No intermediate `Vec` is allocated — each observation
/// is merged in-place and then discarded.
#[allow(clippy::too_many_arguments)]
fn collect_into_map(
    blob_reader: &BlobReader,
    tree_loc: &BlobLoc,
    path_prefix: &str,
    parse_tree: &TreeParseFn,
    tree_cache: Option<&TreeCache>,
    backup_uuid: &str,
    source_root: &str,
    computer_name: &str,
    backup_name: &str,
    snapshot_ts: u64,
    filter: Option<&str>,
    map: &mut HashMap<(String, Sha256), Accum>,
    pool: &mut StringPool,
    pending_cache_bytes: &mut Vec<(String, Vec<u8>)>,
    visited_trees: &mut HashSet<String>,
) -> Result<()> {
    // Read and parse the tree blob — check cache first.
    let tree_id = &tree_loc.identifier;
    // Only skip if we have already *successfully* walked this tree.  We must
    // not cache the id before the walk completes: if reading fails (e.g. a
    // missing object file), a later snapshot may supply the same tree_id from
    // a healthy blob, and we must not skip it.
    if visited_trees.contains(tree_id) {
        return Ok(());
    }
    let tree = if let Some(cache) = tree_cache
        && let Some(cached) = cache.get(tree_id)
    {
        // Mark as visited only after we confirm we can get the tree.
        visited_trees.insert(tree_id.clone());
        cached
    } else {
        let tree_bytes = blob_reader
            .read_blob(tree_loc)
            .with_context(|| format!("reading tree blob {tree_id}"))?;
        let parsed = (parse_tree)(&tree_bytes)
            .with_context(|| format!("parsing tree blob {tree_id}"))?;
        // Mark as visited only after successful read+parse so that a failed
        // attempt does not permanently block future snapshots with the same id.
        visited_trees.insert(tree_id.clone());
        // Serialize eagerly to bytes and queue for batch write.
        // This lets us drop the Tree struct immediately instead of cloning it
        // into a Vec<(String, Tree)> that holds the whole snapshot in memory.
        if tree_cache.is_some() {
            match bitcode::serialize(&parsed) {
                Ok(encoded) => pending_cache_bytes.push((tree_id.clone(), encoded)),
                Err(e) => warn!("scan: could not serialize tree {tree_id} for cache: {e:#}"),
            }
        }
        parsed
    };

    for (name, node) in tree.nodes {
        if node.deleted {
            continue;
        }

        let item_path = if path_prefix.is_empty() {
            name.clone()
        } else {
            format!("{path_prefix}/{name}")
        };

        if node.is_tree {
            // Recurse into subdirectory.
            if let Some(ref subtree_loc) = node.tree_blob_loc
                    && let Err(e) = collect_into_map(
                        blob_reader,
                        subtree_loc,
                        &item_path,
                        parse_tree,
                        tree_cache,
                        backup_uuid,
                        source_root,
                        computer_name,
                        backup_name,
                        snapshot_ts,
                        filter,
                        map,
                        pool,
                        pending_cache_bytes,
                        visited_trees,
                    )
            {
                warn!("scan: error walking subtree '{item_path}': {e:#}");
            }
        } else {
            // File node: merge into the dedup map immediately.
            if let Some(sha) = primary_blob_sha(&node)
                && passes_filter(&name, filter)
            {
                let source_root_idx = pool.intern(source_root);
                let computer_name_idx = pool.intern(computer_name);
                let backup_name_idx = pool.intern(backup_name);
                let uuid_idx = pool.intern(backup_uuid);

                let entry = map.entry((item_path, sha)).or_insert_with(|| Accum {
                    size_bytes: node.item_size,
                    mtime_sec: node.mtime_sec,
                    source_root_idx,
                    computer_name_idx,
                    backup_name_idx,
                    uuid_idxs: Vec::new(),
                    first_seen: snapshot_ts,
                    last_seen: snapshot_ts,
                    snapshot_count: 0,
                });
                entry.snapshot_count += 1;
                if snapshot_ts < entry.first_seen {
                    entry.first_seen = snapshot_ts;
                }
                if snapshot_ts > entry.last_seen {
                    entry.last_seen = snapshot_ts;
                }
                // UUID dedup: small list, linear scan is fine (~20 max).
                if !entry.uuid_idxs.contains(&uuid_idx) {
                    entry.uuid_idxs.push(uuid_idx);
                }
            }
        }
    }

    Ok(())
}

/// Extract the SHA-256 fingerprint of the primary data blob as `[u8; 32]`.
///
/// Returns `None` if there is no blob loc, the identifier is empty, or it is
/// not a valid 64-char lowercase hex string.
fn primary_blob_sha(node: &Node) -> Option<Sha256> {
    let id = node.data_blob_locs.first().map(|loc| &loc.identifier)?;
    let mut out = [0u8; 32];
    match id.len() {
        64 => {
            // SHA-256: 32 bytes
            hex::decode_to_slice(id.as_bytes(), &mut out).ok()?;
        }
        40 => {
            // SHA-1 (Arq5): 20 bytes — store in the first 20 bytes, rest stay 0
            hex::decode_to_slice(id.as_bytes(), &mut out[..20]).ok()?;
        }
        _ => return None,
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Glob filter
// ---------------------------------------------------------------------------

/// Returns true if `filename` matches any of the comma-separated glob patterns
/// in `filter`.  If `filter` is None or empty, all files pass.
fn passes_filter(filename: &str, filter: Option<&str>) -> bool {
    let Some(patterns) = filter else {
        return true;
    };
    for pat in patterns.split(',') {
        let pat = pat.trim();
        if pat.is_empty() {
            continue;
        }
        if glob_match(pat, filename) {
            return true;
        }
    }
    false
}

/// Minimal glob matching: `*` matches any sequence of characters within a
/// filename component (no path separator matching), `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_chars(&p, &t)
}

fn glob_match_chars(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            // `*` can match zero or more characters.
            glob_match_chars(&p[1..], t)
                || (!t.is_empty() && glob_match_chars(p, &t[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_chars(&p[1..], &t[1..]),
        (Some(pc), Some(tc)) => {
            pc.to_lowercase().eq(tc.to_lowercase()) && glob_match_chars(&p[1..], &t[1..])
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// CSV output
// ---------------------------------------------------------------------------

/// Write one CSV row, quoting fields that contain commas or quotes.
fn write_csv_row<W: Write>(out: &mut W, row: &ScanRow) -> Result<()> {
    writeln!(
        out,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        csv_field(&row.source_root),
        csv_field(&row.computer_name),
        csv_field(&row.backup_name),
        csv_field(&row.path),
        row.size_bytes,
        csv_field(&row.mtime),
        csv_field(&row.blob_sha),
        csv_field(&row.sources),
        row.first_seen,
        row.last_seen,
        row.snapshot_count,
        row.path_count,
        row.sha_count,
        csv_field(&row.action),
    )?;
    Ok(())
}

/// Quote a CSV field if it contains commas, double-quotes, or newlines.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Format a Unix timestamp (seconds) as `YYYY-MM-DD HH:MM:SS UTC`.
fn format_ts(sec: i64) -> String {
    if sec == 0 {
        return String::new();
    }
    // Manual UTC formatting without an extra dependency.
    use std::time::{Duration, UNIX_EPOCH};
    let secs = if sec >= 0 { sec as u64 } else { return sec.to_string() };
    // Sanity check: compute a SystemTime just to avoid blatant overflow;
    // we don't actually use it.
    if UNIX_EPOCH.checked_add(Duration::from_secs(secs)).is_none() {
        return sec.to_string();
    }
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Days since Unix epoch → Gregorian calendar.
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

/// Convert days-since-Unix-epoch to (year, month, day).
///
/// Uses the algorithm from the C standard (Proleptic Gregorian calendar).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_matches_extension() {
        assert!(glob_match("*.mov", "vacation.mov"));
        assert!(glob_match("*.mov", "VACATION.MOV")); // case-insensitive
        assert!(!glob_match("*.mov", "vacation.mp4"));
        assert!(glob_match("*.mov", ".mov")); // dot-file with just the extension
    }

    #[test]
    fn glob_question_matches_one_char() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn glob_no_wildcard_exact_match() {
        assert!(glob_match("readme.txt", "readme.txt"));
        assert!(!glob_match("readme.txt", "readme.md"));
    }

    #[test]
    fn passes_filter_none_allows_all() {
        assert!(passes_filter("anything.exe", None));
    }

    #[test]
    fn passes_filter_comma_separated() {
        assert!(passes_filter("video.mov", Some("*.mov,*.mp4")));
        assert!(passes_filter("clip.mp4", Some("*.mov,*.mp4")));
        assert!(!passes_filter("photo.jpg", Some("*.mov,*.mp4")));
    }

    #[test]
    fn format_ts_zero_is_empty() {
        assert_eq!(format_ts(0), "");
    }

    #[test]
    fn format_ts_known_date() {
        // 2023-06-14 00:00:00 UTC = 1686700800
        assert_eq!(format_ts(1686700800), "2023-06-14 00:00:00");
    }

    #[test]
    fn dedup_same_sha_merges() {
        let mut map: HashMap<(String, Sha256), Accum> = HashMap::new();
        let mut pool = StringPool::new();
        let sha = [0xabu8; 32];

        for (uuid, ts) in [("UUID1", 2000u64), ("UUID2", 3000u64)] {
            let source_root_idx = pool.intern("");
            let computer_name_idx = pool.intern("");
            let backup_name_idx = pool.intern("");
            let uuid_idx = pool.intern(uuid);
            let key = ("a/b.txt".to_string(), sha);
            let entry = map.entry(key).or_insert_with(|| Accum {
                size_bytes: 100,
                mtime_sec: 1000,
                source_root_idx,
                computer_name_idx,
                backup_name_idx,
                uuid_idxs: Vec::new(),
                first_seen: ts,
                last_seen: ts,
                snapshot_count: 0,
            });
            entry.snapshot_count += 1;
            if ts < entry.first_seen { entry.first_seen = ts; }
            if ts > entry.last_seen  { entry.last_seen  = ts; }
            if !entry.uuid_idxs.contains(&uuid_idx) {
                entry.uuid_idxs.push(uuid_idx);
            }
        }
        assert_eq!(map.len(), 1);
        let accum = map.values().next().unwrap();
        assert_eq!(accum.snapshot_count, 2);
        assert_eq!(accum.first_seen, 2000);
        assert_eq!(accum.last_seen, 3000);
        assert_eq!(accum.uuid_idxs.len(), 2);
    }

    #[test]
    fn dedup_different_sha_same_path_stays_separate() {
        let mut map: HashMap<(String, Sha256), Accum> = HashMap::new();
        let mut pool = StringPool::new();
        let sha1 = [0x11u8; 32];
        let sha2 = [0x22u8; 32];

        for (sha, ts, size) in [(sha1, 1000u64, 100u64), (sha2, 2000u64, 200u64)] {
            let source_root_idx = pool.intern("");
            let computer_name_idx = pool.intern("");
            let backup_name_idx = pool.intern("");
            let uuid_idx = pool.intern("UUID1");
            let key = ("doc.psd".to_string(), sha);
            map.entry(key).or_insert_with(|| Accum {
                size_bytes: size,
                mtime_sec: ts as i64,
                source_root_idx,
                computer_name_idx,
                backup_name_idx,
                uuid_idxs: vec![uuid_idx],
                first_seen: ts,
                last_seen: ts,
                snapshot_count: 1,
            });
        }
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn csv_field_quotes_commas() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn string_pool_intern_dedup() {
        let mut pool = StringPool::new();
        let i1 = pool.intern("hello");
        let i2 = pool.intern("world");
        let i3 = pool.intern("hello");
        assert_eq!(i1, i3);
        assert_ne!(i1, i2);
        assert_eq!(pool.get(i1), "hello");
        assert_eq!(pool.get(i2), "world");
    }

    #[test]
    fn primary_blob_sha_valid_hex() {
        use crate::format::arq7::{BlobLoc, Node};
        let sha_hex = "a".repeat(64); // 64 'a' chars → valid hex
        let node = Node {
            data_blob_locs: vec![BlobLoc {
                identifier: sha_hex.clone(),
                is_packed: false,
                is_large_pack: false,
                relative_path: None,
                offset: 0,
                length: 0,
                stretch_encryption_key: false,
                compression_type: 0,
                is_arq5_pack_entry: false,
            }],
            ..Default::default()
        };
        let sha = primary_blob_sha(&node).expect("should parse valid hex");
        assert_eq!(hex::encode(sha), sha_hex);
    }

    #[test]
    fn primary_blob_sha_sha1_padded() {
        // Arq5 uses SHA1 (40 hex chars / 20 bytes); result should be in first 20 bytes, rest zero.
        use crate::format::arq7::{BlobLoc, Node};
        let sha1_hex = "b".repeat(40); // 40 'b' chars → valid SHA1 hex
        let node = Node {
            data_blob_locs: vec![BlobLoc {
                identifier: sha1_hex.clone(),
                is_packed: false,
                is_large_pack: false,
                relative_path: None,
                offset: 0,
                length: 0,
                stretch_encryption_key: false,
                compression_type: 0,
                is_arq5_pack_entry: false,
            }],
            ..Default::default()
        };
        let sha = primary_blob_sha(&node).expect("should parse valid SHA1 hex");
        // First 20 bytes match SHA1; last 12 bytes are zero padding.
        let expected_prefix = hex::decode(&sha1_hex).unwrap();
        assert_eq!(&sha[..20], expected_prefix.as_slice());
        assert_eq!(&sha[20..], &[0u8; 12]);
    }

    #[test]
    fn primary_blob_sha_empty_returns_none() {
        use crate::format::arq7::Node;
        let node = Node { data_blob_locs: vec![], ..Default::default() };
        assert!(primary_blob_sha(&node).is_none());
    }

    #[test]
    fn primary_blob_sha_wrong_length_returns_none() {
        use crate::format::arq7::{BlobLoc, Node};
        let node = Node {
            data_blob_locs: vec![BlobLoc {
                identifier: "a".repeat(50), // neither 40 nor 64 chars
                is_packed: false,
                is_large_pack: false,
                relative_path: None,
                offset: 0,
                length: 0,
                stretch_encryption_key: false,
                compression_type: 0,
                is_arq5_pack_entry: false,
            }],
            ..Default::default()
        };
        assert!(primary_blob_sha(&node).is_none());
    }
}
