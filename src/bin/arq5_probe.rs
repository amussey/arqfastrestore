// SPDX-License-Identifier: MIT
//! Developer diagnostic tool for Arq5 backups.
//!
//! This is a standalone executable (source lives in `src/bin/` per Rust convention,
//! which is for binary source files — not to be confused with compiled output).
//! It is NOT part of the main `arqfastrestore` CLI; it is a verbose step-by-step
//! probe useful for debugging format issues or verifying a new Arq5 backup.
//!
//! It walks through all stages of reading an Arq5 backup:
//! load encryption keys → discover buckets → read HEAD commit → load pack indexes
//! → decrypt commit → parse tree → (optionally) recursive tree walk.
//! Each step prints intermediate results so you can see exactly what is happening.
//!
//! Usage:
//!   cargo run --release --bin arq5_probe -- <backup_uuid_path> <password> [--skip-blobs] [--walk-depth N]
//!
//! Example:
//!   cargo run --release --bin arq5_probe -- \
//!     '/path/to/backup/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX' "your-password"

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use arqfastrestore::crypto::{Arq5Keys, decrypt_arq5_object};
#[allow(unused_imports)]
use arqfastrestore::format::parse_pack_file;
use arqfastrestore::format::{Arq5Commit, Arq5Tree, PackIndex, PackIndexDb};

/// Get the cache directory, creating it if needed.
fn cache_dir() -> Result<PathBuf> {
    let dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("arqfastrestore");
    std::fs::create_dir_all(&dir).context("creating cache directory")?;
    Ok(dir)
}

/// Load pack indexes, using local cache when available.
/// `packset_key` is like "XXXXXXXX-YYYYYYYY-trees".
fn load_pack_indexes_cached(dir: &Path, packset_key: &str) -> Result<PackIndexDb> {
    let cache_path = cache_dir()?.join("pack_indexes.redb");

    // Try cache first
    let t0 = Instant::now();
    if let Some(db) = PackIndexDb::load_cache(&cache_path, packset_key)? {
        eprintln!(
            "  ✓ Loaded from cache: {} entries ({:.2}s)",
            db.total_entries(),
            t0.elapsed().as_secs_f64()
        );
        return Ok(db);
    }
    eprintln!("  Cache miss for {packset_key}, loading from storage...");

    // Load from storage
    let mut db = PackIndexDb::new();
    let count = load_pack_indexes(dir, &mut db)?;
    let load_time = t0.elapsed().as_secs_f64();
    eprintln!(
        "  ✓ Loaded {count} index files ({} entries, {:.1}s)",
        db.total_entries(),
        load_time
    );

    // Save to cache
    let t_save = Instant::now();
    db.save_cache(&cache_path, packset_key)?;
    eprintln!(
        "  ✓ Saved to cache ({:.2}s)",
        t_save.elapsed().as_secs_f64()
    );

    Ok(db)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: arq5_probe <backup_path> <password> [--walk-depth N] [--skip-blobs]");
        std::process::exit(1);
    }
    let backup_path = PathBuf::from(&args[1]);
    let password = &args[2];
    let skip_blobs = args.iter().any(|a| a == "--skip-blobs");
    let walk_depth: usize = args
        .windows(2)
        .find(|w| w[0] == "--walk-depth")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(0);

    let t0 = Instant::now();

    // Step 1: Load encryption keys
    eprintln!("=== Step 1: Load encryption keys ===");
    let key_path = backup_path.join("encryptionv2.dat");
    let key_dat = std::fs::read(&key_path).context("reading encryptionv2.dat")?;
    let keys = Arq5Keys::from_dat(&key_dat, password)?;
    eprintln!(
        "  ✓ Derived {} master keys ({:.1}s)",
        keys.keys.len(),
        t0.elapsed().as_secs_f64()
    );

    // Step 2: Discover buckets
    eprintln!("\n=== Step 2: Discover buckets ===");
    let buckets_dir = backup_path.join("buckets");
    let mut bucket_uuids = Vec::new();
    for entry in std::fs::read_dir(&buckets_dir).context("reading buckets/")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        eprintln!("  Bucket: {name}");

        // Try to decrypt the bucket plist
        let bucket_data = std::fs::read(entry.path())?;
        let arqo_data = strip_encrypted_prefix(&bucket_data);
        match decrypt_arq5_object(arqo_data, &keys) {
            Ok(plaintext) => {
                if let Ok(s) = std::str::from_utf8(&plaintext) {
                    // Try to extract bucket name from plist
                    if let Some(idx) = s.find("<key>BucketName</key>") {
                        let after = &s[idx..];
                        if let (Some(start), Some(end)) =
                            (after.find("<string>"), after.find("</string>"))
                        {
                            let bucket_name = &after[start + 8..end];
                            eprintln!("    BucketName: {bucket_name}");
                        }
                    }
                    if let Some(idx) = s.find("<key>LocalPath</key>") {
                        let after = &s[idx..];
                        if let (Some(start), Some(end)) =
                            (after.find("<string>"), after.find("</string>"))
                        {
                            let local_path = &after[start + 8..end];
                            eprintln!("    LocalPath: {local_path}");
                        }
                    }
                }
                eprintln!("    ✓ Decrypted ({} bytes)", plaintext.len());
            }
            Err(e) => eprintln!("    ✗ Decrypt failed: {e}"),
        }
        bucket_uuids.push(name);
    }

    if bucket_uuids.is_empty() {
        bail!("no buckets found");
    }

    // Step 3: Read HEAD commit SHA1 from refs/heads/master
    eprintln!("\n=== Step 3: Read HEAD commit SHA1 ===");
    for bucket_uuid in &bucket_uuids {
        let head_path = backup_path
            .join("bucketdata")
            .join(bucket_uuid)
            .join("refs/heads/master");
        let head_content = std::fs::read_to_string(&head_path)
            .with_context(|| format!("reading {}", head_path.display()))?;
        let head_sha1 = head_content.trim().trim_end_matches('Y');
        let is_encrypted = head_content.trim().ends_with('Y');
        eprintln!("  Bucket {bucket_uuid}:");
        eprintln!("    HEAD SHA1: {head_sha1}");
        eprintln!("    Encrypted: {is_encrypted}");

        // Step 4: Load pack indexes for tree packset (with local cache)
        eprintln!("\n=== Step 4: Load pack indexes (tree packset) ===");
        let tree_packset_dir = backup_path
            .join("packsets")
            .join(format!("{bucket_uuid}-trees"));
        // Cache key includes both the computer UUID and bucket UUID
        let computer_uuid = backup_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let packset_key = format!("{computer_uuid}-{bucket_uuid}-trees");
        let tree_index_db = load_pack_indexes_cached(&tree_packset_dir, &packset_key)?;

        // Step 5: Find commit in pack indexes
        eprintln!("\n=== Step 5: Resolve commit SHA1 ===");

        // Try standalone objects first
        let commit_data = if let Some(data) = try_read_standalone_object(&backup_path, head_sha1)? {
            eprintln!("  ✓ Found in standalone objects");
            data
        } else if let Some((pack_id, offset, length)) = tree_index_db.lookup(head_sha1) {
            eprintln!("  Found in tree pack: {pack_id} (offset={offset}, length={length})");
            let pack_path = tree_packset_dir.join(format!("{pack_id}.pack"));
            let t5 = Instant::now();
            let pack_data = std::fs::read(&pack_path)
                .with_context(|| format!("reading pack {}", pack_path.display()))?;
            eprintln!(
                "  Pack file: {} bytes ({:.2}s read)",
                pack_data.len(),
                t5.elapsed().as_secs_f64()
            );

            // The pack index offset points to the start of the object entry in the pack.
            // Pack entry format: mimetype(Arq string) + name(Arq string) + data_len(u64 BE) + data.
            // We need to skip the header and read just the data portion.
            extract_object_from_pack(&pack_data, offset as usize, length as usize)?
        } else {
            bail!("commit SHA1 {head_sha1} not found in standalone objects or tree pack indexes");
        };

        // Step 6: Decrypt the commit object
        eprintln!("\n=== Step 6: Decrypt commit object ===");
        let arqo_data = strip_encrypted_prefix(&commit_data);
        eprintln!(
            "  Raw data: {} bytes, ARQO data: {} bytes",
            commit_data.len(),
            arqo_data.len()
        );
        eprintln!(
            "  First 20 bytes: {:?}",
            &commit_data[..std::cmp::min(20, commit_data.len())]
        );
        let decrypted =
            decrypt_arq5_object(arqo_data, &keys).context("decrypting commit object")?;
        eprintln!("  ✓ Decrypted: {} bytes", decrypted.len());

        // Try to decompress if needed (gzip)
        let commit_bytes = try_decompress(&decrypted)?;

        // Step 7: Parse the commit
        eprintln!("\n=== Step 7: Parse commit ===");
        eprintln!(
            "  First 30 bytes: {:?}",
            std::str::from_utf8(&commit_bytes[..std::cmp::min(30, commit_bytes.len())])
                .unwrap_or("(binary)")
        );
        let commit = Arq5Commit::parse(&commit_bytes).context("parsing commit")?;
        eprintln!("  ✓ Commit version: {}", commit.version);
        eprintln!("    Author: {:?}", commit.author);
        eprintln!("    Comment: {:?}", commit.comment);
        eprintln!("    Tree SHA1: {:?}", commit.tree_sha1);
        eprintln!("    Stretch key: {}", commit.tree_encryption_key_stretched);
        eprintln!(
            "    Compression: {} (type={})",
            commit.tree_is_compressed, commit.tree_compression_type
        );
        eprintln!("    Location: {:?}", commit.location);
        eprintln!("    Created: {:?}", commit.creation_date_ms);
        eprintln!("    Complete: {}", commit.is_complete);
        eprintln!("    Arq version: {:?}", commit.arq_version);
        eprintln!("    Failed files: {}", commit.failed_files.len());
        eprintln!("    Parents: {}", commit.parent_commits.len());

        // Step 8: Resolve and parse the root tree
        if let Some(tree_sha1) = &commit.tree_sha1 {
            eprintln!("\n=== Step 8: Resolve root tree ===");
            let tree_data = if let Some(data) = try_read_standalone_object(&backup_path, tree_sha1)?
            {
                eprintln!("  ✓ Found tree in standalone objects");
                data
            } else if let Some((pack_id, offset, length)) = tree_index_db.lookup(tree_sha1) {
                eprintln!("  Found tree in pack: {pack_id} (offset={offset}, length={length})");
                let pack_path = tree_packset_dir.join(format!("{pack_id}.pack"));
                let pack_data = std::fs::read(&pack_path)?;
                extract_object_from_pack(&pack_data, offset as usize, length as usize)?
            } else {
                eprintln!("  ✗ Tree SHA1 {tree_sha1} not found!");
                continue;
            };

            // Decrypt
            let arqo_tree = strip_encrypted_prefix(&tree_data);
            let decrypted_tree =
                decrypt_arq5_object(arqo_tree, &keys).context("decrypting tree object")?;
            eprintln!("  ✓ Decrypted tree: {} bytes", decrypted_tree.len());

            // Decompress if needed
            let tree_bytes = if commit.tree_compression_type == 1 {
                eprintln!("  Decompressing (gzip)...");
                decompress_gzip(&decrypted_tree)?
            } else if commit.tree_compression_type == 2 {
                eprintln!("  Decompressing (LZ4)...");
                decompress_lz4(&decrypted_tree)?
            } else {
                decrypted_tree
            };
            eprintln!("  Tree bytes after decompression: {}", tree_bytes.len());

            // Parse tree
            eprintln!(
                "  First 30 bytes: {:?}",
                std::str::from_utf8(&tree_bytes[..std::cmp::min(30, tree_bytes.len())])
                    .unwrap_or("(binary)")
            );
            let tree = Arq5Tree::parse(&tree_bytes).context("parsing tree")?;
            eprintln!("  ✓ Tree version: {}", tree.version);
            eprintln!("    Children: {}", tree.children.len());
            eprintln!("    Missing nodes: {}", tree.missing_nodes.len());

            // List first N children
            let max_show = 30;
            for (i, (name, node)) in tree.children.iter().enumerate() {
                if i >= max_show {
                    eprintln!("    ... and {} more", tree.children.len() - max_show);
                    break;
                }
                let kind = if node.is_tree { "DIR " } else { "FILE" };
                let size = node.data_size;
                let chunks = node.data_blob_keys.len();
                eprintln!("    [{kind}] {name} ({size} bytes, {chunks} chunk(s))");
            }

            // Summary stats
            let total_files = tree.children.iter().filter(|(_, n)| !n.is_tree).count();
            let total_dirs = tree.children.iter().filter(|(_, n)| n.is_tree).count();
            eprintln!("\n  Root tree: {total_files} files, {total_dirs} dirs");
        }

        // Step 9: Load blob pack indexes (skip if --skip-blobs)
        if !skip_blobs {
            eprintln!("\n=== Step 9: Load blob pack indexes ===");
            let blob_packset_dir = backup_path
                .join("packsets")
                .join(format!("{bucket_uuid}-blobs"));
            let blob_packset_key = format!("{computer_uuid}-{bucket_uuid}-blobs");
            let _blob_index_db = load_pack_indexes_cached(&blob_packset_dir, &blob_packset_key)?;
        } else {
            eprintln!("\n=== Step 9: Skipping blob pack indexes (--skip-blobs) ===");
        }

        // Step 10: Recursive tree walk (if --walk-depth > 0)
        if walk_depth > 0
            && let Some(tree_sha1) = &commit.tree_sha1
        {
            eprintln!("\n=== Step 10: Recursive tree walk (depth={walk_depth}) ===");
            let compression_type = commit.tree_compression_type as u8;
            let mut stats = WalkStats::default();
            let mut pack_cache = PackCache::new(512 * 1024 * 1024);
            walk_tree_recursive(
                &backup_path,
                &tree_packset_dir,
                &tree_index_db,
                &keys,
                tree_sha1,
                compression_type,
                "",
                0,
                walk_depth,
                &mut stats,
                &mut pack_cache,
            )?;
            eprintln!(
                "\n  Walk stats: {} dirs, {} files, {:.2} GB total data, {} errors",
                stats.dirs,
                stats.files,
                stats.total_bytes as f64 / 1_073_741_824.0,
                stats.errors
            );
            eprintln!(
                "  Pack cache: {} hits, {} misses ({:.1}% hit rate)",
                stats.pack_cache_hits,
                stats.pack_cache_misses,
                if stats.pack_cache_hits + stats.pack_cache_misses > 0 {
                    stats.pack_cache_hits as f64
                        / (stats.pack_cache_hits + stats.pack_cache_misses) as f64
                        * 100.0
                } else {
                    0.0
                }
            );
        }
    }

    let total_time = t0.elapsed().as_secs_f64();
    eprintln!("\n=== Done in {total_time:.1}s ===");
    Ok(())
}

/// Strip the "encrypted" prefix from Arq5 encrypted blobs.
fn strip_encrypted_prefix(data: &[u8]) -> &[u8] {
    if data.starts_with(b"encrypted") {
        &data[9..]
    } else {
        data
    }
}

/// Try reading an object from standalone objects/ directory.
fn try_read_standalone_object(backup_path: &Path, sha1_hex: &str) -> Result<Option<Vec<u8>>> {
    if sha1_hex.len() < 2 {
        return Ok(None);
    }
    let prefix = &sha1_hex[..2];
    let suffix = &sha1_hex[2..];
    let path = backup_path.join("objects").join(prefix).join(suffix);
    match std::fs::read(&path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context(format!("reading standalone object at {}", path.display())),
    }
}

/// Load all .index files from a packset directory into a PackIndexDb.
fn load_pack_indexes(dir: &Path, db: &mut PackIndexDb) -> Result<usize> {
    let mut count = 0;
    let entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading packset dir {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("iterating packset dir")?;

    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".index") {
            continue;
        }
        let pack_id = name.trim_end_matches(".index").to_string();
        let data = std::fs::read(entry.path())
            .with_context(|| format!("reading index {}", entry.path().display()))?;
        let index =
            PackIndex::parse(&data, pack_id).with_context(|| format!("parsing index {name}"))?;
        db.add_index(index);
        count += 1;
    }
    Ok(count)
}

/// Try to decompress data (detect gzip by magic).
fn try_decompress(data: &[u8]) -> Result<Vec<u8>> {
    // Check for gzip magic (1f 8b)
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        eprintln!("  Detected gzip compression, decompressing...");
        return decompress_gzip(data);
    }
    Ok(data.to_vec())
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("gzip decompression")?;
    Ok(out)
}

fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| anyhow::anyhow!("LZ4 decompression failed: {e}"))
}

/// Stats for recursive tree walk.
#[derive(Default)]
struct WalkStats {
    dirs: u64,
    files: u64,
    total_bytes: u64,
    errors: u64,
    pack_cache_hits: u64,
    pack_cache_misses: u64,
}

/// In-memory cache of pack file contents (pack_id → data).
struct PackCache {
    packs: HashMap<String, Vec<u8>>,
    total_bytes: usize,
    budget: usize,
}

impl PackCache {
    fn new(budget: usize) -> Self {
        Self {
            packs: HashMap::new(),
            total_bytes: 0,
            budget,
        }
    }

    fn get_or_load(
        &mut self,
        packset_dir: &Path,
        pack_id: &str,
        stats: &mut WalkStats,
    ) -> Result<&Vec<u8>> {
        if self.packs.contains_key(pack_id) {
            stats.pack_cache_hits += 1;
            return Ok(self.packs.get(pack_id).unwrap());
        }

        stats.pack_cache_misses += 1;
        let pack_path = packset_dir.join(format!("{pack_id}.pack"));
        let data = std::fs::read(&pack_path)
            .with_context(|| format!("reading pack {}", pack_path.display()))?;
        let data_len = data.len();

        // Evict if over budget (simple: clear all)
        if self.total_bytes + data_len > self.budget {
            self.packs.clear();
            self.total_bytes = 0;
        }

        self.total_bytes += data_len;
        self.packs.insert(pack_id.to_string(), data);
        Ok(self.packs.get(pack_id).unwrap())
    }
}

/// Recursively walk an Arq5 tree, resolving child trees from pack indexes.
#[allow(clippy::too_many_arguments)]
fn walk_tree_recursive(
    backup_path: &Path,
    tree_packset_dir: &Path,
    tree_index_db: &PackIndexDb,
    keys: &Arq5Keys,
    tree_sha1: &str,
    compression_type: u8,
    path_prefix: &str,
    depth: usize,
    max_depth: usize,
    stats: &mut WalkStats,
    pack_cache: &mut PackCache,
) -> Result<()> {
    // Resolve tree object
    let tree_data = if let Some(data) = try_read_standalone_object(backup_path, tree_sha1)? {
        data
    } else if let Some((pack_id, offset, length)) = tree_index_db.lookup(tree_sha1) {
        let pack_data = pack_cache.get_or_load(tree_packset_dir, pack_id, stats)?;
        extract_object_from_pack(pack_data, offset as usize, length as usize)?
    } else {
        stats.errors += 1;
        eprintln!("  {path_prefix}: tree {tree_sha1} NOT FOUND");
        return Ok(());
    };

    // Decrypt
    let arqo_data = strip_encrypted_prefix(&tree_data);
    let decrypted = match decrypt_arq5_object(arqo_data, keys) {
        Ok(d) => d,
        Err(e) => {
            stats.errors += 1;
            eprintln!("  {path_prefix}: decrypt failed: {e}");
            return Ok(());
        }
    };

    // Decompress
    let tree_bytes = match compression_type {
        1 => decompress_gzip(&decrypted)?,
        2 => decompress_lz4(&decrypted)?,
        _ => decrypted,
    };

    // Parse
    let tree = match Arq5Tree::parse(&tree_bytes) {
        Ok(t) => t,
        Err(e) => {
            stats.errors += 1;
            eprintln!("  {path_prefix}: parse failed: {e}");
            return Ok(());
        }
    };

    // Count and recurse
    for (name, node) in &tree.children {
        let child_path = if path_prefix.is_empty() {
            name.clone()
        } else {
            format!("{path_prefix}/{name}")
        };

        if node.is_tree {
            stats.dirs += 1;
            stats.total_bytes += node.data_size;

            // Recurse if we haven't hit max depth
            if depth + 1 < max_depth {
                // The tree SHA1 is in the node's data_blob_keys
                if let Some(blob_key) = node.data_blob_keys.first()
                    && let Some(sha1) = &blob_key.sha1
                {
                    walk_tree_recursive(
                        backup_path,
                        tree_packset_dir,
                        tree_index_db,
                        keys,
                        sha1,
                        compression_type,
                        &child_path,
                        depth + 1,
                        max_depth,
                        stats,
                        pack_cache,
                    )?;
                }
            }
        } else {
            stats.files += 1;
            stats.total_bytes += node.data_size;
        }
    }

    // Periodic progress
    let total = stats.dirs + stats.files;
    if total.is_multiple_of(1000) && total > 0 {
        eprintln!(
            "  ... walked {} dirs, {} files, cache {}/{} hits/misses",
            stats.dirs, stats.files, stats.pack_cache_hits, stats.pack_cache_misses
        );
    }

    Ok(())
}

/// Extract an object from a pack file at the given offset.
///
/// The offset from the pack index points to the start of the object entry
/// in the pack file. Each entry is: mimetype(Arq string) + name(Arq string) +
/// data_len(u64 BE) + data(data_len bytes).
///
/// However, the offset/length semantics may vary. Try multiple strategies:
/// 1. Offset points directly to raw data (simplest)
/// 2. Offset points to the object entry header
/// 3. Parse the entire pack and match by position
fn extract_object_from_pack(pack_data: &[u8], offset: usize, length: usize) -> Result<Vec<u8>> {
    // Strategy 1: Check if ARQO magic or "encrypted" prefix is at offset
    if offset + 4 <= pack_data.len() {
        if &pack_data[offset..offset + 4] == b"ARQO" {
            let end = offset + length;
            if end > pack_data.len() {
                bail!("offset+length exceeds pack size");
            }
            return Ok(pack_data[offset..end].to_vec());
        }
        if offset + 9 <= pack_data.len() && &pack_data[offset..offset + 9] == b"encrypted" {
            let end = offset + length;
            if end > pack_data.len() {
                bail!("offset+length exceeds pack size");
            }
            return Ok(pack_data[offset..end].to_vec());
        }
    }

    // Strategy 2: The offset points to the pack entry header.
    // Parse: mimetype(Arq string: 1 byte null flag + opt u64 len + bytes) +
    //        name(same) + data_len(u64) + data
    let entry_data = &pack_data[offset..];
    let mut pos = 0;

    // Skip mimetype string
    if entry_data[pos] == 0 {
        pos += 1; // null
    } else {
        pos += 1; // isNotNull
        let len = u64::from_be_bytes(entry_data[pos..pos + 8].try_into()?) as usize;
        pos += 8 + len;
    }

    // Skip name string
    if entry_data[pos] == 0 {
        pos += 1;
    } else {
        pos += 1;
        let len = u64::from_be_bytes(entry_data[pos..pos + 8].try_into()?) as usize;
        pos += 8 + len;
    }

    // Read data_len
    let data_len = u64::from_be_bytes(entry_data[pos..pos + 8].try_into()?) as usize;
    pos += 8;

    let data_start = offset + pos;
    let data_end = data_start + data_len;
    if data_end > pack_data.len() {
        bail!(
            "pack data extends past end: data_start={data_start}, data_len={data_len}, pack_size={}",
            pack_data.len()
        );
    }

    Ok(pack_data[data_start..data_end].to_vec())
}
