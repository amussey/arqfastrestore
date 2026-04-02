// SPDX-License-Identifier: MIT
//! Restore from a scan CSV file.
//!
//! ## Workflow
//!
//! 1. Parse the CSV (header-based — column order is irrelevant).
//! 2. Collect all rows where `action == "restore"`.
//! 3. Group requests by source backup UUID (from the `sources` column).
//! 4. For each UUID, walk snapshots newest-first and collect the [`RestoreItem`]
//!    for each requested `(path, blob_sha)` row.
//! 5. Return all collected items so the caller can feed them into the
//!    sort-by-pack [`RestoreEngine`] pipeline.
//!
//! ## Path matching
//!
//! The `path` in the CSV is relative to the backup folder root (e.g.
//! `Users/steve/Documents/report.pdf`).  During the tree walk, the current
//! path prefix is tracked.  Only nodes whose full path exactly matches a
//! requested path are emitted; subtrees with no matching descendants are
//! pruned early.
//!
//! ## Multi-UUID
//!
//! A file may exist in multiple backup sets (the `sources` column lists all
//! UUIDs separated by `;`).  We only need to restore from one UUID per file.
//! The implementation picks the first UUID listed in `sources` that is
//! available in the provided context.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use tracing::warn;

use crate::format::arq7::{BlobLoc, Node};
use crate::restore::tree_cache::TreeCache;
use crate::restore::tree_walker::{RestoreItem, TreeParseFn};
use crate::storage::{BlobReader, DecryptFn, LocalStorage, Storage};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One parsed row from the scan CSV with `action == "restore"`.
#[derive(Debug, Clone)]
pub struct CsvRow {
    /// File path relative to the backup folder root.
    pub path: String,
    /// SHA-256 content fingerprint (hex). Stored for future validation use.
    #[allow(dead_code)]
    pub blob_sha: String,
    /// Semicolon-separated list of backup UUIDs that contain this blob.
    pub sources: String,
    /// Destination override (populated from `dest_as` if present, else None).
    pub dest_as: Option<String>,
}

/// Per-UUID context needed to walk a backup set.
pub struct UuidContext {
    /// Storage root for this UUID's backup set.
    pub storage_root: PathBuf,
    /// Decrypt function, if the backup is encrypted.
    pub decrypt: Option<DecryptFn>,
    /// Tree-parse function (Arq7 generic or Arq5 bucket-aware).
    pub parse_tree: TreeParseFn,
    /// Snapshot records for this UUID.
    pub records: Vec<crate::format::arq7::BackupRecord>,
}

#[derive(Debug, Clone)]
struct RequestedRow {
    row_id: usize,
    path: String,
    blob_sha: Option<String>,
    candidate_uuids: Vec<String>,
    dest_as: Option<String>,
}

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

/// Parse a scan CSV file, returning rows where `action` is `"restore"`.
///
/// Column order is determined from the header row — the caller may have
/// reordered columns in a spreadsheet.
pub fn parse_csv(path: &Path) -> Result<Vec<CsvRow>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading CSV file {}", path.display()))?;
    parse_csv_str(&content)
}

/// Parse scan CSV content from a string.
pub fn parse_csv_str(content: &str) -> Result<Vec<CsvRow>> {
    let mut lines = content.lines();

    // --- Header row ---
    let header = lines
        .next()
        .context("CSV file is empty — expected a header row")?;
    let headers: Vec<&str> = split_csv_line(header);

    // Find required column indices.
    let col = |name: &str| -> Result<usize> {
        headers
            .iter()
            .position(|h| h.trim_matches('"').eq_ignore_ascii_case(name))
            .with_context(|| {
                format!(
                    "CSV is missing required column '{name}'. Found: {}",
                    headers.join(", ")
                )
            })
    };

    let idx_path = col("path")?;
    let idx_sha = col("blob_sha")?;
    let idx_sources = col("sources")?;
    let idx_action = col("action")?;
    // Optional column: dest_as (for rename-on-restore)
    let idx_dest_as = headers
        .iter()
        .position(|h| h.trim_matches('"').eq_ignore_ascii_case("dest_as"));

    let mut rows = Vec::new();

    for (line_no, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields = split_csv_line(line);

        let get = |idx: usize| -> &str {
            fields
                .get(idx)
                .map(|s| s.trim_matches('"'))
                .unwrap_or("")
        };

        let action = get(idx_action).trim().to_lowercase();
        if action != "restore" {
            continue;
        }

        let path = get(idx_path).to_string();
        let blob_sha = get(idx_sha).to_string();
        let sources = get(idx_sources).to_string();

        if path.is_empty() {
            warn!("CSV line {}: skipping row with empty path", line_no + 2);
            continue;
        }
        if sources.is_empty() {
            warn!(
                "CSV line {}: skipping '{}' — no source UUIDs",
                line_no + 2,
                path
            );
            continue;
        }

        let dest_as = idx_dest_as
            .map(get)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        rows.push(CsvRow {
            path,
            blob_sha,
            sources,
            dest_as,
        });
    }

    Ok(rows)
}

/// Split a single CSV line into fields, handling quoted fields with embedded commas.
fn split_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut in_quote = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                // Handle "" (escaped quote) inside quoted fields.
                if in_quote && i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            b',' if !in_quote => {
                fields.push(&line[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    fields.push(&line[start..]);
    fields
}

// ---------------------------------------------------------------------------
// Targeted tree walk
// ---------------------------------------------------------------------------

/// Walk a backup snapshot tree, collecting only the [`RestoreItem`]s whose
/// `(path, blob_sha)` match entries in `requests_by_path`.
///
/// Subtrees that contain no requested file are pruned: if none of the
/// requested paths start with `current_prefix/`, the entire subtree is
/// skipped without reading any blobs from storage.
///
/// Returns the collected items; missing paths are warned but do not abort.
fn collect_requested_items(
    blob_reader: &BlobReader,
    root_tree_blob_loc: &BlobLoc,
    dest_root: &Path,
    cache: Option<&TreeCache>,
    parse_tree: &TreeParseFn,
    // Rows to collect grouped by relative path.
    requests_by_path: &HashMap<String, Vec<RequestedRow>>,
) -> Result<Vec<(usize, RestoreItem)>> {
    let requested_paths: BTreeSet<String> = requests_by_path.keys().cloned().collect();
    let mut items = Vec::new();
    walk_targeted(
        blob_reader,
        root_tree_blob_loc,
        dest_root,
        "",
        cache,
        parse_tree,
        &requested_paths,
        requests_by_path,
        &mut items,
    )?;
    Ok(items)
}

#[allow(clippy::too_many_arguments)]
fn walk_targeted(
    blob_reader: &BlobReader,
    tree_loc: &BlobLoc,
    dest_root: &Path,
    path_prefix: &str,
    cache: Option<&TreeCache>,
    parse_tree: &TreeParseFn,
    requested_paths: &BTreeSet<String>,
    requests_by_path: &HashMap<String, Vec<RequestedRow>>,
    out: &mut Vec<(usize, RestoreItem)>,
) -> Result<()> {
    // Prune: if no requested path starts with this prefix, skip the entire subtree.
    // (Empty prefix = root — always descend.)
    if !path_prefix.is_empty() {
        let prefix_slash = format!("{path_prefix}/");
        // BTreeSet allows O(log N) range scan: find the first path >= prefix_slash
        // and check if it actually starts with it — vastly faster than O(N) linear scan.
        let any_match = requested_paths.contains(path_prefix)
            || requested_paths
                .range(prefix_slash.clone()..)
                .next()
                .map_or(false, |p| p.starts_with(&prefix_slash));
        if !any_match {
            return Ok(());
        }
    }

    // Read and parse the tree blob (cache-aware).
    let _tree_id = &tree_loc.identifier;
    let tree = read_tree_cached(blob_reader, tree_loc, cache, parse_tree)?;

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
            if let Some(ref subtree_loc) = node.tree_blob_loc
                && let Err(e) = walk_targeted(
                    blob_reader,
                    subtree_loc,
                    dest_root,
                    &item_path,
                    cache,
                    parse_tree,
                    requested_paths,
                    requests_by_path,
                    out,
                )
            {
                warn!("csv-restore: error in subtree '{item_path}': {e:#}");
            }
        } else if let Some(requests) = requests_by_path.get(&item_path) {
            let node_blob_sha = primary_blob_sha(&node);

            for request in requests {
                if !request_matches_node(request, node_blob_sha.as_deref()) {
                    continue;
                }

                let dest_path = if let Some(dest_as) = &request.dest_as {
                    dest_root.join(dest_as)
                } else {
                    path_from_relative(dest_root, &item_path)
                };

                out.push((
                    request.row_id,
                    RestoreItem {
                        dest_path,
                        node: node.clone(),
                    },
                ));
            }
        }
    }

    Ok(())
}

/// Read and parse a tree blob, using the cache if available.
fn read_tree_cached(
    blob_reader: &BlobReader,
    loc: &BlobLoc,
    cache: Option<&TreeCache>,
    parse_tree: &TreeParseFn,
) -> Result<crate::format::arq7::Tree> {
    let tree_id = &loc.identifier;
    if let Some(c) = cache
        && let Some(cached) = c.get(tree_id)
    {
        return Ok(cached);
    }

    let bytes = blob_reader
        .read_blob(loc)
        .with_context(|| format!("reading tree blob '{tree_id}'"))?;
    let parsed =
        (parse_tree)(&bytes).with_context(|| format!("parsing tree blob '{tree_id}'"))?;

    if let Some(c) = cache {
        c.put(tree_id, &parsed);
    }

    Ok(parsed)
}

/// Build a `PathBuf` from `dest_root` and a `/`-separated relative path.
fn path_from_relative(dest_root: &Path, relative: &str) -> PathBuf {
    let mut p = dest_root.to_path_buf();
    for component in relative.split('/') {
        if !component.is_empty() {
            p.push(component);
        }
    }
    p
}

fn normalize_blob_sha(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    // Validate hex without allocating a decoded buffer.
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn primary_blob_sha(node: &Node) -> Option<String> {
    // Arq identifiers are already valid hex — just lowercase without re-validating.
    node.data_blob_locs
        .first()
        .map(|loc| loc.identifier.to_ascii_lowercase())
}

fn request_matches_node(request: &RequestedRow, node_blob_sha: Option<&str>) -> bool {
    match (&request.blob_sha, node_blob_sha) {
        (Some(expected), Some(actual)) => {
            // Arq5 SHA1 identifiers are 40 hex chars stored in a 32-byte key,
            // zero-padded to 64 hex chars in the scan CSV.  Normalise both sides
            // by trimming trailing zero pairs so "abc...000000" == "abc...".
            let e = expected.trim_end_matches('0');
            let a = actual.trim_end_matches('0');
            e == a
        }
        (Some(_), None) => false,
        (None, _) => true,
    }
}

// ---------------------------------------------------------------------------
// High-level entry point
// ---------------------------------------------------------------------------

/// Parse a scan CSV and collect all [`RestoreItem`]s for rows with
/// `action == "restore"`.
///
/// For each unique source UUID in the requested rows, snapshots are walked
/// newest-first until every requested `(path, blob_sha)` row is satisfied.
/// Uses the tree cache for fast repeated walks.
///
/// Returns `(items, not_found)` where `not_found` lists paths that were
/// requested but not found in any snapshot.
pub fn items_from_csv(
    csv_path: &Path,
    dest_root: &Path,
    uuid_contexts: &HashMap<String, UuidContext>,
    cache: Option<&TreeCache>,
) -> Result<(Vec<RestoreItem>, Vec<String>)> {
    let rows = parse_csv(csv_path)?;

    if rows.is_empty() {
        bail!("No rows with action=restore found in {}", csv_path.display());
    }

    eprintln!(
        "csv-restore: {} row(s) with action=restore",
        rows.len()
    );

    let mut requested_rows = Vec::new();

    for (row_id, row) in rows.iter().enumerate() {
        let candidate_uuids: Vec<String> = row
            .sources
            .split(';')
            .map(str::trim)
            .filter(|uuid| uuid_contexts.contains_key(*uuid))
            .map(ToOwned::to_owned)
            .collect();

        if candidate_uuids.is_empty() {
            warn!(
                "csv-restore: no available backup set for '{}' (sources: {})",
                row.path, row.sources
            );
            continue;
        }

        requested_rows.push(RequestedRow {
            row_id,
            path: row.path.clone(),
            blob_sha: normalize_blob_sha(&row.blob_sha),
            candidate_uuids,
            dest_as: row.dest_as.clone(),
        });
    }

    let mut all_items: Vec<RestoreItem> = Vec::new();
    let mut found_rows: HashSet<usize> = HashSet::new();

    let mut unresolved: HashMap<usize, RequestedRow> = requested_rows
        .into_iter()
        .map(|row| (row.row_id, row))
        .collect();

    let mut uuid_order = Vec::new();
    let mut seen_uuid = HashSet::new();
    for row in unresolved.values() {
        for uuid in &row.candidate_uuids {
            if seen_uuid.insert(uuid.clone()) {
                uuid_order.push(uuid.clone());
            }
        }
    }

    for uuid in uuid_order {
        if unresolved.is_empty() {
            break;
        }

        let ctx = &uuid_contexts[&uuid];

        if ctx.records.is_empty() {
            bail!("no snapshots for UUID {uuid}");
        }

        let storage: std::sync::Arc<dyn Storage> =
            std::sync::Arc::new(LocalStorage::new(&ctx.storage_root));

        let relevant_rows: Vec<RequestedRow> = unresolved
            .values()
            .filter(|row| row.candidate_uuids.iter().any(|candidate| candidate == &uuid))
            .cloned()
            .collect();

        if relevant_rows.is_empty() {
            continue;
        }

        // Build the per-path request map once — shared across all snapshot walks.
        let requests_by_path: HashMap<String, Vec<RequestedRow>> = {
            let mut m: HashMap<String, Vec<RequestedRow>> = HashMap::new();
            for row in &relevant_rows {
                m.entry(row.path.clone()).or_default().push(row.clone());
            }
            m
        };

        eprintln!(
            "csv-restore: walking {} snapshots for UUID {uuid} in parallel ({} file(s) needed)...",
            ctx.records.len(),
            relevant_rows.len(),
        );

        // Walk snapshots newest-first in parallel chunks.  Each rayon task gets
        // its own BlobReader (not Sync).  We stop early once all files are found.
        //
        // Chunk size of 4 keeps peak RAM bounded: each concurrent walk can hold
        // a full tree's worth of parsed blobs in memory while decrypting.
        // After each chunk we check for early exit before starting the next.
        const SNAPSHOT_CHUNK_SIZE: usize = 4;

        // row_id → path lookup for cheap early-exit updates.
        let row_id_to_path: HashMap<usize, String> = relevant_rows
            .iter()
            .map(|r| (r.row_id, r.path.clone()))
            .collect();

        // remaining_paths tracks which paths still need a snapshot match.
        let mut remaining_paths: BTreeSet<String> = requests_by_path.keys().cloned().collect();
        // found_in_phase1: row_id → RestoreItem (first/newest match wins).
        let mut found_in_phase1: HashMap<usize, RestoreItem> = HashMap::new();

        for chunk in ctx.records.chunks(SNAPSHOT_CHUNK_SIZE) {
            if remaining_paths.is_empty() {
                break;
            }

            let chunk_results: Vec<(usize, RestoreItem)> = chunk
                .par_iter()
                .flat_map(|record| {
                    let root_loc = match &record.root_tree_blob_loc {
                        Some(loc) => loc.clone(),
                        None => {
                            warn!(
                                "csv-restore: snapshot ts={} has no root_tree_blob_loc — skipping UUID {uuid}",
                                record.timestamp
                            );
                            return vec![];
                        }
                    };

                    let blob_reader = BlobReader::new(storage.clone(), ctx.decrypt.clone());

                    match collect_requested_items(
                        &blob_reader,
                        &root_loc,
                        dest_root,
                        cache,
                        &ctx.parse_tree,
                        &requests_by_path,
                    ) {
                        Ok(matches) => matches,
                        Err(e) => {
                            warn!(
                                "csv-restore: error walking UUID {uuid} snapshot ts={}: {e:#}",
                                record.timestamp
                            );
                            vec![]
                        }
                    }
                })
                .collect();

            // Merge chunk results: first match per row_id wins (records are
            // newest-first so first occurrence = most recent snapshot).
            for (row_id, item) in chunk_results {
                if found_in_phase1.contains_key(&row_id) {
                    continue;
                }
                if let Some(path) = row_id_to_path.get(&row_id) {
                    remaining_paths.remove(path);
                }
                found_in_phase1.insert(row_id, item);
            }
        }

        let matched = found_in_phase1.len();
        for (row_id, item) in found_in_phase1 {
            if unresolved.remove(&row_id).is_some() {
                found_rows.insert(row_id);
                all_items.push(item);
            }
        }

        eprintln!(
            "csv-restore:   found {matched}/{} file(s) across all snapshots for UUID {uuid}",
            relevant_rows.len(),
        );
    }

    // Determine which requested rows were not found in any snapshot.
    let not_found: Vec<String> = rows
        .iter()
        .enumerate()
        .filter(|(row_id, _)| !found_rows.contains(row_id))
        .map(|(_, r)| r.path.clone())
        .collect();

    if !not_found.is_empty() {
        eprintln!(
            "csv-restore: WARNING — {} file(s) not found in any snapshot:",
            not_found.len()
        );
        for p in not_found.iter().take(20) {
            eprintln!("  {p}");
        }
        if not_found.len() > 20 {
            eprintln!("  ... and {} more", not_found.len() - 20);
        }
    }

    Ok((all_items, not_found))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::arq7::{BackupRecord, BlobLoc, Node, Tree};
    use tempfile::tempdir;

    fn test_blob_loc(id: &str) -> BlobLoc {
        BlobLoc {
            identifier: id.to_string(),
            is_packed: false,
            is_large_pack: false,
            relative_path: None,
            offset: 0,
            length: 0,
            stretch_encryption_key: true,
            compression_type: 0,
            is_arq5_pack_entry: false,
        }
    }

    fn test_file_node(id: &str, size: u64) -> Node {
        Node {
            is_tree: false,
            data_blob_locs: vec![test_blob_loc(id)],
            item_size: size,
            ..Node::default()
        }
    }

    fn test_context_with_two_versions(old_sha: &str, new_sha: &str) -> (tempfile::TempDir, TreeCache, UuidContext) {
        let dir = tempdir().unwrap();
        let cache = TreeCache::open(&dir.path().join("trees.redb")).unwrap();
        cache.put(
            "root-old",
            &Tree {
                version: 2,
                nodes: vec![("file.txt".to_string(), test_file_node(old_sha, 10))],
            },
        );
        cache.put(
            "root-new",
            &Tree {
                version: 2,
                nodes: vec![("file.txt".to_string(), test_file_node(new_sha, 20))],
            },
        );

        let ctx = UuidContext {
            storage_root: dir.path().to_path_buf(),
            decrypt: None,
            parse_tree: std::sync::Arc::new(|_| anyhow::bail!("parse_tree should not be called in test")),
            records: vec![
                BackupRecord {
                    timestamp: 100,
                    root_tree_blob_loc: Some(test_blob_loc("root-old")),
                    local_path: "/src".to_string(),
                    arq_version: "arq7".to_string(),
                    is_complete: true,
                },
                BackupRecord {
                    timestamp: 200,
                    root_tree_blob_loc: Some(test_blob_loc("root-new")),
                    local_path: "/src".to_string(),
                    arq_version: "arq7".to_string(),
                    is_complete: true,
                },
            ],
        };

        (dir, cache, ctx)
    }

    // -----------------------------------------------------------------------
    // CSV parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_csv_standard_columns() {
        let csv = "\
source_root,computer_name,backup_name,path,size_bytes,mtime,blob_sha,sources,first_seen,last_seen,snapshot_count,path_count,sha_count,action
/Videos,PC,Backup,Videos/movie.mov,1000000,2024-01-01,aabbcc,UUID1,1000,2000,5,1,1,restore
/Docs,PC,Backup,Docs/report.pdf,50000,2023-06-01,ddeeff,UUID1,1000,2000,3,1,1,skip
";
        let rows = parse_csv_str(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "Videos/movie.mov");
        assert_eq!(rows[0].blob_sha, "aabbcc");
        assert_eq!(rows[0].sources, "UUID1");
        assert!(rows[0].dest_as.is_none());
    }

    #[test]
    fn parse_csv_column_order_independent() {
        // action first, path last — should still work.
        let csv = "\
action,sources,blob_sha,path,size_bytes,mtime
restore,UUID2,deadbeef,Photos/img.jpg,2000,2024-06-01
";
        let rows = parse_csv_str(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "Photos/img.jpg");
        assert_eq!(rows[0].sources, "UUID2");
    }

    #[test]
    fn parse_csv_dest_as_column() {
        let csv = "\
path,blob_sha,sources,action,dest_as
old/path/file.txt,abc123,UUID1,restore,new/path/file.txt
";
        let rows = parse_csv_str(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dest_as, Some("new/path/file.txt".to_string()));
    }

    #[test]
    fn parse_csv_skips_non_restore_actions() {
        let csv = "\
path,blob_sha,sources,action
a.txt,aaa,UUID1,restore
b.txt,bbb,UUID1,skip
c.txt,ccc,UUID1,
d.txt,ddd,UUID1,restore
";
        let rows = parse_csv_str(csv).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path, "a.txt");
        assert_eq!(rows[1].path, "d.txt");
    }

    #[test]
    fn parse_csv_handles_quoted_fields_with_commas() {
        let csv = "\
path,blob_sha,sources,action
\"path,with,commas.txt\",aabbcc,UUID1,restore
";
        let rows = parse_csv_str(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "path,with,commas.txt");
    }

    #[test]
    fn parse_csv_empty_file_returns_error() {
        let result = parse_csv_str("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_csv_missing_required_column_returns_error() {
        // Missing 'action' column.
        let csv = "path,blob_sha,sources\nfoo.txt,abc,UUID1\n";
        let result = parse_csv_str(csv);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("action"));
    }

    // -----------------------------------------------------------------------
    // Path building test
    // -----------------------------------------------------------------------

    #[test]
    fn path_from_relative_builds_correctly() {
        let root = PathBuf::from("/restore");
        let p = path_from_relative(&root, "Users/steve/Documents/report.pdf");
        assert_eq!(
            p,
            PathBuf::from("/restore/Users/steve/Documents/report.pdf")
        );
    }

    #[test]
    fn path_from_relative_single_component() {
        let root = PathBuf::from("/dest");
        let p = path_from_relative(&root, "file.txt");
        assert_eq!(p, PathBuf::from("/dest/file.txt"));
    }

    #[test]
    fn normalize_blob_sha_accepts_valid_hex() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(normalize_blob_sha(sha), Some(sha.to_string()));
    }

    #[test]
    fn normalize_blob_sha_rejects_invalid_hex() {
        assert!(normalize_blob_sha("not-hex").is_none());
        assert!(normalize_blob_sha("").is_none());
    }

    #[test]
    fn request_matches_node_arq5_zero_padded_sha1() {
        // Arq5 SHA1 stored as 40-char hex in node, but scan CSV has it
        // zero-padded to 64 chars.  Both should match.
        let sha1_raw = "f3d320d757db9db70acc0e0996d4156560ebe38f";
        let sha1_padded = "f3d320d757db9db70acc0e0996d4156560ebe38f000000000000000000000000";
        let request_padded = RequestedRow {
            row_id: 0,
            path: "file.jpg".to_string(),
            blob_sha: normalize_blob_sha(sha1_padded),
            candidate_uuids: vec![],
            dest_as: None,
        };
        // Node has the raw 40-char SHA1.
        assert!(request_matches_node(&request_padded, Some(sha1_raw)));
        // Also works the other way (both padded).
        assert!(request_matches_node(&request_padded, Some(sha1_padded)));
        // Different SHA should not match.
        let other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(!request_matches_node(&request_padded, Some(other)));
    }

    #[test]
    fn items_from_csv_selects_historical_version_by_blob_sha() {
        let old_sha = "1111111111111111111111111111111111111111111111111111111111111111";
        let new_sha = "2222222222222222222222222222222222222222222222222222222222222222";
        let (dir, cache, ctx) = test_context_with_two_versions(old_sha, new_sha);

        let csv_path = dir.path().join("test.csv");
        std::fs::write(
            &csv_path,
            format!(
                "action,path,blob_sha,sources,dest_as\nrestore,file.txt,{old_sha},UUID1,history/file-old.txt\n"
            ),
        )
        .unwrap();

        let mut contexts = HashMap::new();
        contexts.insert("UUID1".to_string(), ctx);
        let dest_root = dir.path().join("restore");

        let (items, not_found) = items_from_csv(&csv_path, &dest_root, &contexts, Some(&cache)).unwrap();
        assert!(not_found.is_empty());
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].dest_path, dest_root.join("history/file-old.txt"));
        assert_eq!(items[0].node.data_blob_locs[0].identifier, old_sha);
        assert_eq!(items[0].node.item_size, 10);
    }

    #[test]
    fn items_from_csv_can_restore_two_versions_of_same_path() {
        let old_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let new_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let (dir, cache, ctx) = test_context_with_two_versions(old_sha, new_sha);

        let csv_path = dir.path().join("test.csv");
        std::fs::write(
            &csv_path,
            format!(
                "action,path,blob_sha,sources,dest_as\nrestore,file.txt,{new_sha},UUID1,\nrestore,file.txt,{old_sha},UUID1,history/file-old.txt\n"
            ),
        )
        .unwrap();

        let mut contexts = HashMap::new();
        contexts.insert("UUID1".to_string(), ctx);
        let dest_root = dir.path().join("restore");

        let (items, not_found) = items_from_csv(&csv_path, &dest_root, &contexts, Some(&cache)).unwrap();
        assert!(not_found.is_empty());
        assert_eq!(items.len(), 2);

        let mut by_dest: HashMap<String, (String, u64)> = HashMap::new();
        for item in items {
            let rel = item
                .dest_path
                .strip_prefix(&dest_root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            by_dest.insert(rel, (item.node.data_blob_locs[0].identifier.clone(), item.node.item_size));
        }

        assert_eq!(by_dest.get("file.txt"), Some(&(new_sha.to_string(), 20)));
        assert_eq!(by_dest.get("history/file-old.txt"), Some(&(old_sha.to_string(), 10)));
    }

    #[test]
    fn items_from_csv_falls_back_to_later_source_uuid() {
        let sha = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        let dir = tempdir().unwrap();
        let cache = TreeCache::open(&dir.path().join("trees.redb")).unwrap();
        cache.put(
            "root-hit",
            &Tree {
                version: 2,
                nodes: vec![("file.txt".to_string(), test_file_node(sha, 33))],
            },
        );
        cache.put(
            "root-miss",
            &Tree {
                version: 2,
                nodes: vec![(
                    "file.txt".to_string(),
                    test_file_node(
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        44,
                    ),
                )],
            },
        );

        let csv_path = dir.path().join("test.csv");
        std::fs::write(
            &csv_path,
            format!("action,path,blob_sha,sources,dest_as\nrestore,file.txt,{sha},UUID_MISS;UUID_HIT,chosen/file.txt\n"),
        )
        .unwrap();

        let ctx_miss = UuidContext {
            storage_root: dir.path().to_path_buf(),
            decrypt: None,
            parse_tree: std::sync::Arc::new(|_| anyhow::bail!("parse_tree should not be called in test")),
            records: vec![BackupRecord {
                timestamp: 200,
                root_tree_blob_loc: Some(test_blob_loc("root-miss")),
                local_path: "/src".to_string(),
                arq_version: "arq7".to_string(),
                is_complete: true,
            }],
        };
        let ctx_hit = UuidContext {
            storage_root: dir.path().to_path_buf(),
            decrypt: None,
            parse_tree: std::sync::Arc::new(|_| anyhow::bail!("parse_tree should not be called in test")),
            records: vec![BackupRecord {
                timestamp: 100,
                root_tree_blob_loc: Some(test_blob_loc("root-hit")),
                local_path: "/src".to_string(),
                arq_version: "arq7".to_string(),
                is_complete: true,
            }],
        };

        let mut contexts = HashMap::new();
        contexts.insert("UUID_MISS".to_string(), ctx_miss);
        contexts.insert("UUID_HIT".to_string(), ctx_hit);
        let dest_root = dir.path().join("restore");

        let (items, not_found) = items_from_csv(&csv_path, &dest_root, &contexts, Some(&cache)).unwrap();
        assert!(not_found.is_empty());
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].dest_path, dest_root.join("chosen/file.txt"));
        assert_eq!(items[0].node.data_blob_locs[0].identifier, sha);
        assert_eq!(items[0].node.item_size, 33);
    }

    // -----------------------------------------------------------------------
    // CSV split tests
    // -----------------------------------------------------------------------

    #[test]
    fn split_csv_simple() {
        let fields = split_csv_line("a,b,c");
        assert_eq!(fields, vec!["a", "b", "c"]);
    }

    #[test]
    fn split_csv_quoted() {
        let fields = split_csv_line("\"a,b\",c,\"d\"");
        assert_eq!(fields, vec!["\"a,b\"", "c", "\"d\""]);
    }

    #[test]
    fn split_csv_empty_field() {
        let fields = split_csv_line("a,,c");
        assert_eq!(fields, vec!["a", "", "c"]);
    }
}
