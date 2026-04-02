// SPDX-License-Identifier: MIT
//! Persistent tree cache backed by a [redb] database.
//!
//! Each entry maps a tree blob identifier (SHA256 hex string) to a serialized
//! [`Tree`] struct (using `bitcode` for compact, fast encoding). A cache hit
//! replaces the read → decrypt → decompress → parse pipeline with a single
//! local key-value lookup.
//!
//! ## Performance
//! - **First run**: cache is populated on the fly; negligible overhead.
//! - **Subsequent runs**: 22,000+ SMB round-trips → 22,000 local redb lookups.
//!   Tree walk time drops from 30+ minutes to seconds.
//!
//! ## Crash safety
//! redb is ACID. A partial/interrupted first run leaves a valid, partially
//! populated cache. The next run will hit for already-walked trees and miss for
//! the rest, resuming transparently.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use redb::{Database, TableDefinition};
use tracing::warn;

use crate::format::arq7::Tree;

const TREE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("trees");

/// Persistent disk-backed cache of parsed [`Tree`] structs.
pub struct TreeCache {
    db: Database,
    /// Number of cache hits during this session.
    hits: AtomicUsize,
    /// Number of cache misses during this session.
    misses: AtomicUsize,
}

impl TreeCache {
    /// Open (or create) the cache database at `path`.
    ///
    /// The parent directory must already exist.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)
            .with_context(|| format!("opening tree cache at {}", path.display()))?;
        Ok(Self {
            db,
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        })
    }

    /// Look up a tree by its blob identifier. Returns `None` on miss or error.
    pub fn get(&self, tree_id: &str) -> Option<Tree> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(TREE_TABLE).ok()?;
        let guard = table.get(tree_id).ok()??;
        let tree: Tree = bitcode::deserialize(guard.value()).ok()?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(tree)
    }

    /// Store a tree in the cache. Non-fatal on failure (warns instead).
    pub fn put(&self, tree_id: &str, tree: &Tree) {
        if let Err(e) = self.put_inner(tree_id, tree) {
            warn!("tree cache write failed for {tree_id}: {e:#}");
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn put_inner(&self, tree_id: &str, tree: &Tree) -> Result<()> {
        let encoded = bitcode::serialize(tree).context("serializing tree for cache")?;
        let txn = self
            .db
            .begin_write()
            .context("beginning cache write transaction")?;
        {
            let mut table = txn.open_table(TREE_TABLE).context("opening tree table")?;
            table
                .insert(tree_id, encoded.as_slice())
                .context("inserting tree into cache")?;
        }
        txn.commit().context("committing cache write transaction")?;
        Ok(())
    }

    /// Store multiple trees in the cache in a single write transaction.
    ///
    /// Much faster than calling [`put`] in a loop because redb only calls
    /// `fdatasync()` once per transaction instead of once per tree.
    #[allow(dead_code)]
    pub fn put_batch(&self, entries: &[(&str, &Tree)]) {
        if entries.is_empty() {
            return;
        }
        if let Err(e) = self.put_batch_inner(entries) {
            warn!("tree cache batch write failed ({} entries): {e:#}", entries.len());
        }
        self.misses.fetch_add(entries.len(), Ordering::Relaxed);
    }

    fn put_batch_inner(&self, entries: &[(&str, &Tree)]) -> Result<()> {
        let txn = self
            .db
            .begin_write()
            .context("beginning cache batch write transaction")?;
        {
            let mut table = txn.open_table(TREE_TABLE).context("opening tree table")?;
            for (tree_id, tree) in entries {
                let encoded = bitcode::serialize(tree)
                    .with_context(|| format!("serializing tree {tree_id} for cache"))?;
                table
                    .insert(*tree_id, encoded.as_slice())
                    .with_context(|| format!("inserting tree {tree_id} into cache"))?;
            }
        }
        txn.commit().context("committing cache batch write transaction")?;
        Ok(())
    }

    /// Store multiple trees in the cache given pre-serialized byte blobs.
    ///
    /// Callers that have already serialized trees (e.g. to avoid holding large
    /// `Tree` structs in memory) can use this to flush without re-serializing.
    /// One `fdatasync` per call.
    pub fn put_batch_raw(&self, entries: &[(String, Vec<u8>)]) {
        if entries.is_empty() {
            return;
        }
        if let Err(e) = self.put_batch_raw_inner(entries) {
            warn!(
                "tree cache raw batch write failed ({} entries): {e:#}",
                entries.len()
            );
        }
        self.misses.fetch_add(entries.len(), Ordering::Relaxed);
    }

    fn put_batch_raw_inner(&self, entries: &[(String, Vec<u8>)]) -> Result<()> {
        let txn = self
            .db
            .begin_write()
            .context("beginning cache raw batch write transaction")?;
        {
            let mut table = txn.open_table(TREE_TABLE).context("opening tree table")?;
            for (tree_id, encoded) in entries {
                table
                    .insert(tree_id.as_str(), encoded.as_slice())
                    .with_context(|| format!("inserting tree {tree_id} into cache"))?;
            }
        }
        txn.commit().context("committing cache raw batch write transaction")?;
        Ok(())
    }

    /// Print cache statistics to stderr in `key=value` format.
    pub fn print_stats(&self) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            return;
        }
        let hit_pct = (hits * 100) / total;
        eprintln!("tree_cache.hits={hits} misses={misses} hit_pct={hit_pct}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::arq7::{BlobLoc, Tree};
    use tempfile::tempdir;

    #[allow(dead_code)]
    fn make_blob_loc(id: &str) -> BlobLoc {
        BlobLoc {
            identifier: id.to_owned(),
            is_packed: false,
            is_large_pack: false,
            relative_path: None,
            offset: 0,
            length: 10,
            stretch_encryption_key: true,
            compression_type: 0,
            is_arq5_pack_entry: false,
        }
    }

    fn make_tree() -> Tree {
        Tree {
            version: 2,
            nodes: vec![],
        }
    }

    #[test]
    fn miss_on_empty_cache() {
        let dir = tempdir().unwrap();
        let cache = TreeCache::open(&dir.path().join("cache.redb")).unwrap();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn put_then_get_roundtrip() {
        let dir = tempdir().unwrap();
        let cache = TreeCache::open(&dir.path().join("cache.redb")).unwrap();
        let tree = make_tree();
        cache.put("abc123", &tree);
        let retrieved = cache.get("abc123").expect("should be a cache hit");
        assert_eq!(retrieved.version, 2);
        assert!(retrieved.nodes.is_empty());
    }

    #[test]
    fn cache_persists_across_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.redb");
        {
            let cache = TreeCache::open(&path).unwrap();
            cache.put("key1", &make_tree());
        }
        // Re-open — data should survive
        let cache2 = TreeCache::open(&path).unwrap();
        assert!(cache2.get("key1").is_some());
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = tempdir().unwrap();
        let cache = TreeCache::open(&dir.path().join("cache.redb")).unwrap();
        cache.put("key1", &make_tree());
        assert!(cache.get("key_does_not_exist").is_none());
    }
}
