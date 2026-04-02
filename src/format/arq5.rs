// SPDX-License-Identifier: MIT
//! Arq5 binary format parsers: pack index, commit, tree, node, blob key, and pack file.
#![allow(dead_code)]
//!
//! ## Pack Index (`.index` files)
//! Magic: `ff744f63` (4 bytes) + version 2 (4 bytes)
//! Fanout table: 256 × u32 BE — `fanout[i]` = number of entries with `SHA1[0] <= i`
//! Entries: `(offset: u64 BE, length: u64 BE, sha1: 20 bytes, padding: u32)` × total_count
//! Total count = `fanout[255]`.
//!
//! ## Commit / Tree / Node
//! Each begins with a version header string (Arq-encoded), followed by versioned fields
//! parsed with big-endian integers. All boolean flags are 1-byte.

use crate::format::primitives::Reader;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::Path;

const MAGIC: u32 = 0xff74_4f63;
const VERSION: u32 = 2;
const FANOUT_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// Pack Index
// ---------------------------------------------------------------------------

/// A single pack index entry.
#[derive(Debug, Clone)]
pub struct PackIndexEntry {
    pub sha1_hex: String,
    pub offset: u64,
    pub length: u64,
}

/// A parsed Arq5 pack index, with SHA1→entry lookup.
pub struct PackIndex {
    pub pack_id: String,
    entries: HashMap<String, PackIndexEntry>,
}

impl PackIndex {
    /// Parse a `.index` file. `pack_id` is the base name (without extension).
    ///
    /// Each entry is 40 bytes: `offset(u64) + length(u64) + sha1(20) + padding(u32)`.
    pub fn parse(data: &[u8], pack_id: String) -> Result<Self> {
        let mut r = Reader::new(data);

        let magic = r.read_u32_be().context("reading magic")?;
        if magic != MAGIC {
            bail!("invalid pack index magic: {magic:#010x}");
        }

        let version = r.read_u32_be().context("reading version")?;
        if version != VERSION {
            bail!("unsupported pack index version: {version}");
        }

        // Fanout table: 256 u32 values
        let mut fanout = [0u32; FANOUT_SIZE];
        for f in fanout.iter_mut() {
            *f = r.read_u32_be().context("reading fanout")?;
        }
        let total = fanout[255] as usize;

        // Entries: 40 bytes each (offset:8 + length:8 + sha1:20 + padding:4)
        let mut entries = HashMap::with_capacity(total);
        for _ in 0..total {
            let offset = r.read_u64_be().context("reading entry offset")?;
            let length = r.read_u64_be().context("reading entry length")?;
            let sha1_hex = r.read_sha1_hex().context("reading entry sha1")?;
            r.skip(4).context("reading entry padding")?;
            entries.insert(
                sha1_hex.clone(),
                PackIndexEntry {
                    sha1_hex,
                    offset,
                    length,
                },
            );
        }

        Ok(Self { pack_id, entries })
    }

    /// Look up a SHA1 (hex) in this index.
    pub fn get(&self, sha1_hex: &str) -> Option<&PackIndexEntry> {
        self.entries.get(sha1_hex)
    }

    /// Return the number of entries in this index.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// In-memory database of all pack indexes, built from multiple `.index` files.
pub struct PackIndexDb {
    /// sha1_hex → (pack_id, offset, length)
    map: HashMap<String, (String, u64, u64)>,
}

impl PackIndexDb {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Merge a parsed index into this database.
    pub fn add_index(&mut self, index: PackIndex) {
        for (sha1, entry) in &index.entries {
            self.map.insert(
                sha1.clone(),
                (index.pack_id.clone(), entry.offset, entry.length),
            );
        }
    }

    /// Look up a SHA1, returning `(pack_id, offset, length)`.
    pub fn lookup(&self, sha1_hex: &str) -> Option<(&str, u64, u64)> {
        self.map
            .get(sha1_hex)
            .map(|(id, off, len)| (id.as_str(), *off, *len))
    }

    /// Return the total number of entries across all merged indexes.
    pub fn total_entries(&self) -> usize {
        self.map.len()
    }
}

impl Default for PackIndexDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pack Index Persistent Cache
// ---------------------------------------------------------------------------

/// Cached pack index data suitable for serialization.
/// Stored as a single bitcode blob per packset in a redb database.
#[derive(serde::Serialize, serde::Deserialize)]
struct PackIndexCacheEntry {
    /// Vec of (sha1_hex, pack_id, offset, length) — flat for compact serialization.
    entries: Vec<(String, String, u64, u64)>,
}

const PACK_INDEX_TABLE: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("pack_indexes");

impl PackIndexDb {
    /// Save the current index database to a redb cache file.
    ///
    /// `cache_path` is the redb database file (e.g., `~/.cache/arqfastrestore/pack_indexes.redb`).
    /// `packset_key` is a unique key for this packset (e.g., `"XXXXXXXX-trees"`).
    pub fn save_cache(&self, cache_path: &Path, packset_key: &str) -> Result<()> {
        let entry = PackIndexCacheEntry {
            entries: self
                .map
                .iter()
                .map(|(sha1, (pack_id, off, len))| (sha1.clone(), pack_id.clone(), *off, *len))
                .collect(),
        };
        let encoded = bitcode::serialize(&entry).context("serializing pack index cache")?;

        let db = redb::Database::create(cache_path)
            .with_context(|| format!("opening pack index cache at {}", cache_path.display()))?;
        let txn = db.begin_write().context("begin cache write")?;
        {
            let mut table = txn
                .open_table(PACK_INDEX_TABLE)
                .context("opening pack_indexes table")?;
            table
                .insert(packset_key, encoded.as_slice())
                .context("inserting pack index cache")?;
        }
        txn.commit().context("committing pack index cache")?;
        Ok(())
    }

    /// Load a pack index database from a redb cache file.
    ///
    /// Returns `None` if the cache file or key doesn't exist.
    pub fn load_cache(cache_path: &Path, packset_key: &str) -> Result<Option<Self>> {
        if !cache_path.exists() {
            return Ok(None);
        }
        let db = redb::Database::open(cache_path)
            .with_context(|| format!("opening pack index cache at {}", cache_path.display()))?;
        let txn = db.begin_read().context("begin cache read")?;
        let table = match txn.open_table(PACK_INDEX_TABLE) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let guard = match table.get(packset_key) {
            Ok(Some(g)) => g,
            Ok(None) => return Ok(None),
            Err(_) => return Ok(None),
        };
        let entry: PackIndexCacheEntry =
            bitcode::deserialize(guard.value()).context("deserializing pack index cache")?;
        let mut map = HashMap::with_capacity(entry.entries.len());
        for (sha1, pack_id, off, len) in entry.entries {
            map.insert(sha1, (pack_id, off, len));
        }
        Ok(Some(Self { map }))
    }
}

// ---------------------------------------------------------------------------
// BlobKey
// ---------------------------------------------------------------------------

/// Arq5 blob key — a reference to a data blob (file chunk, tree, etc.).
#[derive(Debug, Clone)]
pub struct Arq5BlobKey {
    /// 40-char hex SHA1 (or `None` if null).
    pub sha1: Option<String>,
    /// Whether encryption key stretching was used (tree_version >= 14).
    pub stretch_encryption_key: bool,
    /// Storage type: 1 = S3, 2 = Glacier (tree_version >= 17).
    pub storage_type: u32,
    /// Glacier archive ID (tree_version >= 17).
    pub archive_id: Option<String>,
    /// Glacier archive size in bytes (tree_version >= 17).
    pub archive_size: u64,
    /// Glacier upload date in ms since epoch (tree_version >= 17).
    pub archive_upload_date: Option<u64>,
}

impl Arq5BlobKey {
    /// Parse a blob key from the reader using the enclosing tree's version.
    pub fn parse(r: &mut Reader, tree_version: u32) -> Result<Self> {
        let sha1 = r.read_string().context("blob key sha1")?;

        let stretch_encryption_key = if tree_version >= 14 {
            r.read_bool().context("blob key stretch_encryption_key")?
        } else {
            false
        };

        let (storage_type, archive_id, archive_size, archive_upload_date) = if tree_version >= 17 {
            let st = r.read_u32_be().context("blob key storage_type")?;
            let aid = r.read_string().context("blob key archive_id")?;
            let asiz = r.read_u64_be().context("blob key archive_size")?;
            let aud = r.read_date().context("blob key archive_upload_date")?;
            (st, aid, asiz, aud)
        } else {
            (0, None, 0, None)
        };

        Ok(Self {
            sha1,
            stretch_encryption_key,
            storage_type,
            archive_id,
            archive_size,
            archive_upload_date,
        })
    }
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

/// A single parent commit reference within an [`Arq5Commit`].
#[derive(Debug, Clone)]
pub struct Arq5ParentCommit {
    /// SHA1 hex of the parent commit object (or `None`).
    pub sha1: Option<String>,
    /// Whether the parent's encryption key was stretched.
    pub encryption_key_stretched: bool,
}

/// Arq5 commit object — points to a tree SHA1 for a backup snapshot.
#[derive(Debug, Clone)]
pub struct Arq5Commit {
    /// Format version parsed from the header (e.g., `"CommitV012"` → 12).
    pub version: u32,
    pub author: Option<String>,
    pub comment: Option<String>,
    pub parent_commits: Vec<Arq5ParentCommit>,
    pub tree_sha1: Option<String>,
    pub tree_encryption_key_stretched: bool,
    pub tree_is_compressed: bool,
    /// Compression type for the tree blob (0 = none, 1 = gzip, 2 = lz4).
    pub tree_compression_type: i32,
    /// Location string, e.g. `"file://hostname/path"`.
    pub location: Option<String>,
    pub merge_common_ancestor_sha1: Option<String>,
    pub is_merge_ancestor_stretched: bool,
    /// Creation timestamp in ms since epoch.
    pub creation_date_ms: Option<u64>,
    /// Files that failed to back up: `(path, error_message)`.
    pub failed_files: Vec<(String, String)>,
    pub has_missing_nodes: bool,
    pub is_complete: bool,
    /// Raw config plist XML bytes (may be empty).
    pub config_plist_xml: Option<Vec<u8>>,
    pub arq_version: Option<String>,
}

impl Arq5Commit {
    /// Parse an Arq5 commit object from raw (already-decrypted) bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);

        // Header: raw 10-byte ASCII prefix "CommitV0NN" (NOT Arq-encoded string)
        let header_bytes = r.read_bytes(10).context("commit header")?;
        let header =
            std::str::from_utf8(header_bytes).context("commit header is not valid ASCII")?;
        let version = parse_version_suffix(header, "CommitV", 3)
            .with_context(|| format!("parsing commit version from header {header:?}"))?;

        let author = r.read_string().context("commit author")?;
        let comment = r.read_string().context("commit comment")?;

        let num_parents = r.read_u64_be().context("num parent commits")? as usize;
        let mut parent_commits = Vec::with_capacity(num_parents);
        for _ in 0..num_parents {
            let sha1 = r.read_string().context("parent commit sha1")?;
            let encryption_key_stretched = if version >= 4 {
                r.read_bool().context("parent encryption_key_stretched")?
            } else {
                false
            };
            parent_commits.push(Arq5ParentCommit {
                sha1,
                encryption_key_stretched,
            });
        }

        let tree_sha1 = r.read_string().context("tree sha1")?;

        let tree_encryption_key_stretched = if version >= 4 {
            r.read_bool().context("tree_encryption_key_stretched")?
        } else {
            false
        };

        // Compression: version 8/9 use a bool; version >= 10 use an i32
        let (tree_is_compressed, tree_compression_type) = if version == 8 || version == 9 {
            let compressed = r.read_bool().context("tree_is_compressed")?;
            (compressed, if compressed { 1i32 } else { 0i32 })
        } else if version >= 10 {
            let ct = r.read_i32_be().context("tree_compression_type")?;
            (ct != 0, ct)
        } else {
            (false, 0i32)
        };

        let location = r.read_string().context("commit location")?;

        // Versions <= 7 carry a merge ancestor SHA1; 4..=7 additionally have a stretch flag
        let (merge_common_ancestor_sha1, is_merge_ancestor_stretched) = if version <= 7 {
            let msha = r.read_string().context("merge_common_ancestor_sha1")?;
            let stretched = if (4..=7).contains(&version) {
                r.read_bool().context("is_merge_ancestor_stretched")?
            } else {
                false
            };
            (msha, stretched)
        } else {
            (None, false)
        };

        let creation_date_ms = r.read_date().context("creation_date_ms")?;

        let failed_files = if version >= 3 {
            let count = r.read_u64_be().context("num_failed_files")? as usize;
            let mut ff = Vec::with_capacity(count);
            for _ in 0..count {
                let path = r.read_string_required().context("failed file path")?;
                let error = r.read_string_required().context("failed file error")?;
                ff.push((path, error));
            }
            ff
        } else {
            Vec::new()
        };

        let has_missing_nodes = if version >= 8 {
            r.read_bool().context("has_missing_nodes")?
        } else {
            false
        };

        let is_complete = if version >= 9 {
            r.read_bool().context("is_complete")?
        } else {
            false
        };

        let config_plist_xml = {
            let blob = r.read_data().context("config_plist_xml")?;
            if blob.is_empty() { None } else { Some(blob) }
        };

        let arq_version = r.read_string().context("arq_version")?;

        Ok(Self {
            version,
            author,
            comment,
            parent_commits,
            tree_sha1,
            tree_encryption_key_stretched,
            tree_is_compressed,
            tree_compression_type,
            location,
            merge_common_ancestor_sha1,
            is_merge_ancestor_stretched,
            creation_date_ms,
            failed_files,
            has_missing_nodes,
            is_complete,
            config_plist_xml,
            arq_version,
        })
    }
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

/// Arq5 tree — a directory listing with metadata.
#[derive(Debug, Clone)]
pub struct Arq5Tree {
    /// Format version parsed from the header (e.g., `"TreeV022"` → 22).
    pub version: u32,
    /// Compression type for xattrs blob at the tree level.
    pub xattrs_compression_type: i32,
    /// Compression type for ACL blob at the tree level.
    pub acl_compression_type: i32,
    /// Tree-level xattrs blob key.
    pub xattrs_blob_key: Arq5BlobKey,
    /// Size of the xattrs data in bytes.
    pub xattrs_size: u64,
    /// Tree-level ACL blob key.
    pub acl_blob_key: Arq5BlobKey,
    // Unix directory metadata
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    /// Names of nodes that were missing during the backup.
    pub missing_nodes: Vec<String>,
    /// Child nodes: `(name, node)` pairs in parsed order.
    pub children: Vec<(String, Arq5Node)>,
}

impl Arq5Tree {
    /// Parse an Arq5 tree object from raw (already-decrypted/decompressed) bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);

        // Header: raw 8-byte ASCII prefix "TreeV0NN" (NOT Arq-encoded string)
        let header_bytes = r.read_bytes(8).context("tree header")?;
        let header = std::str::from_utf8(header_bytes).context("tree header is not valid ASCII")?;
        let version = parse_version_suffix(header, "TreeV0", 2)
            .with_context(|| format!("parsing tree version from header {header:?}"))?;

        // Compression fields
        let xattrs_compression_type =
            read_compression_type(&mut r, version, 12, 19).context("xattrs_compression_type")?;
        let acl_compression_type =
            read_compression_type(&mut r, version, 12, 19).context("acl_compression_type")?;

        let xattrs_blob_key = Arq5BlobKey::parse(&mut r, version).context("xattrs_blob_key")?;
        let xattrs_size = r.read_u64_be().context("xattrs_size")?;
        let acl_blob_key = Arq5BlobKey::parse(&mut r, version).context("acl_blob_key")?;

        // Unix metadata
        let uid = r.read_i32_be().context("uid")?;
        let gid = r.read_i32_be().context("gid")?;
        let mode = r.read_i32_be().context("mode")?;
        let mtime_sec = r.read_i64_be().context("mtime_sec")?;
        let mtime_nsec = r.read_i64_be().context("mtime_nsec")?;
        let flags = r.read_i64_be().context("flags")?;
        let finder_flags = r.read_i32_be().context("finder_flags")?;
        let extended_finder_flags = r.read_i32_be().context("extended_finder_flags")?;
        let st_dev = r.read_i32_be().context("st_dev")?;
        let st_ino = r.read_i32_be().context("st_ino")?;
        let st_nlink = r.read_u32_be().context("st_nlink")?;
        let st_rdev = r.read_i32_be().context("st_rdev")?;
        let ctime_sec = r.read_i64_be().context("ctime_sec")?;
        let ctime_nsec = r.read_i64_be().context("ctime_nsec")?;
        let st_blocks = r.read_i64_be().context("st_blocks")?;
        let st_blksize = r.read_u32_be().context("st_blksize")?;

        // Versions 11..=16 have an aggregate size field to discard
        if (11..=16).contains(&version) {
            r.read_u64_be()
                .context("aggregate_size_on_disk (discard)")?;
        }

        let (create_time_sec, create_time_nsec) = if version >= 15 {
            (
                r.read_i64_be().context("create_time_sec")?,
                r.read_i64_be().context("create_time_nsec")?,
            )
        } else {
            (0, 0)
        };

        let missing_nodes = if version >= 18 {
            let count = r.read_u32_be().context("missing_node_count")? as usize;
            let mut names = Vec::with_capacity(count);
            for _ in 0..count {
                names.push(r.read_string_required().context("missing node name")?);
            }
            names
        } else {
            Vec::new()
        };

        let node_count = r.read_u32_be().context("node_count")? as usize;
        let mut children = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let name = r.read_string_required().context("node name")?;
            let node = Arq5Node::parse(&mut r, version).context("node")?;
            children.push((name, node));
        }

        Ok(Self {
            version,
            xattrs_compression_type,
            acl_compression_type,
            xattrs_blob_key,
            xattrs_size,
            acl_blob_key,
            uid,
            gid,
            mode,
            mtime_sec,
            mtime_nsec,
            flags,
            finder_flags,
            extended_finder_flags,
            st_dev,
            st_ino,
            st_nlink,
            st_rdev,
            ctime_sec,
            ctime_nsec,
            st_blocks,
            st_blksize,
            create_time_sec,
            create_time_nsec,
            missing_nodes,
            children,
        })
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Arq5 node — a file or subdirectory within a tree.
#[derive(Debug, Clone)]
pub struct Arq5Node {
    /// `true` if this node is a subdirectory (tree), `false` if it is a file.
    pub is_tree: bool,
    /// Whether the subtree contains items that were missing during backup.
    pub tree_contains_missing_items: bool,
    /// Compression type for file data blobs (0 = none, 1 = gzip, 2 = lz4).
    pub data_compression_type: i32,
    /// Compression type for xattrs blob.
    pub xattrs_compression_type: i32,
    /// Compression type for ACL blob.
    pub acl_compression_type: i32,
    /// Data blob keys — one per chunk for large files.
    pub data_blob_keys: Vec<Arq5BlobKey>,
    /// Total uncompressed file data size in bytes.
    pub data_size: u64,
    /// Xattrs blob key.
    pub xattrs_blob_key: Arq5BlobKey,
    /// Size of the xattrs data in bytes.
    pub xattrs_size: u64,
    /// ACL blob key.
    pub acl_blob_key: Arq5BlobKey,
    // Unix file metadata
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub finder_file_type: Option<String>,
    pub finder_file_creator: Option<String>,
    pub is_file_extension_hidden: bool,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
}

impl Arq5Node {
    /// Parse a single node from the reader, using the enclosing tree's version.
    pub fn parse(r: &mut Reader, tree_version: u32) -> Result<Self> {
        let is_tree = r.read_bool().context("is_tree")?;

        let tree_contains_missing_items = if tree_version >= 18 {
            r.read_bool().context("tree_contains_missing_items")?
        } else {
            false
        };

        // Compression fields
        let data_compression_type =
            read_compression_type(r, tree_version, 12, 19).context("data_compression_type")?;
        let xattrs_compression_type = read_compression_type(r, tree_version, 12, 19)
            .context("node xattrs_compression_type")?;
        let acl_compression_type =
            read_compression_type(r, tree_version, 12, 19).context("node acl_compression_type")?;

        // Data blob keys count is signed (i32) in the format
        let key_count = r.read_i32_be().context("data_blob_keys_count")? as usize;
        let mut data_blob_keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            data_blob_keys.push(Arq5BlobKey::parse(r, tree_version).context("data blob key")?);
        }

        let data_size = r.read_u64_be().context("data_size")?;

        // Versions <= 18 stored thumbnail/preview SHA1s that are now discarded
        if tree_version <= 18 {
            r.read_string().context("thumbnail_sha1 (discard)")?;
            if (14..=18).contains(&tree_version) {
                r.read_bool()
                    .context("is_thumbnail_encryption_key_stretched (discard)")?;
            }
            r.read_string().context("preview_sha1 (discard)")?;
            if (14..=18).contains(&tree_version) {
                r.read_bool()
                    .context("is_preview_encryption_key_stretched (discard)")?;
            }
        }

        let xattrs_blob_key =
            Arq5BlobKey::parse(r, tree_version).context("node xattrs_blob_key")?;
        let xattrs_size = r.read_u64_be().context("node xattrs_size")?;
        let acl_blob_key = Arq5BlobKey::parse(r, tree_version).context("node acl_blob_key")?;

        // Unix metadata
        let uid = r.read_i32_be().context("node uid")?;
        let gid = r.read_i32_be().context("node gid")?;
        let mode = r.read_i32_be().context("node mode")?;
        let mtime_sec = r.read_i64_be().context("node mtime_sec")?;
        let mtime_nsec = r.read_i64_be().context("node mtime_nsec")?;
        let flags = r.read_i64_be().context("node flags")?;
        let finder_flags = r.read_i32_be().context("node finder_flags")?;
        let extended_finder_flags = r.read_i32_be().context("node extended_finder_flags")?;
        let finder_file_type = r.read_string().context("finder_file_type")?;
        let finder_file_creator = r.read_string().context("finder_file_creator")?;
        let is_file_extension_hidden = r.read_bool().context("is_file_extension_hidden")?;
        let st_dev = r.read_i32_be().context("node st_dev")?;
        let st_ino = r.read_i32_be().context("node st_ino")?;
        let st_nlink = r.read_u32_be().context("node st_nlink")?;
        let st_rdev = r.read_i32_be().context("node st_rdev")?;
        let ctime_sec = r.read_i64_be().context("node ctime_sec")?;
        let ctime_nsec = r.read_i64_be().context("node ctime_nsec")?;
        let create_time_sec = r.read_i64_be().context("node create_time_sec")?;
        let create_time_nsec = r.read_i64_be().context("node create_time_nsec")?;
        let st_blocks = r.read_i64_be().context("node st_blocks")?;
        let st_blksize = r.read_u32_be().context("node st_blksize")?;

        Ok(Self {
            is_tree,
            tree_contains_missing_items,
            data_compression_type,
            xattrs_compression_type,
            acl_compression_type,
            data_blob_keys,
            data_size,
            xattrs_blob_key,
            xattrs_size,
            acl_blob_key,
            uid,
            gid,
            mode,
            mtime_sec,
            mtime_nsec,
            flags,
            finder_flags,
            extended_finder_flags,
            finder_file_type,
            finder_file_creator,
            is_file_extension_hidden,
            st_dev,
            st_ino,
            st_nlink,
            st_rdev,
            ctime_sec,
            ctime_nsec,
            create_time_sec,
            create_time_nsec,
            st_blocks,
            st_blksize,
        })
    }
}

// ---------------------------------------------------------------------------
// Pack file
// ---------------------------------------------------------------------------

/// An object parsed from an Arq5 `.pack` file.
#[derive(Debug, Clone)]
pub struct PackObject {
    /// MIME type of the object (or `None`).
    pub mimetype: Option<String>,
    /// Name of the object (or `None`).
    pub name: Option<String>,
    /// Raw object data bytes.
    pub data: Vec<u8>,
}

/// Parse an Arq5 `.pack` file and return the contained objects.
///
/// Format:
/// - Magic: `"PACK"` (4 bytes)
/// - Version: `2` (u32 BE)
/// - Count: u64 BE
/// - For each object: mimetype (Arq string) + name (Arq string) + data_len (u64 BE) + data bytes
/// - Trailing: 20-byte SHA1 checksum (not verified here)
pub fn parse_pack_file(data: &[u8]) -> Result<Vec<PackObject>> {
    let mut r = Reader::new(data);

    let magic = r.read_bytes(4).context("pack magic")?;
    if magic != b"PACK" {
        bail!("invalid pack file magic");
    }

    let version = r.read_u32_be().context("pack version")?;
    if version != 2 {
        bail!("unsupported pack version: {version}");
    }

    let count = r.read_u64_be().context("pack object count")? as usize;
    let mut objects = Vec::with_capacity(count);
    for _ in 0..count {
        let mimetype = r.read_string().context("pack object mimetype")?;
        let name = r.read_string().context("pack object name")?;
        let data_len = r.read_u64_be().context("pack object data_len")? as usize;
        let obj_data = r.read_bytes(data_len).context("pack object data")?.to_vec();
        objects.push(PackObject {
            mimetype,
            name,
            data: obj_data,
        });
    }
    // Trailing 20-byte SHA1 — skip verification for now
    Ok(objects)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a decimal version number from the last `digit_count` characters of `header`.
///
/// For example, `parse_version_suffix("CommitV012", "CommitV", 3)` returns `Ok(12)`.
fn parse_version_suffix(header: &str, prefix: &str, digit_count: usize) -> Result<u32> {
    if !header.starts_with(prefix) {
        bail!("expected header starting with {prefix:?}, got {header:?}");
    }
    let suffix = &header[prefix.len()..];
    if suffix.len() < digit_count {
        bail!("header {header:?} too short to contain {digit_count}-digit version");
    }
    let digits = &suffix[suffix.len() - digit_count..];
    digits
        .parse::<u32>()
        .with_context(|| format!("parsing version digits {digits:?} from {header:?}"))
}

/// Read a compression type field that uses a bool for older versions and an i32 for newer ones.
///
/// - version < `bool_min`: returns 0 (no compression)
/// - `bool_min` <= version < `i32_min`: reads a bool and converts to 0/1
/// - version >= `i32_min`: reads an i32 BE
fn read_compression_type(r: &mut Reader, version: u32, bool_min: u32, i32_min: u32) -> Result<i32> {
    if version >= i32_min {
        r.read_i32_be()
    } else if version >= bool_min {
        Ok(if r.read_bool()? { 1 } else { 0 })
    } else {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic_rejected() {
        let data = vec![0u8; 8 + 256 * 4]; // magic + version + fanout
        // Leave magic as 0 — should fail
        assert!(PackIndex::parse(&data, "test".into()).is_err());
    }

    #[test]
    fn pack_index_entry_size_40_bytes() {
        // Verify entries are 40 bytes (offset:8 + length:8 + sha1:20 + padding:4)
        // Build a minimal index with 1 entry
        let mut data = Vec::new();
        // Magic
        data.extend_from_slice(&0xff744f63u32.to_be_bytes());
        // Version
        data.extend_from_slice(&2u32.to_be_bytes());
        // Fanout: entry SHA1 starts with 0xAB = 171
        // fanout[0..171] = 0, fanout[171..256] = 1
        for i in 0u32..256 {
            let val: u32 = if i <= 170 { 0 } else { 1 };
            data.extend_from_slice(&val.to_be_bytes());
        }
        // Entry: offset=100, length=200, sha1 starting with 0xAB..., padding=0
        data.extend_from_slice(&100u64.to_be_bytes());
        data.extend_from_slice(&200u64.to_be_bytes());
        let mut sha1 = [0xABu8; 20];
        sha1[1] = 0xCD;
        data.extend_from_slice(&sha1);
        data.extend_from_slice(&0u32.to_be_bytes()); // padding

        let idx = PackIndex::parse(&data, "test".into()).unwrap();
        assert_eq!(idx.entry_count(), 1);
        let entry = idx.get(&hex::encode(sha1)).unwrap();
        assert_eq!(entry.offset, 100);
        assert_eq!(entry.length, 200);
    }

    #[test]
    fn commit_header_parsing() {
        // Build a minimal CommitV012 object
        let mut data = Vec::new();
        // Header: raw 10-byte ASCII "CommitV012"
        data.extend_from_slice(b"CommitV012");
        // author (null)
        data.push(0);
        // comment (null)
        data.push(0);
        // num_parent_commits = 0
        data.extend_from_slice(&0u64.to_be_bytes());
        // tree_sha1 = "a" * 40
        let tree_sha1 = "a".repeat(40);
        data.push(1);
        data.extend_from_slice(&(tree_sha1.len() as u64).to_be_bytes());
        data.extend_from_slice(tree_sha1.as_bytes());
        // version >= 4: tree_encryption_key_stretched = true
        data.push(1);
        // version >= 10: tree_compression_type = 2 (LZ4)
        data.extend_from_slice(&2i32.to_be_bytes());
        // location (null)
        data.push(0);
        // creation_date (null)
        data.push(0);
        // version >= 3: num_failed_files = 0
        data.extend_from_slice(&0u64.to_be_bytes());
        // version >= 8: has_missing_nodes = false
        data.push(0);
        // version >= 9: is_complete = true
        data.push(1);
        // config_plist_xml (empty data)
        data.extend_from_slice(&0u64.to_be_bytes());
        // arq_version (null)
        data.push(0);

        let commit = Arq5Commit::parse(&data).unwrap();
        assert_eq!(commit.version, 12);
        assert_eq!(commit.tree_sha1.as_deref(), Some("a".repeat(40).as_str()));
        assert_eq!(commit.tree_compression_type, 2);
        assert!(commit.is_complete);
    }

    #[test]
    fn pack_file_parsing() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PACK");
        data.extend_from_slice(&2u32.to_be_bytes()); // version
        data.extend_from_slice(&1u64.to_be_bytes()); // 1 object
        // Object: mimetype=null, name=null, data="hello"
        data.push(0); // mimetype null
        data.push(0); // name null
        data.extend_from_slice(&5u64.to_be_bytes()); // data length
        data.extend_from_slice(b"hello"); // data
        // Trailing SHA1 (20 bytes, ignored)
        data.extend_from_slice(&[0u8; 20]);

        let objects = parse_pack_file(&data).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].data, b"hello");
        assert!(objects[0].mimetype.is_none());
    }

    #[test]
    fn parse_version_suffix_valid() {
        assert_eq!(
            parse_version_suffix("CommitV012", "CommitV", 3).unwrap(),
            12
        );
        assert_eq!(parse_version_suffix("TreeV022", "TreeV0", 2).unwrap(), 22);
    }

    #[test]
    fn parse_version_suffix_bad_prefix_rejected() {
        assert!(parse_version_suffix("BadHeader", "CommitV", 3).is_err());
    }

    #[test]
    fn pack_index_cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test_cache.redb");

        // Build a PackIndexDb with some entries
        let mut db = PackIndexDb::new();
        let mut data = Vec::new();
        // Build a minimal 2-entry pack index
        data.extend_from_slice(&0xff744f63u32.to_be_bytes()); // magic
        data.extend_from_slice(&2u32.to_be_bytes()); // version
        // Fanout: two entries, SHA1s starting with 0x11 and 0xAA
        for i in 0u32..256 {
            let val: u32 = if i < 0x11 {
                0
            } else if i < 0xAA {
                1
            } else {
                2
            };
            data.extend_from_slice(&val.to_be_bytes());
        }
        // Entry 1: sha1 = 0x11...
        data.extend_from_slice(&100u64.to_be_bytes());
        data.extend_from_slice(&50u64.to_be_bytes());
        let sha1_a = {
            let mut s = [0x11u8; 20];
            s[1] = 0x22;
            s
        };
        data.extend_from_slice(&sha1_a);
        data.extend_from_slice(&0u32.to_be_bytes());
        // Entry 2: sha1 = 0xAA...
        data.extend_from_slice(&200u64.to_be_bytes());
        data.extend_from_slice(&75u64.to_be_bytes());
        let sha1_b = {
            let mut s = [0xAAu8; 20];
            s[1] = 0xBB;
            s
        };
        data.extend_from_slice(&sha1_b);
        data.extend_from_slice(&0u32.to_be_bytes());

        let idx = PackIndex::parse(&data, "pack001".into()).unwrap();
        db.add_index(idx);
        assert_eq!(db.total_entries(), 2);

        // Save
        db.save_cache(&cache_path, "test-packset").unwrap();

        // Load
        let loaded = PackIndexDb::load_cache(&cache_path, "test-packset")
            .unwrap()
            .expect("cache should exist");
        assert_eq!(loaded.total_entries(), 2);

        let (pack_id, off, len) = loaded.lookup(&hex::encode(sha1_a)).unwrap();
        assert_eq!(pack_id, "pack001");
        assert_eq!(off, 100);
        assert_eq!(len, 50);

        let (pack_id2, off2, len2) = loaded.lookup(&hex::encode(sha1_b)).unwrap();
        assert_eq!(pack_id2, "pack001");
        assert_eq!(off2, 200);
        assert_eq!(len2, 75);
    }

    #[test]
    fn pack_index_cache_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("nonexistent.redb");
        let result = PackIndexDb::load_cache(&cache_path, "whatever").unwrap();
        assert!(result.is_none());
    }
}
