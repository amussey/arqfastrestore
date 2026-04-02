// SPDX-License-Identifier: MIT
//! Adapter layer: converts Arq5 types to Arq7 (unified pipeline) types.
#![allow(dead_code)]
//!
//! The restore engine operates exclusively on [`BlobLoc`], [`Node`], and [`Tree`]
//! from the Arq7 format module. This module provides the conversion functions that
//! allow Arq5 backup data to flow through that same pipeline without the engine
//! needing to know about Arq5 specifics.
//!
//! ## Key conversions
//! - [`blob_key_to_blob_loc`] — converts an [`Arq5BlobKey`] to a [`BlobLoc`], consulting
//!   the pack index to decide whether the blob is packed or standalone.
//! - [`arq5_node_to_node`] — converts an [`Arq5Node`] to a [`Node`].
//! - [`arq5_tree_to_tree`] — converts an [`Arq5Tree`] to a [`Tree`].
//! - [`strip_encrypted_prefix`] — strips the 9-byte `"encrypted"` prefix found on
//!   Arq5 encrypted objects before decryption.

use crate::format::arq5::{Arq5BlobKey, Arq5Node, Arq5Tree, PackIndexDb};
use crate::format::arq7::{BlobLoc, Node, Tree};
use anyhow::{Context, Result, bail};

/// Convert an Arq5 [`BlobLoc`] blob key to an Arq7 [`BlobLoc`].
///
/// Looks up the SHA1 in `pack_index_db` first (most objects are packed into
/// `.pack` files). Falls back to a standalone object path of the form
/// `objects/XX/YYYY...` (where `XX` is the first two hex characters of the
/// SHA1 and `YYYY...` is the remainder) if the SHA1 is not found in any pack.
///
/// The returned `BlobLoc` has `is_arq5_pack_entry = true` when the blob lives
/// inside a pack file, signalling to [`BlobReader`] that it must strip the
/// per-entry header (mimetype + name + data_len) before decryption.
pub fn blob_key_to_blob_loc(
    key: &Arq5BlobKey,
    compression_type: i32,
    pack_index_db: &PackIndexDb,
    packset_dir: &str,
) -> Result<BlobLoc> {
    let sha1 = key.sha1.as_deref().context("null SHA1 in blob key")?;

    if sha1.is_empty() {
        bail!("null SHA1 in blob key");
    }

    let blob_loc = if let Some((pack_id, offset, length)) = pack_index_db.lookup(sha1) {
        // Blob lives inside a pack file.
        BlobLoc {
            identifier: sha1.to_owned(),
            is_packed: true,
            is_large_pack: false,
            relative_path: Some(format!("{packset_dir}/{pack_id}.pack")),
            offset,
            length,
            stretch_encryption_key: key.stretch_encryption_key,
            compression_type: compression_type as u32,
            is_arq5_pack_entry: true,
        }
    } else {
        // Blob is a standalone object: objects/XX/YYY...
        let prefix = &sha1[..2];
        let rest = &sha1[2..];
        BlobLoc {
            identifier: sha1.to_owned(),
            is_packed: false,
            is_large_pack: false,
            relative_path: Some(format!("objects/{prefix}/{rest}")),
            offset: 0,
            length: 0,
            stretch_encryption_key: key.stretch_encryption_key,
            compression_type: compression_type as u32,
            is_arq5_pack_entry: false,
        }
    };

    Ok(blob_loc)
}

/// Convert an [`Arq5Node`] to an Arq7 [`Node`].
///
/// For directory nodes (`node.is_tree == true`), the first data blob key is
/// resolved against the *tree* pack index and becomes `tree_blob_loc`; the
/// `data_blob_locs` are left empty because the data blob key is a tree
/// reference, not file data.
///
/// For file nodes, all data blob keys with non-`None` SHA1s are converted to
/// `data_blob_locs` using the *blob* pack index, and `tree_blob_loc` is `None`.
///
/// Metadata fields are mapped with the appropriate casts. Arq5 is macOS-only,
/// so `computer_os_type` is always set to `1` (macOS). Fields with no Arq5
/// equivalent (`acl_blob_loc`, `xattrs_blob_locs`, `username`, `group_name`,
/// Windows fields, etc.) are set to their zero/empty/`None` defaults.
pub fn arq5_node_to_node(
    node: &Arq5Node,
    blob_pack_db: &PackIndexDb,
    blob_packset_dir: &str,
    tree_pack_db: &PackIndexDb,
    tree_packset_dir: &str,
) -> Result<Node> {
    let (tree_blob_loc, data_blob_locs) = if node.is_tree {
        // For directories: the first data blob key is the subtree reference.
        let tree_loc = node
            .data_blob_keys
            .iter()
            .find(|k| k.sha1.is_some())
            .map(|k| {
                blob_key_to_blob_loc(
                    k,
                    node.data_compression_type,
                    tree_pack_db,
                    tree_packset_dir,
                )
            })
            .transpose()
            .context("converting tree node's tree blob key")?;
        (tree_loc, vec![])
    } else {
        // For files: convert all non-null data blob keys.
        let mut locs = Vec::with_capacity(node.data_blob_keys.len());
        for (i, key) in node.data_blob_keys.iter().enumerate() {
            if key.sha1.is_none() {
                continue;
            }
            let loc = blob_key_to_blob_loc(
                key,
                node.data_compression_type,
                blob_pack_db,
                blob_packset_dir,
            )
            .with_context(|| format!("converting file node data blob key [{i}]"))?;
            locs.push(loc);
        }
        (None, locs)
    };

    Ok(Node {
        is_tree: node.is_tree,
        tree_blob_loc,
        computer_os_type: 1, // Arq5 is macOS-only
        data_blob_locs,
        acl_blob_loc: None,
        xattrs_blob_locs: vec![],
        item_size: node.data_size,
        contained_files_count: 0,
        mtime_sec: node.mtime_sec,
        mtime_nsec: node.mtime_nsec,
        ctime_sec: node.ctime_sec,
        ctime_nsec: node.ctime_nsec,
        create_time_sec: node.create_time_sec,
        create_time_nsec: node.create_time_nsec,
        username: None,
        group_name: None,
        deleted: false,
        mac_st_dev: node.st_dev,
        mac_st_ino: node.st_ino as u64,
        mac_st_mode: node.mode as u32,
        mac_st_nlink: node.st_nlink,
        mac_st_uid: node.uid as u32,
        mac_st_gid: node.gid as u32,
        mac_st_rdev: node.st_rdev,
        mac_st_flags: node.flags as i32,
        win_attrs: 0,
        win_reparse_tag: None,
        win_reparse_point_is_directory: None,
    })
}

/// Convert an [`Arq5Tree`] to an Arq7 [`Tree`].
///
/// All child nodes in `tree.children` are converted via [`arq5_node_to_node`].
/// The `version` field is carried over from the Arq5 tree unchanged.
pub fn arq5_tree_to_tree(
    tree: &Arq5Tree,
    blob_pack_db: &PackIndexDb,
    blob_packset_dir: &str,
    tree_pack_db: &PackIndexDb,
    tree_packset_dir: &str,
) -> Result<Tree> {
    let mut nodes = Vec::with_capacity(tree.children.len());
    for (i, (name, child)) in tree.children.iter().enumerate() {
        let node = arq5_node_to_node(
            child,
            blob_pack_db,
            blob_packset_dir,
            tree_pack_db,
            tree_packset_dir,
        )
        .with_context(|| format!("converting Arq5 tree child [{i}] {name:?}"))?;
        nodes.push((name.clone(), node));
    }
    Ok(Tree {
        version: tree.version,
        nodes,
    })
}

/// Strip the 9-byte `"encrypted"` ASCII prefix from Arq5 encrypted objects.
///
/// Returns the data unchanged if the prefix is not present, making this safe
/// to call unconditionally on any blob that may or may not be encrypted.
pub fn strip_encrypted_prefix(data: &[u8]) -> &[u8] {
    if data.starts_with(b"encrypted") {
        &data[9..]
    } else {
        data
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::arq5::{Arq5BlobKey, Arq5Node, PackIndex, PackIndexDb};

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a minimal Arq5BlobKey with the given SHA1 hex string.
    fn make_blob_key(sha1: Option<&str>) -> Arq5BlobKey {
        Arq5BlobKey {
            sha1: sha1.map(|s| s.to_owned()),
            stretch_encryption_key: false,
            storage_type: 0,
            archive_id: None,
            archive_size: 0,
            archive_upload_date: None,
        }
    }

    /// Build an empty [`PackIndexDb`].
    fn empty_db() -> PackIndexDb {
        PackIndexDb::new()
    }

    /// Build a [`PackIndexDb`] containing one entry.
    ///
    /// The pack index binary format:
    /// - magic (4) + version 2 (4) + fanout (256×4) + entries (40 each)
    fn db_with_entry(sha1_hex: &str, pack_id: &str, offset: u64, length: u64) -> PackIndexDb {
        let sha1_bytes = hex::decode(sha1_hex).expect("valid sha1 hex in test helper");
        assert_eq!(sha1_bytes.len(), 20, "SHA1 must be 20 bytes");

        let first_byte = sha1_bytes[0] as u32;

        let mut data = Vec::new();
        // magic
        data.extend_from_slice(&0xff744f63u32.to_be_bytes());
        // version
        data.extend_from_slice(&2u32.to_be_bytes());
        // fanout: entries with first byte <= first_byte get count 1
        for i in 0u32..256 {
            let val: u32 = if i < first_byte { 0 } else { 1 };
            data.extend_from_slice(&val.to_be_bytes());
        }
        // entry
        data.extend_from_slice(&offset.to_be_bytes());
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&sha1_bytes);
        data.extend_from_slice(&0u32.to_be_bytes()); // padding

        let index = PackIndex::parse(&data, pack_id.to_owned()).expect("valid pack index in test");
        let mut db = PackIndexDb::new();
        db.add_index(index);
        db
    }

    /// Build a minimal [`Arq5Node`] for a file with the given data blob key SHA1s.
    fn make_file_node(sha1s: &[&str]) -> Arq5Node {
        Arq5Node {
            is_tree: false,
            tree_contains_missing_items: false,
            data_compression_type: 0,
            xattrs_compression_type: 0,
            acl_compression_type: 0,
            data_blob_keys: sha1s.iter().map(|s| make_blob_key(Some(s))).collect(),
            data_size: 42,
            xattrs_blob_key: make_blob_key(None),
            xattrs_size: 0,
            acl_blob_key: make_blob_key(None),
            uid: 501,
            gid: 20,
            mode: 0o644,
            mtime_sec: 1_000_000,
            mtime_nsec: 0,
            flags: 0,
            finder_flags: 0,
            extended_finder_flags: 0,
            finder_file_type: None,
            finder_file_creator: None,
            is_file_extension_hidden: false,
            st_dev: 16777220,
            st_ino: 12345,
            st_nlink: 1,
            st_rdev: 0,
            ctime_sec: 1_000_001,
            ctime_nsec: 0,
            create_time_sec: 999_999,
            create_time_nsec: 0,
            st_blocks: 8,
            st_blksize: 4096,
        }
    }

    /// Build a minimal [`Arq5Node`] for a directory with a single tree blob key SHA1.
    fn make_dir_node(tree_sha1: &str) -> Arq5Node {
        Arq5Node {
            is_tree: true,
            tree_contains_missing_items: false,
            data_compression_type: 0,
            xattrs_compression_type: 0,
            acl_compression_type: 0,
            data_blob_keys: vec![make_blob_key(Some(tree_sha1))],
            data_size: 0,
            xattrs_blob_key: make_blob_key(None),
            xattrs_size: 0,
            acl_blob_key: make_blob_key(None),
            uid: 0,
            gid: 0,
            mode: 0o755,
            mtime_sec: 2_000_000,
            mtime_nsec: 0,
            flags: 0,
            finder_flags: 0,
            extended_finder_flags: 0,
            finder_file_type: None,
            finder_file_creator: None,
            is_file_extension_hidden: false,
            st_dev: 16777220,
            st_ino: 99999,
            st_nlink: 2,
            st_rdev: 0,
            ctime_sec: 2_000_001,
            ctime_nsec: 0,
            create_time_sec: 1_999_999,
            create_time_nsec: 0,
            st_blocks: 0,
            st_blksize: 4096,
        }
    }

    // -------------------------------------------------------------------------
    // Tests: strip_encrypted_prefix
    // -------------------------------------------------------------------------

    #[test]
    fn strip_encrypted_prefix_works() {
        let with_prefix = b"encryptedABCDEFGH";
        let stripped = strip_encrypted_prefix(with_prefix);
        assert_eq!(stripped, b"ABCDEFGH");

        let without_prefix = b"plaindata";
        let unchanged = strip_encrypted_prefix(without_prefix);
        assert_eq!(unchanged, b"plaindata");

        // Exactly "encrypted" with nothing after
        let just_prefix = b"encrypted";
        assert_eq!(strip_encrypted_prefix(just_prefix), b"");

        // Empty slice
        assert_eq!(strip_encrypted_prefix(b""), b"");
    }

    // -------------------------------------------------------------------------
    // Tests: blob_key_to_blob_loc
    // -------------------------------------------------------------------------

    #[test]
    fn blob_key_to_blob_loc_packed() {
        let sha1 = "abcdef1234567890abcdef1234567890abcdef12";
        let db = db_with_entry(sha1, "pack0001", 512, 256);

        let key = make_blob_key(Some(sha1));
        let loc =
            blob_key_to_blob_loc(&key, 2, &db, "packsets/BUCKET-blobs").expect("conversion ok");

        assert!(loc.is_packed);
        assert!(loc.is_arq5_pack_entry);
        assert_eq!(
            loc.relative_path.as_deref(),
            Some("packsets/BUCKET-blobs/pack0001.pack")
        );
        assert_eq!(loc.offset, 512);
        assert_eq!(loc.length, 256);
        assert_eq!(loc.identifier, sha1);
        assert_eq!(loc.compression_type, 2);
    }

    #[test]
    fn blob_key_to_blob_loc_standalone() {
        let sha1 = "abcdef1234567890abcdef1234567890abcdef12";
        let db = empty_db(); // not in any pack

        let key = make_blob_key(Some(sha1));
        let loc =
            blob_key_to_blob_loc(&key, 0, &db, "packsets/BUCKET-blobs").expect("conversion ok");

        assert!(!loc.is_packed);
        assert!(!loc.is_arq5_pack_entry);
        assert_eq!(
            loc.relative_path.as_deref(),
            Some("objects/ab/cdef1234567890abcdef1234567890abcdef12")
        );
        assert_eq!(loc.offset, 0);
        assert_eq!(loc.length, 0);
        assert_eq!(loc.identifier, sha1);
    }

    #[test]
    fn blob_key_null_sha1_rejected() {
        let key = make_blob_key(None);
        let db = empty_db();
        let result = blob_key_to_blob_loc(&key, 0, &db, "packsets/BUCKET-blobs");
        assert!(result.is_err(), "expected error for null SHA1");
    }

    // -------------------------------------------------------------------------
    // Tests: arq5_node_to_node
    // -------------------------------------------------------------------------

    #[test]
    fn arq5_file_node_conversion() {
        let sha1 = "aabbccddeeff00112233445566778899aabbccdd";
        let node = make_file_node(&[sha1]);
        let db = empty_db();

        let result = arq5_node_to_node(&node, &db, "packsets/blobs", &db, "packsets/trees")
            .expect("conversion ok");

        assert!(!result.is_tree);
        assert!(result.tree_blob_loc.is_none());
        assert_eq!(result.data_blob_locs.len(), 1);
        assert_eq!(result.data_blob_locs[0].identifier, sha1);
        assert_eq!(result.item_size, 42);
        assert_eq!(result.mac_st_uid, 501);
        assert_eq!(result.mac_st_gid, 20);
        assert_eq!(result.mac_st_mode, 0o644);
        assert_eq!(result.mtime_sec, 1_000_000);
        assert_eq!(result.computer_os_type, 1);
        assert!(result.acl_blob_loc.is_none());
        assert!(result.xattrs_blob_locs.is_empty());
    }

    #[test]
    fn arq5_dir_node_conversion() {
        let sha1 = "aabbccddeeff00112233445566778899aabbccdd";
        let node = make_dir_node(sha1);
        let db = empty_db();

        let result = arq5_node_to_node(&node, &db, "packsets/blobs", &db, "packsets/trees")
            .expect("conversion ok");

        assert!(result.is_tree);
        assert!(result.tree_blob_loc.is_some());
        assert_eq!(result.tree_blob_loc.as_ref().unwrap().identifier, sha1);
        // For a directory the data_blob_locs must be empty.
        assert!(result.data_blob_locs.is_empty());
        assert_eq!(result.mac_st_mode, 0o755);
        assert_eq!(result.mac_st_nlink, 2);
        assert_eq!(result.mtime_sec, 2_000_000);
    }
}
