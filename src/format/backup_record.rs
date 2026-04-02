// SPDX-License-Identifier: MIT
//! Arq7 backup record parsing and folder listing.
//!
//! Each .backuprecord file is:
//!   1. Optionally ARQO-encrypted
//!   2. LZ4-compressed (4-byte BE length + block data)
//!   3. JSON (Arq 7.x) or plist (older Arq7 versions)

use crate::crypto::{Arq7Keys, decrypt_arq7_object};
use crate::format::arq7::{BackupRecord, decompress_lz4};
use crate::storage::Storage;
use anyhow::{Context, Result};
use tracing::warn;

const ARQO_MAGIC: &[u8] = b"ARQO";

/// Parse a raw .backuprecord file (may be encrypted + LZ4-compressed).
///
/// `keys` is `None` if the backup is unencrypted.
pub fn parse_backup_record_bytes(data: &[u8], keys: Option<&Arq7Keys>) -> Result<BackupRecord> {
    // Step 1: decrypt if encrypted (ARQO magic)
    let decrypted;
    let after_decrypt = if data.starts_with(ARQO_MAGIC) {
        let k = keys.context("backup record is encrypted but no keys provided")?;
        decrypted = decrypt_arq7_object(data, k).context("decrypt backup record")?;
        &decrypted[..]
    } else {
        data
    };

    // Step 2: LZ4-decompress
    let record_bytes = decompress_lz4(after_decrypt).context("LZ4 decompress backup record")?;

    // Step 3: parse JSON (Arq 7.x format), fall back to plist for older versions
    if record_bytes.first() == Some(&b'{') {
        parse_backup_record_json(&record_bytes)
    } else {
        parse_backup_record_plist(&record_bytes)
    }
}

fn parse_backup_record_json(data: &[u8]) -> Result<BackupRecord> {
    let v: serde_json::Value = serde_json::from_slice(data).context("parse backup record JSON")?;

    let timestamp = v["creationDate"].as_f64().map(|f| f as u64).unwrap_or(0);

    let local_path = v["localPath"].as_str().unwrap_or("").to_owned();

    let arq_version = v["arqVersion"].as_str().unwrap_or("").to_owned();

    let is_complete = v["isComplete"].as_bool().unwrap_or(false);

    let root_tree_blob_loc = v["node"]["treeBlobLoc"]
        .as_object()
        .map(parse_blob_loc_from_json)
        .transpose()
        .context("parse root treeBlobLoc")?;

    Ok(BackupRecord {
        timestamp,
        root_tree_blob_loc,
        local_path,
        arq_version,
        is_complete,
    })
}

fn parse_blob_loc_from_json(
    dict: &serde_json::Map<String, serde_json::Value>,
) -> Result<crate::format::arq7::BlobLoc> {
    use crate::format::arq7::BlobLoc;

    let identifier = dict
        .get("blobIdentifier")
        .and_then(|v| v.as_str())
        .context("treeBlobLoc: missing blobIdentifier")?
        .to_owned();

    let is_packed = dict
        .get("isPacked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // relativePath may have a leading slash; strip it — it's storage-relative
    let relative_path = dict
        .get("relativePath")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('/').to_owned())
        .filter(|s| !s.is_empty());

    let offset = dict.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);

    let length = dict.get("length").and_then(|v| v.as_u64()).unwrap_or(0);

    let stretch_encryption_key = dict
        .get("stretchEncryptionKey")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let compression_type = dict
        .get("compressionType")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as u32;

    Ok(BlobLoc {
        identifier,
        is_packed,
        is_large_pack: false,
        relative_path,
        offset,
        length,
        stretch_encryption_key,
        compression_type,
        is_arq5_pack_entry: false,
    })
}

fn parse_backup_record_plist(data: &[u8]) -> Result<BackupRecord> {
    use plist::Value;
    let value = Value::from_reader(std::io::Cursor::new(data)).context("parse plist")?;

    let dict = value
        .as_dictionary()
        .context("backup record plist is not a dictionary")?;

    let timestamp = dict
        .get("creationDate")
        .and_then(|v| v.as_real())
        .map(|f| f as u64)
        .or_else(|| {
            dict.get("creationDate")
                .and_then(|v| v.as_unsigned_integer())
        })
        .unwrap_or(0);

    let local_path = dict
        .get("localPath")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_owned();

    let arq_version = dict
        .get("arqVersion")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_owned();

    let is_complete = dict
        .get("isComplete")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    // The root node is in the "node" key — specifically node.treeBlobLoc
    // We extract it as a raw plist for now; full BlobLoc parsing from plist
    let root_tree_blob_loc = dict
        .get("node")
        .and_then(|v| v.as_dictionary())
        .and_then(|node_dict| node_dict.get("treeBlobLoc"))
        .and_then(|v| v.as_dictionary())
        .map(parse_blob_loc_from_plist)
        .transpose()
        .context("parse root treeBlobLoc")?;

    Ok(BackupRecord {
        timestamp,
        root_tree_blob_loc,
        local_path,
        arq_version,
        is_complete,
    })
}

fn parse_blob_loc_from_plist(dict: &plist::Dictionary) -> Result<crate::format::arq7::BlobLoc> {
    use crate::format::arq7::BlobLoc;

    let identifier = dict
        .get("blobIdentifier")
        .and_then(|v| v.as_string())
        .context("treeBlobLoc: missing blobIdentifier")?
        .to_owned();

    let is_packed = dict
        .get("isPacked")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    let relative_path = dict
        .get("relativePath")
        .and_then(|v| v.as_string())
        .map(|s| s.to_owned())
        .filter(|s| !s.is_empty());

    let offset = dict
        .get("offset")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);

    let length = dict
        .get("length")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(0);

    let stretch_encryption_key = dict
        .get("stretchEncryptionKey")
        .and_then(|v| v.as_boolean())
        .unwrap_or(true);

    let compression_type = dict
        .get("compressionType")
        .and_then(|v| v.as_unsigned_integer())
        .unwrap_or(2) as u32;

    Ok(BlobLoc {
        identifier,
        is_packed,
        is_large_pack: false,
        relative_path,
        offset,
        length,
        stretch_encryption_key,
        compression_type,
        is_arq5_pack_entry: false,
    })
}

/// Join a storage-relative path prefix with a suffix, avoiding leading slashes
/// when the prefix is empty.
fn join_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        suffix.to_owned()
    } else {
        format!("{prefix}/{suffix}")
    }
}

/// List all backup records for a single backup folder UUID.
///
/// `folder_path` is the path within storage to the backup folder, e.g.
/// `"<planUUID>/backupfolders/<folderUUID>"`.
///
/// Returns records sorted by timestamp ascending (oldest first).
pub fn list_backup_records(
    storage: &dyn Storage,
    folder_path: &str,
    keys: Option<&Arq7Keys>,
) -> Result<Vec<BackupRecord>> {
    let backuprecords_path = join_path(folder_path, "backuprecords");

    // List 5-digit prefix directories
    let prefixes = storage
        .list(&backuprecords_path)
        .with_context(|| format!("list {backuprecords_path}"))?;

    let mut records = Vec::new();

    for prefix in &prefixes {
        let prefix_path = format!("{backuprecords_path}/{prefix}");
        let files = match storage.list(&prefix_path) {
            Ok(f) => f,
            Err(e) => {
                warn!("failed to list {prefix_path}: {e}");
                continue;
            }
        };

        for filename in &files {
            if !filename.ends_with(".backuprecord") {
                continue;
            }
            let record_path = format!("{prefix_path}/{filename}");
            let data = match storage.read(&record_path) {
                Ok(d) => d,
                Err(e) => {
                    warn!("failed to read {record_path}: {e}");
                    continue;
                }
            };

            match parse_backup_record_bytes(&data, keys) {
                Ok(record) => records.push(record),
                Err(e) => {
                    warn!("failed to parse {record_path}: {e}");
                }
            }
        }
    }

    // Sort by timestamp ascending
    records.sort_by_key(|r| r.timestamp);
    Ok(records)
}

/// List all backup folders within a plan directory.
///
/// Returns `(folder_uuid, local_path, records)` tuples.
pub fn list_all_backup_folders(
    storage: &dyn Storage,
    plan_path: &str,
    keys: Option<&Arq7Keys>,
) -> Result<Vec<(String, String, Vec<BackupRecord>)>> {
    let bf_path = join_path(plan_path, "backupfolders");
    let folder_uuids = storage
        .list(&bf_path)
        .with_context(|| format!("list {bf_path}"))?;

    let mut result = Vec::new();

    for uuid in folder_uuids {
        let folder_path = join_path(&bf_path, &uuid);

        // Read backupfolder.json for the local path (decrypt if needed).
        let local_path = read_folder_local_path(storage, &folder_path, keys)
            .unwrap_or_else(|_| format!("<unknown: {uuid}>"));

        let records = list_backup_records(storage, &folder_path, keys).unwrap_or_else(|e| {
            warn!("failed to list records in {folder_path}: {e}");
            vec![]
        });

        result.push((uuid, local_path, records));
    }

    Ok(result)
}

/// Read `computerName` and `userName` from an Arq5 `computerinfo` plist (plain XML, not encrypted).
/// Returns `(computer_name, user_name)`.  Falls back to empty strings on any error.
pub fn read_arq5_computer_info(storage: &dyn Storage) -> (String, String) {
    let data = match storage.read("computerinfo") {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let text = match std::str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => return (String::new(), String::new()),
    };
    // Simple key-value extraction from the minimal plist format Arq writes.
    // Format: <key>X</key>\n<string>Y</string>
    let extract = |key: &str| -> String {
        let needle = format!("<key>{key}</key>");
        if let Some(pos) = text.find(&needle) {
            let after = &text[pos + needle.len()..];
            if let Some(start) = after.find("<string>") {
                let start = start + "<string>".len();
                if let Some(end) = after[start..].find("</string>") {
                    return after[start..start + end].trim().to_owned();
                }
            }
        }
        String::new()
    };
    (extract("computerName"), extract("userName"))
}

/// Read `computerName` and `backupName` from `backupconfig.json` (plain JSON, not encrypted).
/// Returns `(computer_name, backup_name)`.
pub fn read_backup_config(storage: &dyn Storage, plan_path: &str) -> (String, String) {
    let path = join_path(plan_path, "backupconfig.json");
    let data = match storage.read(&path) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let v: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return (String::new(), String::new()),
    };
    let computer_name = v["computerName"].as_str().unwrap_or("").to_owned();
    let backup_name = v["backupName"].as_str().unwrap_or("").to_owned();
    (computer_name, backup_name)
}

fn read_folder_local_path(
    storage: &dyn Storage,
    folder_path: &str,
    keys: Option<&Arq7Keys>,
) -> Result<String> {
    let json_path = format!("{folder_path}/backupfolder.json");
    let raw = storage.read(&json_path)?;
    // backupfolder.json is ARQO-encrypted when the backup is encrypted.
    let data = if raw.starts_with(ARQO_MAGIC) {
        if let Some(k) = keys {
            decrypt_arq7_object(&raw, k).context("decrypt backupfolder.json")?
        } else {
            raw
        }
    } else {
        raw
    };
    // The decrypted payload may be LZ4-compressed (4-byte BE length prefix).
    let json_bytes = if data.len() > 4 {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len > 0 && len < 10 * 1024 * 1024 && data.len() > 4 {
            decompress_lz4(&data).unwrap_or(data)
        } else {
            data
        }
    } else {
        data
    };
    let v: serde_json::Value =
        serde_json::from_slice(&json_bytes).context("parse backupfolder.json")?;
    Ok(v["localPath"].as_str().unwrap_or("").to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal LZ4-compressed JSON record for testing (no encryption).
    fn make_test_record_bytes_json(timestamp: u64, local_path: &str) -> Vec<u8> {
        let json_str = format!(
            r#"{{"version":100,"arqVersion":"7.10.0.0","creationDate":{timestamp},"isComplete":true,"localPath":"{local_path}"}}"#
        );
        let bytes = json_str.as_bytes();
        let uncompressed_len = (bytes.len() as u32).to_be_bytes();
        let compressed = lz4_flex::compress(bytes);
        let mut out = Vec::new();
        out.extend_from_slice(&uncompressed_len);
        out.extend_from_slice(&compressed);
        out
    }

    /// Build a minimal LZ4-compressed XML plist for testing (plist fallback path).
    fn make_test_record_bytes_plist(timestamp: u64, local_path: &str) -> Vec<u8> {
        let plist_str = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>creationDate</key>
    <integer>{timestamp}</integer>
    <key>localPath</key>
    <string>{local_path}</string>
    <key>arqVersion</key>
    <string>7.3.1.0</string>
    <key>isComplete</key>
    <true/>
</dict>
</plist>"#
        );
        let bytes = plist_str.as_bytes();
        let uncompressed_len = (bytes.len() as u32).to_be_bytes();
        let compressed = lz4_flex::compress(bytes);
        let mut out = Vec::new();
        out.extend_from_slice(&uncompressed_len);
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn parse_unencrypted_json_record() {
        let data = make_test_record_bytes_json(1616936407, "/Users/test");
        let record = parse_backup_record_bytes(&data, None).unwrap();
        assert_eq!(record.timestamp, 1616936407);
        assert_eq!(record.local_path, "/Users/test");
        assert_eq!(record.arq_version, "7.10.0.0");
        assert!(record.is_complete);
        assert!(record.root_tree_blob_loc.is_none());
    }

    #[test]
    fn parse_unencrypted_plist_record_fallback() {
        let data = make_test_record_bytes_plist(1616936407, "/Users/test");
        let record = parse_backup_record_bytes(&data, None).unwrap();
        assert_eq!(record.timestamp, 1616936407);
        assert_eq!(record.local_path, "/Users/test");
        assert_eq!(record.arq_version, "7.3.1.0");
        assert!(record.is_complete);
        assert!(record.root_tree_blob_loc.is_none());
    }
}
