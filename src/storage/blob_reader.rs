// SPDX-License-Identifier: MIT
//! Resolves a [`BlobLoc`] to raw decrypted+decompressed bytes.
//!
//! A [`BlobLoc`] can point to either a standalone object file or a slice
//! within a pack file.  In both cases the raw bytes may be ARQO-encrypted
//! and/or compressed; this module handles all three steps in order:
//!
//! 1. **Read** — fetch the relevant bytes from storage (with pack file caching).
//! 2. **Decrypt** — if the bytes start with the `"ARQO"` magic and a decryption
//!    function is available, call it to obtain the plaintext.
//! 3. **Decompress** — pass through [`decompress_blob`] according to
//!    `blob_loc.compression_type`.
//!
//! ## Pack file cache
//!
//! Pack files are typically 30–40 MB and contain many blobs. Without caching,
//! the same pack file gets re-read from storage for every blob it contains —
//! extremely wasteful over network storage (SMB/S3). The cache keeps pack
//! file contents in memory so each file is read from storage exactly once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use anyhow::{Context, Result, bail};

use crate::format::arq7::{BlobLoc, decompress_blob};
use crate::storage::Storage;

/// A pluggable decryption function.
///
/// Given raw ARQO-encrypted bytes, returns the decrypted plaintext.
/// Arq7 closures call `decrypt_arq7_object`; Arq5 closures strip the
/// `"encrypted"` prefix and call `decrypt_arq5_object`.
pub type DecryptFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

/// Magic bytes that mark an ARQO-encrypted payload.
const ARQO_MAGIC: &[u8] = b"ARQO";

/// I/O and cache statistics for a [`BlobReader`].
///
/// All fields are atomics — safe to read from any thread at any time.
pub struct BlobReaderStats {
    /// Total `read_blob` calls.
    pub total_reads: AtomicUsize,
    /// Number of packed-blob reads served from the cache.
    pub cache_hits: AtomicUsize,
    /// Number of packed-blob reads that required a storage read.
    pub cache_misses: AtomicUsize,
    /// Total bytes read from storage (not from cache).
    pub bytes_from_storage: AtomicU64,
    /// Wall-clock time spent inside `storage.read()` calls (nanoseconds).
    pub storage_read_nanos: AtomicU64,
    /// Total `maybe_decrypt` calls that performed actual decryption.
    pub decryptions: AtomicUsize,
    /// Wall-clock time spent in decryption (nanoseconds).
    pub decrypt_nanos: AtomicU64,
    /// Total `decompress_blob` calls that performed decompression (type ≠ 0).
    pub decompressions: AtomicUsize,
    /// Wall-clock time spent in decompression (nanoseconds).
    pub decompress_nanos: AtomicU64,
    /// Per-pack storage read counter: how many times each pack file was read
    /// from storage (not from cache). Key = pack path, value = read count.
    pub pack_storage_reads: RwLock<HashMap<String, u64>>,
    /// Total logical (decompressed) bytes produced — the "useful" output.
    pub logical_bytes_out: AtomicU64,
}

impl BlobReaderStats {
    fn new() -> Self {
        Self {
            total_reads: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
            bytes_from_storage: AtomicU64::new(0),
            storage_read_nanos: AtomicU64::new(0),
            decryptions: AtomicUsize::new(0),
            decrypt_nanos: AtomicU64::new(0),
            decompressions: AtomicUsize::new(0),
            decompress_nanos: AtomicU64::new(0),
            pack_storage_reads: RwLock::new(HashMap::new()),
            logical_bytes_out: AtomicU64::new(0),
        }
    }
}

/// Default byte budget for the in-memory pack file cache (512 MiB).
///
/// A small backup may have ~26 large packs (~40 MB each) = ~1 GB total but only 26 unique
/// ones, so 512 MB lets most of them stay hot.  A large backup may have 10K small packs
/// (~5 MB each) with near-zero reuse; 512 MB holds ~100 of them but they're
/// evicted quickly, keeping RSS bounded.
const PACK_CACHE_BUDGET_BYTES: u64 = 512 * 1024 * 1024;

/// A cache slot: the `OnceLock` is set exactly once by whichever thread
/// wins the race.  All other threads calling `get_or_init` will block until
/// the data is ready, then share the same `Arc<Vec<u8>>`.  This eliminates
/// the "thundering herd" where N rayon threads each read the same 40 MB
/// pack file independently.
type PackSlot = Arc<OnceLock<Vec<u8>>>;

/// Resolves [`BlobLoc`] references to their final, usable byte content.
///
/// Includes an in-memory cache for pack files to avoid redundant storage
/// reads when many blobs reside in the same pack.  Uses `OnceLock` per
/// slot to guarantee each pack file is read from storage at most once even
/// under heavy concurrent access from rayon workers.
pub struct BlobReader {
    storage: Arc<dyn Storage>,
    decrypt: Option<DecryptFn>,
    /// Cache: pack-file path → slot.
    pack_cache: RwLock<HashMap<String, PackSlot>>,
    /// Current total bytes held in the cache (populated slots only).
    pack_cache_bytes: std::sync::atomic::AtomicU64,
    /// Maximum bytes to hold in the cache (0 = disabled).
    max_cache_bytes: u64,
    /// Accumulated I/O statistics.
    stats: BlobReaderStats,
}

impl BlobReader {
    /// Create a new `BlobReader` with the default pack cache byte budget.
    pub fn new(storage: Arc<dyn Storage>, decrypt: Option<DecryptFn>) -> Self {
        Self::with_cache_bytes(storage, decrypt, PACK_CACHE_BUDGET_BYTES)
    }

    /// Create a new `BlobReader` with a specific pack cache byte budget.
    ///
    /// Use `max_cache_bytes = 0` to disable caching entirely.
    pub fn with_cache_bytes(
        storage: Arc<dyn Storage>,
        decrypt: Option<DecryptFn>,
        max_cache_bytes: u64,
    ) -> Self {
        Self {
            storage,
            decrypt,
            pack_cache: RwLock::new(HashMap::new()),
            pack_cache_bytes: std::sync::atomic::AtomicU64::new(0),
            max_cache_bytes,
            stats: BlobReaderStats::new(),
        }
    }

    /// Resolve a `BlobLoc` to its raw, decrypted, decompressed bytes.
    ///
    /// Returns an error if:
    /// - The backing file cannot be read from storage.
    /// - The slice indices are out of range (packed case).
    /// - The payload is ARQO-encrypted but no decryption function was provided.
    /// - Decryption or decompression fails.
    pub fn read_blob(&self, loc: &BlobLoc) -> Result<Vec<u8>> {
        self.stats.total_reads.fetch_add(1, Ordering::Relaxed);

        let path = loc.relative_path.as_deref().unwrap_or(&loc.identifier);
        let raw = if loc.is_packed {
            self.read_packed_slice(loc)
                .with_context(|| format!("reading packed blob at {}", path))?
        } else {
            let t0 = Instant::now();
            let data = self
                .storage
                .read(path)
                .with_context(|| format!("reading standalone blob at {}", path))?;
            let elapsed = t0.elapsed().as_nanos() as u64;
            self.stats
                .storage_read_nanos
                .fetch_add(elapsed, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            data
        };

        let decrypted = self.maybe_decrypt(raw, loc)?;

        let result = if loc.compression_type != 0 {
            self.stats.decompressions.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let result = decompress_blob(&decrypted, loc.compression_type).with_context(|| {
                format!(
                    "decompressing blob {} (compression_type={})",
                    loc.identifier, loc.compression_type
                )
            });
            self.stats
                .decompress_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            result
        } else {
            decompress_blob(&decrypted, loc.compression_type)
        };

        // Track logical bytes produced (the useful output).
        if let Ok(ref data) = result {
            self.stats
                .logical_bytes_out
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }

        result
    }

    /// Same as [`read_blob`] but returns `None` if `loc` is `None` or if the
    /// `BlobLoc`'s identifier is empty (indicating a missing/null blob).
    #[allow(dead_code)]
    pub fn read_blob_opt(&self, loc: Option<&BlobLoc>) -> Result<Option<Vec<u8>>> {
        match loc {
            None => Ok(None),
            Some(l) if l.identifier.is_empty() => Ok(None),
            Some(l) => self.read_blob(l).map(Some),
        }
    }

    /// Print a summary of I/O statistics to stderr in `key=value` format.
    ///
    /// `label` is a short tag (e.g. `"walk"` or `"restore"`) prefixed to
    /// every key, making the output easy to grep and parse:
    ///
    /// ```text
    /// blob.walk.reads=22600 cache_hits=22540 cache_misses=60
    /// blob.walk.storage_mb=2.1 storage_s=32.500
    /// …
    /// ```
    pub fn print_stats(&self, label: &str) {
        let total = self.stats.total_reads.load(Ordering::Relaxed);
        let hits = self.stats.cache_hits.load(Ordering::Relaxed);
        let misses = self.stats.cache_misses.load(Ordering::Relaxed);
        let bytes = self.stats.bytes_from_storage.load(Ordering::Relaxed);
        let storage_secs = self.stats.storage_read_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let decryptions = self.stats.decryptions.load(Ordering::Relaxed);
        let decrypt_secs = self.stats.decrypt_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let decompressions = self.stats.decompressions.load(Ordering::Relaxed);
        let decompress_secs = self.stats.decompress_nanos.load(Ordering::Relaxed) as f64 / 1e9;
        let logical_out = self.stats.logical_bytes_out.load(Ordering::Relaxed);

        let cache = self.pack_cache.read().unwrap();
        let cached_packs = cache.len();
        drop(cache);
        let cached_bytes = self.pack_cache_bytes.load(Ordering::Relaxed);
        let mb_cached = cached_bytes as f64 / 1_048_576.0;
        let budget_mb = self.max_cache_bytes as f64 / 1_048_576.0;

        let mb_storage = bytes as f64 / 1_048_576.0;
        let mb_logical = logical_out as f64 / 1_048_576.0;
        let read_amp = if logical_out > 0 {
            bytes as f64 / logical_out as f64
        } else {
            0.0
        };

        eprintln!("blob.{label}.reads={total} cache_hits={hits} cache_misses={misses}");
        eprintln!("blob.{label}.storage_mb={mb_storage:.1} storage_s={storage_secs:.3}");
        eprintln!("blob.{label}.logical_mb={mb_logical:.1} read_amplification={read_amp:.2}x");
        eprintln!(
            "blob.{label}.pack_cache_packs={cached_packs} pack_cache_mb={mb_cached:.1}/{budget_mb:.0}"
        );
        eprintln!("blob.{label}.decryptions={decryptions} decrypt_s={decrypt_secs:.3}");
        eprintln!("blob.{label}.decompressions={decompressions} decompress_s={decompress_secs:.3}");

        // Per-pack storage read report: show packs that were read from
        // storage more than once (indicating cache eviction + re-read).
        if let Ok(map) = self.stats.pack_storage_reads.read() {
            let unique_packs = map.len();
            let multi_read: Vec<_> = map.iter().filter(|(_, count)| **count > 1).collect();
            let total_reread_count: u64 = multi_read.iter().map(|(_, c)| **c - 1).sum();
            eprintln!(
                "blob.{label}.unique_packs={unique_packs} packs_re_read={} total_extra_reads={total_reread_count}",
                multi_read.len()
            );

            // Show top-10 most re-read packs.
            if !multi_read.is_empty() {
                let mut sorted: Vec<_> = multi_read;
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                eprintln!("blob.{label}.top_re_read_packs:");
                for (path, count) in sorted.iter().take(10) {
                    // Shorten path for display — show just the last 2 components.
                    let short = path
                        .rsplit('/')
                        .take(2)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("/");
                    eprintln!("  {count}x  {short}");
                }
                if sorted.len() > 10 {
                    eprintln!("  ... and {} more re-read packs", sorted.len() - 10);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Read the `[offset .. offset+length]` slice from a pack file.
    ///
    /// Uses the in-memory pack cache to avoid re-reading the same pack file.
    /// Each cache slot is an `Arc<OnceLock<Vec<u8>>>`: the first thread to
    /// claim the slot does the storage read while all others wait on the same
    /// `OnceLock`.  This eliminates the thundering-herd where N rayon workers
    /// would each independently read the same 40 MB pack file.
    fn read_packed_slice(&self, loc: &BlobLoc) -> Result<Vec<u8>> {
        let path = loc.relative_path.as_deref().unwrap_or(&loc.identifier);

        // If caching is disabled, read directly from storage every time.
        if self.max_cache_bytes == 0 {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let pack = self
                .storage
                .read(path)
                .with_context(|| format!("reading pack file {}", path))?;
            self.stats
                .storage_read_nanos
                .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(pack.len() as u64, Ordering::Relaxed);
            // Track per-pack storage read count (no-cache path).
            if let Ok(mut map) = self.stats.pack_storage_reads.write() {
                *map.entry(path.to_string()).or_insert(0) += 1;
            }
            return Self::extract_slice(&pack, loc);
        }

        // --- Step 1: get-or-insert a slot with only a read lock held ---
        let slot: PackSlot = {
            {
                let cache = self.pack_cache.read().unwrap();
                if let Some(s) = cache.get(path) {
                    s.clone()
                } else {
                    Arc::new(OnceLock::new()) // placeholder — may be replaced below
                }
            }
        };

        // Re-check under write lock only if we got a placeholder.
        let slot = if slot.get().is_some() {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            slot
        } else {
            let mut cache = self.pack_cache.write().unwrap();
            if let Some(existing) = cache.get(path) {
                let s = existing.clone();
                drop(cache);
                if s.get().is_some() {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                }
                s
            } else {
                // Evict entries until we're under the byte budget.
                // We evict based on current tracked bytes; the new entry's size
                // is unknown until after get_or_init, so we evict conservatively.
                while self.pack_cache_bytes.load(Ordering::Relaxed) >= self.max_cache_bytes
                    && !cache.is_empty()
                {
                    if let Some(key) = cache.keys().next().cloned()
                        && let Some(slot) = cache.remove(&key)
                        && let Some(data) = slot.get()
                    {
                        self.pack_cache_bytes
                            .fetch_sub(data.len() as u64, Ordering::Relaxed);
                    }
                }
                let new_slot: PackSlot = Arc::new(OnceLock::new());
                cache.insert(path.to_string(), new_slot.clone());
                drop(cache);
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
                new_slot
            }
        };

        // --- Step 2: populate the slot (exactly one thread does the I/O) ---
        let pack: &Vec<u8> = slot.get_or_init(|| {
            let t0 = Instant::now();
            let data = self.storage.read(path).unwrap_or_else(|_| Vec::new());
            let elapsed = t0.elapsed().as_nanos() as u64;
            self.stats
                .storage_read_nanos
                .fetch_add(elapsed, Ordering::Relaxed);
            self.stats
                .bytes_from_storage
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            self.pack_cache_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            // Track per-pack storage read count.
            if let Ok(mut map) = self.stats.pack_storage_reads.write() {
                *map.entry(path.to_string()).or_insert(0) += 1;
            }

            data
        });

        if pack.is_empty() {
            self.storage
                .read(path)
                .with_context(|| format!("reading pack file {}", path))?;
        }

        Self::extract_slice(pack, loc)
    }

    /// Extract the raw object data from an Arq5 pack entry at the given offset.
    ///
    /// Arq5 pack entry format at offset:
    ///   - mimetype: Arq-encoded string (1 byte null flag, if not null: 8 bytes BE length + bytes)
    ///   - name: Arq-encoded string (same encoding)
    ///   - data_length: u64 BE
    ///   - data: [u8; data_length]
    fn extract_arq5_pack_entry(pack: &[u8], offset: usize) -> Result<Vec<u8>> {
        let mut pos = offset;

        // Skip mimetype (Arq-encoded optional string)
        if pos >= pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at mimetype null flag");
        }
        let is_null = pack[pos] == 0;
        pos += 1;
        if !is_null {
            if pos + 8 > pack.len() {
                bail!("Arq5 pack entry: unexpected EOF at mimetype length");
            }
            let len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
            pos += 8 + len;
        }

        // Skip name (same encoding)
        if pos >= pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at name null flag");
        }
        let is_null = pack[pos] == 0;
        pos += 1;
        if !is_null {
            if pos + 8 > pack.len() {
                bail!("Arq5 pack entry: unexpected EOF at name length");
            }
            let len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
            pos += 8 + len;
        }

        // Read data length
        if pos + 8 > pack.len() {
            bail!("Arq5 pack entry: unexpected EOF at data length");
        }
        let data_len = u64::from_be_bytes(pack[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        // Read data
        let end = pos + data_len;
        if end > pack.len() {
            bail!(
                "Arq5 pack entry: data [{pos}..{end}) out of bounds (pack size {})",
                pack.len()
            );
        }
        Ok(pack[pos..end].to_vec())
    }

    /// Extract object bytes from a pack buffer based on BlobLoc.
    fn extract_slice(pack: &[u8], loc: &BlobLoc) -> Result<Vec<u8>> {
        if loc.is_arq5_pack_entry {
            return Self::extract_arq5_pack_entry(pack, loc.offset as usize);
        }

        let start = loc.offset as usize;
        let end = start
            .checked_add(loc.length as usize)
            .context("blob slice end overflows usize")?;

        if end > pack.len() {
            bail!(
                "pack slice [{start}..{end}) is out of bounds (pack size {})",
                pack.len()
            );
        }

        Ok(pack[start..end].to_vec())
    }

    /// Decrypt `data` if it starts with the ARQO magic, otherwise pass through.
    fn maybe_decrypt(&self, data: Vec<u8>, loc: &BlobLoc) -> Result<Vec<u8>> {
        if !data.starts_with(ARQO_MAGIC) {
            return Ok(data);
        }

        self.stats.decryptions.fetch_add(1, Ordering::Relaxed);

        let decrypt = self.decrypt.as_ref().with_context(|| {
            format!(
                "blob {} is ARQO-encrypted but no decryption function was provided",
                loc.identifier
            )
        })?;

        let t0 = Instant::now();
        let result =
            (decrypt)(&data).with_context(|| format!("decrypting blob {}", loc.identifier));
        self.stats
            .decrypt_nanos
            .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // -------------------------------------------------------------------------
    // MockStorage
    // -------------------------------------------------------------------------

    /// Simple in-memory storage backed by a `HashMap<String, Vec<u8>>`.
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
                .with_context(|| format!("MockStorage: path not found: {path}"))
        }

        fn list(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn exists(&self, path: &str) -> Result<bool> {
            Ok(self.files.contains_key(path))
        }
    }

    // -------------------------------------------------------------------------
    // Helper: build a minimal BlobLoc
    // -------------------------------------------------------------------------

    fn make_loc(
        relative_path: &str,
        is_packed: bool,
        offset: u64,
        length: u64,
        compression_type: u32,
    ) -> BlobLoc {
        BlobLoc {
            identifier: "deadbeef".to_string(),
            is_packed,
            is_large_pack: false,
            relative_path: Some(relative_path.to_string()),
            offset,
            length,
            stretch_encryption_key: false,
            compression_type,
            is_arq5_pack_entry: false,
        }
    }

    // -------------------------------------------------------------------------
    // Test 1: standalone, unencrypted, no compression
    // -------------------------------------------------------------------------

    #[test]
    fn standalone_unencrypted_no_compression() {
        let content = b"hello arq world".to_vec();

        let mut storage = MockStorage::new();
        storage.insert("standardobjects/ab/deadbeef", content.clone());

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc(
            "standardobjects/ab/deadbeef",
            false,
            0,
            content.len() as u64,
            0,
        );

        let result = reader.read_blob(&loc).unwrap();
        assert_eq!(result, content);
    }

    // -------------------------------------------------------------------------
    // Test 2: packed, unencrypted, LZ4-compressed
    // -------------------------------------------------------------------------

    #[test]
    fn packed_unencrypted_lz4() {
        let original = b"the quick brown fox jumps over the lazy dog";

        // Build the LZ4 frame: 4-byte BE uncompressed length + raw LZ4 block.
        let be_len = (original.len() as u32).to_be_bytes();
        let compressed_block = lz4_flex::compress(original);
        let mut blob_bytes = be_len.to_vec();
        blob_bytes.extend_from_slice(&compressed_block);

        // Place the blob at an arbitrary offset within a larger "pack" file.
        let prefix = b"xxxx_padding_xxxx";
        let offset = prefix.len() as u64;
        let length = blob_bytes.len() as u64;

        let mut pack_data = prefix.to_vec();
        pack_data.extend_from_slice(&blob_bytes);
        // Append some trailing garbage to confirm we only read the slice.
        pack_data.extend_from_slice(b"trailing_garbage");

        let mut storage = MockStorage::new();
        storage.insert("blobpacks/ab/cdef1234.pack", pack_data);

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc(
            "blobpacks/ab/cdef1234.pack",
            true,
            offset,
            length,
            2, // LZ4
        );

        let result = reader.read_blob(&loc).unwrap();
        assert_eq!(result, original.as_ref());
    }

    // -------------------------------------------------------------------------
    // Test 3: read_blob_opt with None and empty identifier
    // -------------------------------------------------------------------------

    #[test]
    fn read_blob_opt_none_and_empty_identifier() {
        let storage = MockStorage::new();
        let reader = BlobReader::new(Arc::new(storage), None);

        // None input → None output, no error.
        assert!(reader.read_blob_opt(None).unwrap().is_none());

        // BlobLoc with empty identifier → None output, no error.
        let empty_loc = BlobLoc {
            identifier: String::new(),
            is_packed: false,
            is_large_pack: false,
            relative_path: Some("does/not/matter".to_string()),
            offset: 0,
            length: 0,
            stretch_encryption_key: false,
            compression_type: 0,
            is_arq5_pack_entry: false,
        };
        assert!(reader.read_blob_opt(Some(&empty_loc)).unwrap().is_none());
    }

    // -------------------------------------------------------------------------
    // Test 4: packed slice out of bounds → error
    // -------------------------------------------------------------------------

    #[test]
    fn packed_slice_out_of_bounds() {
        let mut storage = MockStorage::new();
        storage.insert("blobpacks/small.pack", vec![0u8; 10]);

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc("blobpacks/small.pack", true, 5, 20, 0); // 5+20 = 25 > 10

        assert!(reader.read_blob(&loc).is_err());
    }

    // -------------------------------------------------------------------------
    // Test 5: encrypted blob without decrypt fn → error
    // -------------------------------------------------------------------------

    #[test]
    fn encrypted_blob_without_keys_returns_error() {
        let mut data = b"ARQO".to_vec();
        data.extend_from_slice(b"some_ciphertext_payload");

        let mut storage = MockStorage::new();
        storage.insert("standardobjects/ab/encblob", data.clone());

        let reader = BlobReader::new(Arc::new(storage), None);
        let loc = make_loc("standardobjects/ab/encblob", false, 0, data.len() as u64, 0);

        let err = reader.read_blob(&loc).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no decryption function was provided"),
            "unexpected error: {msg}"
        );
    }
}
