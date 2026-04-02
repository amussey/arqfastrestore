# arqfastrestore — Performance Tracking

## Theoretical Maximum Throughput

The restore pipeline has these stages, each with a theoretical throughput ceiling:

```
Storage read → Decrypt → Decompress → Write (dry-run: skip write)
```

**Storage is the bottleneck.** Decryption (~0.1% of wall time) and decompression (~0.04%) are negligible.

### Storage Backend Throughput Baselines

| Backend | Measured | Latency | Notes |
|---------|----------|---------|-------|
| WSL2→SMB→ZFS (spinning) | 15.5 MB/s per stream | ~166ms | Current test environment |
| Local ZFS (spinning, sequential) | ~100-150 MB/s | <1ms | Expected direct-attached |
| Local ZFS (spinning, random) | ~5-30 MB/s | 5-15ms | Depends on seek pattern |
| Local SSD (NVMe) | ~1-3 GB/s | <0.1ms | Cache disk target |
| S3 (per-request) | ~50-100 MB/s | 50-200ms | Per-stream, parallelizable |

### Read Amplification

Arq stores file chunks inside **pack files**. To read one chunk, we must:
1. Read the entire pack file (or use range requests if supported)
2. Decrypt it
3. Extract the needed bytes

If multiple chunks come from the same pack, caching the pack eliminates re-reads.

**Read amplification** = total bytes read from storage / total logical file data.

| Scenario | Read Amp | Why |
|----------|----------|-----|
| All packs cached | 1.0-1.2x | Each pack read once; small overhead for metadata |
| Partial cache (large backup) | 2-15x | Packs evicted then re-read later |
| No cache (streaming) | 10-50x | Same pack re-read per chunk access |

---

## Benchmark Results

### CCCCCCCC — Small backup (32G on disk, 3.79 GB data, 13,324 files)

**Backup characteristics:**
- 26 large pack files, ~571 MB total → fits entirely in 512 MB pack cache
- High pack reuse: files share packs extensively

| Metric | Warm Tree Cache (v2 instrumentation) |
|--------|--------------------------------------|
| Wall time | 96.7s |
| Storage I/O (cumulative) | 916.9s |
| Bytes read | 3,037 MB |
| Logical output | 3,794 MB |
| Read amplification | **0.80x** (sub-1x = compressed data) |
| Pack cache hit rate | 99.8% (26 misses, 12,549 hits) |
| Unique packs | 26 |
| Packs re-read from storage | **0** (perfect cache) |
| Throughput (wall) | 39.2 MB/s |
| Efficiency vs theoretical | ~95% |

### DDDDDDDD — Large backup (394G on disk, 109.5 GB data, 126,859 files)

**Backup characteristics:**
- ~4,350 pack files, ~5 MB each, ~21.5 GB total unique pack data
- Low pack reuse: packs are small and shard-distributed
- 512 MB cache budget can hold ~100 packs = 2.3% of pack population

| Metric | Warm Tree Cache |
|--------|-----------------|
| Wall time | 3,164s (52.7 min) |
| Storage I/O (cumulative) | 29,647s (8.2 hrs) |
| Bytes read | 278 GB |
| Read amplification | **12.9x** |
| Pack cache hit rate | 58.7% |
| Packs in cache | 1 (overflow!) |
| Throughput (wall) | 34.6 MB/s |
| Efficiency vs theoretical | **~44%** |

**Theoretical max (all packs cached):** 21.5 GB / 15.5 MB/s ≈ 1,387s sequential read time. With ~10 parallel streams: ~140s theoretical minimum wall time. Realistic target (with overhead): ~1,400-1,500s.

**Current: 3,164s → ~2.1-2.3x theoretical.** ~44% efficiency.

**Root cause:** Pack cache is catastrophically undersized. 208 GB of pack data seen through a 512 MB window → 13x re-read amplification. Packs are evicted and re-read repeatedly.

### Efficiency Summary

| Backup | Size | Files | Wall Time | Efficiency | Target |
|--------|------|-------|-----------|------------|--------|
| CCCCCCCC (warm) | 3.98 GB | 13,324 | 40.9s | ~95% | ✅ Exceeds 80% |
| DDDDDDDD (warm) | 109.5 GB | 126,859 | 52.7 min | ~44% | ❌ Below 80% target |

---

## Performance Bottleneck Analysis

### 1. Pack Cache Overflow (DDDDDDDD) — **CRITICAL**

**Problem:** 512 MB cache for 21.5 GB of pack data. Random eviction makes it worse.

**Impact:** 278 GB read instead of 21.5 GB = 13x read amplification = ~2x wall time.

**Solutions (prioritized):**

| Solution | Effort | Impact | Notes |
|----------|--------|--------|-------|
| **Sort restore items by pack file** | Medium | HIGH | Process all chunks from same pack together; each pack read once |
| **Increase cache to available RAM** | Low | Medium | Auto-size to 50-80% of free RAM; helps medium-sized backups |
| **On-disk pack cache (SSD)** | Medium | HIGH | Spill packs to local SSD; ~1000x faster than re-reading from SMB |
| **LRU/frequency eviction** | Low | Low-Med | Better than random, but doesn't fix fundamental sizing issue |
| **Pack index pre-scan** | Medium | HIGH | Read all .index files first → build pack→chunks map → sort by pack |

**Recommended approach:** Sort-by-pack is the single highest-impact change. Instead of processing files in tree-walk order (random pack access), build a map of pack→[chunks] and process all chunks from each pack sequentially. This converts random I/O to sequential I/O and means each pack is read exactly once.

### 2. Rayon Thread Contention on SMB

**Problem:** Multiple rayon threads reading different packs over SMB. Each read takes ~166ms latency + ~330ms transfer (5MB). SMB can multiplex but spinning disks can't.

**Impact:** Disk head thrashing similar to the tree walk issue (already fixed there).

**Note:** This is partially mitigated by the pack cache — when cache hits are high, threads don't all hit storage simultaneously.

### 3. Tree Walk I/O (Solved)

**Problem:** Was using parallel tree walk, causing disk thrashing.
**Status:** ✅ Fixed — sequential tree walk + persistent redb cache.

---

## Pack Cache Strategy: Sort-by-Pack Design

### Concept

Instead of:
```
for each file (tree walk order):
    for each chunk in file:
        read pack containing chunk (random access)
```

Do:
```
Phase 1: Walk tree → collect all (file, chunk_index, pack_id, offset, length)
Phase 2: Group by pack_id → sort
Phase 3: For each pack (sequential):
    read pack once into memory
    extract all chunks belonging to files in this pack
    for each chunk: decrypt, decompress, write to appropriate file
```

### Benefits
- Each pack read exactly once: 21.5 GB total I/O (down from 278 GB)
- Sequential pack access: no disk thrashing
- Minimal memory: only one pack in memory at a time (~5 MB)
- Parallelism: can pipeline (read next pack while processing current)

### Challenges
- Requires knowing all file→chunk→pack mappings before restore starts
- Files with chunks in multiple packs need coordination
- Progress reporting becomes pack-oriented rather than file-oriented

---

## Instrumentation Wishlist

| Metric | Status | Notes |
|--------|--------|-------|
| Storage bytes read | ✅ | `blob.restore.storage_mb` |
| Storage I/O time (cumulative) | ✅ | `blob.restore.storage_s` |
| Pack cache hits/misses | ✅ | `blob.restore.cache_hits/misses` |
| Pack cache memory usage | ✅ | `blob.restore.pack_cache_mb` |
| Decrypt time | ✅ | `blob.restore.decrypt_s` |
| Decompress time | ✅ | `blob.restore.decompress_s` |
| Wall clock time | ✅ | `phase=walk elapsed_s` |
| Per-pack read count | ✅ | `unique_packs=N packs_re_read=N` |
| Read amplification ratio | ✅ | `read_amplification=Nx` (storage/logical) |
| Logical bytes output | ✅ | `logical_mb=N` |
| Unique pack bytes | ❌ | Total unique pack data (denominator for amplification) |
| Queue depth / thread utilization | ❌ | How many rayon threads are active vs blocked on I/O |
| Storage latency histogram | ❌ | p50/p95/p99 per-read latency |

---

## Version History

| Date | Change | Impact |
|------|--------|--------|
| 2026-03-29 | Initial benchmarks: CCCCCCCC + DDDDDDDD | Baseline established |
| 2026-03-29 | Identified pack cache overflow as primary bottleneck | DDDDDDDD at 44% efficiency |
| 2026-03-29 | Added per-pack read count + read amplification instrumentation | CCCC: 0 re-reads, 0.80x amp |
