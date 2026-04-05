#!/usr/bin/env python3
"""
mts_process.py — Group, concatenate, and transcode AVCHD MTS files into H.265 MP4s.

Groups MTS clips by recording date (from file mtime), then for each day:
  1. Sorts clips chronologically
  2. Concatenates them (lossless, via ffmpeg concat demuxer)
  3. Transcodes to H.265/HEVC with deinterlacing
  4. Embeds provenance metadata (source paths, original filenames)

Usage:
    # Dry run — show proposed groupings, no files written
    python3 mts_process.py --input /path/to/RawVideo --output /path/to/output

    # Execute
    python3 mts_process.py --input /path/to/RawVideo --output /path/to/output --run

    # Use Intel VA-API hardware encoding (hevc_vaapi) instead of software libx265
    # Note: hevc_qsv requires oneVPL on Alder Lake+; hevc_vaapi works universally
    python3 mts_process.py --input /path/to/RawVideo --output /path/to/output --run --vaapi

    # Adjust day-boundary split threshold (default: same calendar date = same event)
    python3 mts_process.py --input /path/to/RawVideo --output /path/to/output --run --gap-hours 6

    # Resume — skip output files that already exist
    python3 mts_process.py --input /path/to/RawVideo --output /path/to/output --run --resume
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_CRF = 22          # libx265 CRF (lower = higher quality; 22 is near-transparent)
DEFAULT_VAAPI_QP = 24     # hevc_vaapi QP (roughly equivalent to CRF 22 in libx265)
DEFAULT_AUDIO_BITRATE = "128k"
DEFAULT_GAP_HOURS = None  # None = group by calendar day; set to split within a day
VAAPI_DEVICE = "/dev/dri/renderD128"


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_mts_files(input_dir: Path) -> list[dict]:
    """Walk input_dir and return a list of MTS file records sorted by mtime."""
    records = []
    for root, _dirs, files in os.walk(input_dir):
        for fname in files:
            if fname.upper().endswith(".MTS"):
                fpath = Path(root) / fname
                stat = fpath.stat()
                mtime = stat.st_mtime
                size = stat.st_size
                records.append({
                    "path": fpath,
                    "mtime": mtime,
                    "size": size,
                    # Relative path from input_dir, used for provenance metadata
                    "rel_path": str(fpath.relative_to(input_dir)),
                })
    records.sort(key=lambda r: r["mtime"])
    return records


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def group_by_date(records: list[dict], gap_hours: float | None) -> list[dict]:
    """
    Group MTS records into events.

    If gap_hours is None: group by calendar date (local time) of mtime.
    If gap_hours is set: split into a new group whenever the gap between
    consecutive clips exceeds gap_hours, regardless of date.

    Returns a list of group dicts, sorted by first-clip mtime:
        {
            "key": "2009-07-19",
            "date": datetime,
            "clips": [record, ...],   # sorted by mtime
            "total_bytes": int,
        }
    """
    if not records:
        return []

    groups: list[dict] = []

    if gap_hours is None:
        # Group by local calendar date
        by_date: dict[str, list] = defaultdict(list)
        for r in records:
            dt = datetime.fromtimestamp(r["mtime"])
            day_key = dt.strftime("%Y-%m-%d")
            by_date[day_key].append(r)
        for day_key in sorted(by_date):
            clips = sorted(by_date[day_key], key=lambda r: r["mtime"])
            groups.append({
                "key": day_key,
                "date": datetime.strptime(day_key, "%Y-%m-%d"),
                "clips": clips,
                "total_bytes": sum(c["size"] for c in clips),
            })
    else:
        # Group by time gap
        gap_secs = gap_hours * 3600
        current_clips = [records[0]]
        for r in records[1:]:
            gap = r["mtime"] - current_clips[-1]["mtime"]
            if gap > gap_secs:
                groups.append(_make_group(current_clips))
                current_clips = [r]
            else:
                current_clips.append(r)
        groups.append(_make_group(current_clips))

    return groups


def _make_group(clips: list[dict]) -> dict:
    clips_sorted = sorted(clips, key=lambda r: r["mtime"])
    dt = datetime.fromtimestamp(clips_sorted[0]["mtime"])
    day_key = dt.strftime("%Y-%m-%d")
    return {
        "key": day_key,
        "date": datetime.strptime(day_key, "%Y-%m-%d"),
        "clips": clips_sorted,
        "total_bytes": sum(c["size"] for c in clips_sorted),
    }


# ---------------------------------------------------------------------------
# Output filename
# ---------------------------------------------------------------------------

def output_path_for_group(output_dir: Path, group: dict, index: int, total: int) -> Path:
    """
    Generate output filename: YYYY-MM-DD_NofM.mp4
    If multiple groups fall on the same date, append a sub-index.
    """
    date_str = group["key"]
    # Count how many groups share this date
    return output_dir / f"{date_str}.mp4"


def deduplicate_output_paths(groups: list[dict], output_dir: Path) -> list[Path]:
    """Return output paths, disambiguating same-date groups with _1, _2 suffixes."""
    date_counts: dict[str, int] = defaultdict(int)
    for g in groups:
        date_counts[g["key"]] += 1

    date_seen: dict[str, int] = defaultdict(int)
    paths = []
    for g in groups:
        key = g["key"]
        if date_counts[key] == 1:
            paths.append(output_dir / f"{key}.mp4")
        else:
            date_seen[key] += 1
            paths.append(output_dir / f"{key}_{date_seen[key]:02d}.mp4")
    return paths


# ---------------------------------------------------------------------------
# Dry-run display
# ---------------------------------------------------------------------------

def display_plan(groups: list[dict], output_paths: list[Path]) -> None:
    print(f"\n{'='*70}")
    print(f"  MTS PROCESSING PLAN  —  {len(groups)} event group(s)")
    print(f"{'='*70}\n")

    total_input_bytes = sum(g["total_bytes"] for g in groups)
    total_clips = sum(len(g["clips"]) for g in groups)

    for g, out_path in zip(groups, output_paths):
        clips = g["clips"]
        size_mb = g["total_bytes"] / 1024 / 1024
        # Estimate duration: AVCHD is ~17 Mbps average
        est_duration_secs = g["total_bytes"] / (17_000_000 / 8)
        est_duration_str = _format_duration(est_duration_secs)

        first_dt = datetime.fromtimestamp(clips[0]["mtime"])
        last_dt = datetime.fromtimestamp(clips[-1]["mtime"])

        print(f"  {g['key']}  ({len(clips)} clips,  {size_mb:.0f} MB,  ~{est_duration_str})")
        print(f"    Recording span: {first_dt.strftime('%H:%M:%S')} – {last_dt.strftime('%H:%M:%S')}")
        print(f"    Output:  {out_path.name}")
        print(f"    Sources:")
        for c in clips:
            print(f"      {c['rel_path']}")
        print()

    print(f"{'─'*70}")
    print(f"  Total input:  {total_clips} clips,  {total_input_bytes/1024/1024/1024:.1f} GB")
    est_output_gb = total_input_bytes / 1024 / 1024 / 1024 * 0.35  # ~65% reduction at CRF 22
    print(f"  Est. output:  ~{est_output_gb:.1f} GB  (H.265, CRF 22, ~65% reduction)")
    print(f"\n  Run with --run to execute.\n")


def _format_duration(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


# ---------------------------------------------------------------------------
# ffmpeg processing
# ---------------------------------------------------------------------------

def build_ffmpeg_cmd(
    concat_list_path: Path,
    output_path: Path,
    provenance_comment: str,
    title: str,
    use_vaapi: bool,
    crf: int,
    vaapi_qp: int,
    audio_bitrate: str,
    vaapi_device: str = VAAPI_DEVICE,
) -> list[str]:
    cmd = [
        "ffmpeg", "-y",
        "-f", "concat", "-safe", "0",
        "-i", str(concat_list_path),
    ]

    if use_vaapi:
        cmd += [
            "-vf", "bwdif=mode=send_field:parity=auto,format=nv12,hwupload=extra_hw_frames=64",
            "-vaapi_device", vaapi_device,
            "-c:v", "hevc_vaapi",
            "-qp", str(vaapi_qp),
        ]
    else:
        cmd += [
            "-vf", "bwdif=mode=send_field:parity=auto",
            "-c:v", "libx265",
            "-crf", str(crf),
            "-preset", "medium",
            "-tag:v", "hvc1",
        ]

    cmd += [
        "-c:a", "aac",
        "-b:a", audio_bitrate,
        # Provenance metadata
        "-metadata", f"title={title}",
        "-metadata", f"comment={provenance_comment}",
        "-metadata", f"description={provenance_comment}",
        # Movflags for better compatibility
        "-movflags", "+faststart",
        str(output_path),
    ]
    return cmd


def process_group(
    group: dict,
    output_path: Path,
    use_vaapi: bool,
    crf: int,
    vaapi_qp: int,
    audio_bitrate: str,
    resume: bool,
    dry_run: bool,
    vaapi_device: str = VAAPI_DEVICE,
) -> bool:
    """Process one event group. Returns True on success."""
    clips = group["clips"]

    if resume and output_path.exists():
        print(f"  SKIP (exists): {output_path.name}")
        return True

    # Build provenance string
    provenance_lines = [f"mts_process.py output — {len(clips)} source clips:"]
    for c in clips:
        provenance_lines.append(f"  {c['rel_path']}")
    provenance_comment = "\n".join(provenance_lines)
    title = group["key"]

    # Write ffmpeg concat list to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="mts_concat_"
    ) as f:
        concat_list_path = Path(f.name)
        for c in clips:
            # ffmpeg concat list requires escaped paths
            escaped = str(c["path"]).replace("'", "'\\''")
            f.write(f"file '{escaped}'\n")

    try:
        cmd = build_ffmpeg_cmd(
            concat_list_path=concat_list_path,
            output_path=output_path,
            provenance_comment=provenance_comment,
            title=title,
            use_vaapi=use_vaapi,
            crf=crf,
            vaapi_qp=vaapi_qp,
            audio_bitrate=audio_bitrate,
            vaapi_device=vaapi_device,
        )

        print(f"\n  Processing: {output_path.name}  ({len(clips)} clips)")
        print(f"  Command: {' '.join(cmd)}\n")

        if dry_run:
            print("  [DRY RUN — not executing]")
            return True

        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            print(f"\n  ERROR: ffmpeg exited with code {result.returncode}", file=sys.stderr)
            # Don't leave a partial output file
            if output_path.exists():
                output_path.unlink()
            return False

        # Set output mtime to match the recording date of the first clip
        os.utime(output_path, (clips[0]["mtime"], clips[0]["mtime"]))
        size_mb = output_path.stat().st_size / 1024 / 1024
        print(f"\n  Done: {output_path.name}  ({size_mb:.0f} MB)")
        return True

    finally:
        concat_list_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Group and transcode AVCHD MTS files into dated H.265 MP4s.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", required=True, type=Path,
        help="Root directory containing MTS files (searched recursively)",
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Output directory for H.265 MP4 files",
    )
    parser.add_argument(
        "--run", action="store_true",
        help="Execute transcoding (default is dry-run only)",
    )
    parser.add_argument(
        "--vaapi", action="store_true",
        help="Use Intel VA-API hardware encoding (hevc_vaapi) instead of software libx265",
    )
    parser.add_argument(
        "--vaapi-device", default=VAAPI_DEVICE,
        help=f"VA-API render device (default: {VAAPI_DEVICE})",
    )
    parser.add_argument(
        "--crf", type=int, default=DEFAULT_CRF,
        help=f"CRF quality for libx265 (default: {DEFAULT_CRF}, lower=better)",
    )
    parser.add_argument(
        "--vaapi-qp", type=int, default=DEFAULT_VAAPI_QP,
        help=f"QP for hevc_vaapi (default: {DEFAULT_VAAPI_QP}, lower=better)",
    )
    parser.add_argument(
        "--audio-bitrate", default=DEFAULT_AUDIO_BITRATE,
        help=f"AAC audio bitrate (default: {DEFAULT_AUDIO_BITRATE})",
    )
    parser.add_argument(
        "--gap-hours", type=float, default=None,
        help="Split into new event when gap between clips exceeds N hours "
             "(default: group by calendar day)",
    )
    parser.add_argument(
        "--jobs", type=int, default=1,
        help="Number of parallel encode jobs (default: 1, recommend 4 for 12700H)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip output files that already exist",
    )
    parser.add_argument(
        "--dump-plan", type=Path, default=None,
        help="Write grouping plan as JSON to this file",
    )
    args = parser.parse_args()

    if args.jobs < 1:
        print("ERROR: --jobs must be >= 1", file=sys.stderr)
        return 1

    # Validate input
    if not args.input.is_dir():
        print(f"ERROR: --input is not a directory: {args.input}", file=sys.stderr)
        return 1

    # Create output dir
    if args.run:
        args.output.mkdir(parents=True, exist_ok=True)

    # Scan
    print(f"Scanning {args.input} for MTS files...", flush=True)
    records = scan_mts_files(args.input)
    if not records:
        print("No MTS files found.", file=sys.stderr)
        return 1
    print(f"Found {len(records)} MTS files.", flush=True)

    # Group
    groups = group_by_date(records, args.gap_hours)
    output_paths = deduplicate_output_paths(groups, args.output)

    # Dump plan JSON if requested
    if args.dump_plan:
        plan = []
        for g, op in zip(groups, output_paths):
            plan.append({
                "key": g["key"],
                "output": str(op),
                "clip_count": len(g["clips"]),
                "total_bytes": g["total_bytes"],
                "clips": [
                    {
                        "path": str(c["path"]),
                        "rel_path": c["rel_path"],
                        "mtime": c["mtime"],
                        "mtime_str": datetime.fromtimestamp(c["mtime"]).isoformat(),
                        "size": c["size"],
                    }
                    for c in g["clips"]
                ],
            })
        args.dump_plan.parent.mkdir(parents=True, exist_ok=True)
        with open(args.dump_plan, "w") as f:
            json.dump(plan, f, indent=2)
        print(f"Plan written to {args.dump_plan}")

    # Display plan
    display_plan(groups, output_paths)

    if not args.run:
        return 0

    # Execute — parallel if --jobs > 1
    errors = 0
    total = len(groups)

    def run_one(args_tuple):
        i, group, out_path = args_tuple
        print(f"\n[{i}/{total}] {group['key']} starting", flush=True)
        ok = process_group(
            group=group,
            output_path=out_path,
            use_vaapi=args.vaapi,
            crf=args.crf,
            vaapi_qp=args.vaapi_qp,
            audio_bitrate=args.audio_bitrate,
            resume=args.resume,
            dry_run=False,
            vaapi_device=args.vaapi_device,
        )
        if not ok:
            print(f"  FAILED: {out_path.name}", file=sys.stderr)
        return ok

    work = [(i, g, p) for i, (g, p) in enumerate(zip(groups, output_paths), 1)]

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, item): item for item in work}
        for fut in as_completed(futures):
            if not fut.result():
                errors += 1

    print(f"\n{'='*70}")
    print(f"  Complete: {len(groups) - errors}/{len(groups)} groups succeeded.")
    if errors:
        print(f"  {errors} group(s) failed — check stderr above.")
    print(f"{'='*70}\n")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
