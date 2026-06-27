#!/usr/bin/env python3
"""Drop old benchmark / VirusTotal snapshots from website/results.

Keeps *-latest.* plus the newest N versioned tags. Run before git add in CI.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


_BENCH_RE = re.compile(r"^benchmarks-(.+)\.(json|txt)$")
_JAVA_RE = re.compile(r"^java-backends-(.+)\.json$")
_VT_RE = re.compile(r"^virustotal-(.+)\.(json|txt)$")


def _max_snapshots() -> int:
    raw = os.environ.get("BASEFWX_MAX_RESULT_SNAPSHOTS", "8").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 8
    return max(1, value)


def _tag_sort_key(tag: str) -> tuple:
    """Rough semver-ish ordering: v3.7.0 > v3.6.4 > manual-2026."""
    body = tag.lstrip("vV")
    parts: list[tuple[int, object]] = []
    for piece in re.split(r"[.\-_]", body):
        if piece.isdigit():
            parts.append((0, int(piece)))
        else:
            parts.append((1, piece))
    return tuple(parts)


def _collect_tags(paths: list[Path], pattern: re.Pattern[str]) -> dict[str, list[Path]]:
    by_tag: dict[str, list[Path]] = {}
    for path in paths:
        match = pattern.match(path.name)
        if not match:
            continue
        tag = match.group(1)
        if tag == "latest":
            continue
        by_tag.setdefault(tag, []).append(path)
    return by_tag


def _prune_groups(
    by_tag: dict[str, list[Path]],
    *,
    keep_tag: str,
    max_snapshots: int,
) -> list[Path]:
    to_delete: list[Path] = []
    if not by_tag:
        return to_delete

    ranked = sorted(by_tag.keys(), key=_tag_sort_key, reverse=True)
    keep = set(ranked[:max_snapshots])
    if keep_tag:
        keep.add(keep_tag)

    for tag, paths in by_tag.items():
        if tag not in keep:
            to_delete.extend(paths)
    return to_delete


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--keep-tag", default="", help="Release tag to always retain")
    ap.add_argument("--max-snapshots", type=int, default=0)
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        print(f"results dir not found: {results_dir}")
        return 1

    max_snapshots = args.max_snapshots or _max_snapshots()
    keep_tag = args.keep_tag.strip()

    files = [p for p in results_dir.iterdir() if p.is_file()]
    doomed: list[Path] = []
    doomed.extend(_prune_groups(_collect_tags(files, _BENCH_RE), keep_tag=keep_tag, max_snapshots=max_snapshots))
    doomed.extend(_prune_groups(_collect_tags(files, _JAVA_RE), keep_tag=keep_tag, max_snapshots=max_snapshots))
    doomed.extend(_prune_groups(_collect_tags(files, _VT_RE), keep_tag=keep_tag, max_snapshots=max_snapshots))

    removed = 0
    for path in sorted(set(doomed)):
        if not path.is_file():
            continue
        path.unlink()
        print(f"pruned {path.name}")
        removed += 1

    print(f"prune complete: removed {removed} file(s), keeping {max_snapshots} versioned snapshot(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
