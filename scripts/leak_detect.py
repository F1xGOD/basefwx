#!/usr/bin/env python3
"""
BaseFWX - Cryptography Engine
Copyright (C) 2020-2026  FixCraft Inc.
Licensed under the GNU General Public License v3.0 or later.

Memory-leak detector for the Python runtime.

Runs each registered codec / cipher path N iterations, watching:

  1. tracemalloc.get_traced_memory() current and peak.
  2. RSS via /proc/self/status (Linux only; portable fallback uses
     resource.getrusage).
  3. Tracemalloc snapshot deltas between baseline (after warm-up)
     and end-of-run (after gc.collect()), grouped by source line.

For each codec, the script reports the per-iteration RSS slope (KiB
per iteration via linear regression over the iteration RSS curve)
and the top tracemalloc deltas. If the slope is positive and
exceeds the configured threshold, exits non-zero.

Designed to run inside GitHub Actions where the CI runner is a
bounded container; the resource_guards layer is not needed (the
container itself bounds RAM). On developer machines, prefer running
under the lib/resource_guards.sh caps.

Exit codes:
    0  no leak above threshold for any codec
    1  at least one codec leaked above threshold
    2  setup / import error (basefwx unavailable, etc.)

Usage:
    python3 scripts/leak_detect.py
    python3 scripts/leak_detect.py --iters 200 --leak-kib-per-iter 8
    python3 scripts/leak_detect.py --codecs hash512,uhash513,b64
"""

from __future__ import annotations

import argparse
import gc
import os
import sys
import tracemalloc
from pathlib import Path
from typing import Callable, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_ROOT = REPO_ROOT / "python"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

try:
    import basefwx  # type: ignore
except Exception as exc:
    print(f"FATAL: cannot import basefwx from {PY_ROOT}: {exc}", file=sys.stderr)
    raise SystemExit(2)


def _rss_kib() -> int:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(rss)


# Each entry: (codec name, callable that does ONE round-trip with a
# fixed-size payload). All callables take no args and return None.
# Keep payloads small — this script's job is to detect leaks, not
# benchmark throughput.
def _hash512_op() -> None:
    basefwx.hash512("leak-detector probe payload")


def _uhash513_op() -> None:
    # uhash513 is intentionally deprecated, but still included here so
    # retirement does not hide leak regressions in the compatibility path.
    import warnings as _w

    with _w.catch_warnings():
        _w.simplefilter("ignore", category=DeprecationWarning)
        basefwx.uhash513("leak-detector probe payload")


def _b64_op() -> None:
    enc = basefwx.b64encode("leak-detector probe payload")
    _ = basefwx.b64decode(enc)


def _b512_op() -> None:
    # b512 is keyed; use a constant short password to keep KDF cost low.
    enc = basefwx.b512encode("probe", "leak-detector-pw-xx")
    _ = basefwx.b512decode(enc, "leak-detector-pw-xx")


def _pb512_op() -> None:
    enc = basefwx.pb512encode("probe", "leak-detector-pw-xx")
    _ = basefwx.pb512decode(enc, "leak-detector-pw-xx")


def _b256_op() -> None:
    # b256 is retired (3.7.0+) but we still smoke its leak behavior
    # so its retirement doesn't mask any underlying issue. The
    # DeprecationWarning is silenced for the leak run.
    import warnings as _w

    with _w.catch_warnings():
        _w.simplefilter("ignore", category=DeprecationWarning)
        enc = basefwx.b256encode("leak-detector probe payload")
        _ = basefwx.b256decode(enc)


CODECS: dict[str, Tuple[Callable[[], None], int]] = {
    # name: (op, default-iters)
    "hash512": (_hash512_op, 500),
    "uhash513": (_uhash513_op, 500),
    "b64": (_b64_op, 500),
    "b512": (_b512_op, 50),  # b512 is KDF-heavy; fewer iters
    "pb512": (_pb512_op, 50),
    "b256": (_b256_op, 200),
}


def _slope_kib_per_iter(samples: list[tuple[int, int]]) -> float:
    """Linear-regression slope of RSS over actual iteration number.

    Inputs: list of (iteration, RSS KiB) samples. Returns the slope in
    KiB / iteration. A positive slope
    means RSS grows over time; a value at or near zero means stable.
    """
    n = len(samples)
    if n < 2:
        return 0.0
    mean_x = sum(point[0] for point in samples) / n
    mean_y = sum(point[1] for point in samples) / n
    num = sum((iteration - mean_x) * (rss - mean_y) for iteration, rss in samples)
    den = sum((iteration - mean_x) ** 2 for iteration, _ in samples)
    if den == 0:
        return 0.0
    return num / den


def _run_one(name: str, op: Callable[[], None], iters: int,
             sample_every: int) -> Tuple[float, int, int, list[tracemalloc.StatisticDiff]]:
    # Warm-up: 50 iters to settle Python's import cache / NumPy pool.
    for _ in range(min(50, iters // 5 or 1)):
        op()
    gc.collect()

    tracemalloc.start(10)
    baseline_snap = tracemalloc.take_snapshot()
    baseline_rss = _rss_kib()
    samples: list[tuple[int, int]] = [(0, baseline_rss)]

    for i in range(iters):
        op()
        if (i + 1) % sample_every == 0:
            samples.append((i + 1, _rss_kib()))

    gc.collect()
    end_snap = tracemalloc.take_snapshot()
    end_rss = _rss_kib()
    tracemalloc.stop()

    if samples[-1][0] != iters:
        samples.append((iters, end_rss))

    slope = _slope_kib_per_iter(samples)
    top_diffs = end_snap.compare_to(baseline_snap, "lineno")[:5]
    return slope, baseline_rss, end_rss, top_diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters", type=int, default=None,
                        help="iterations per codec (override the per-codec default)")
    parser.add_argument("--sample-every", type=int, default=10,
                        help="record an RSS sample every N iterations (default 10)")
    parser.add_argument("--leak-kib-per-iter", type=float, default=8.0,
                        help="fail if RSS slope exceeds this KiB/iter (default 8)")
    parser.add_argument("--codecs", type=str, default="",
                        help="comma-separated codec subset to run (default: all)")
    parser.add_argument("--quiet", action="store_true",
                        help="only print failing codecs and the final summary")
    args = parser.parse_args()

    selected = [c.strip() for c in args.codecs.split(",") if c.strip()] or list(CODECS.keys())
    unknown = [c for c in selected if c not in CODECS]
    if unknown:
        print(f"unknown codec(s): {','.join(unknown)}", file=sys.stderr)
        print(f"available: {','.join(CODECS.keys())}", file=sys.stderr)
        return 2

    print(f"BaseFWX Python leak detector — repo={REPO_ROOT}")
    print(f"  threshold: {args.leak_kib_per_iter:.1f} KiB / iter")
    print(f"  codecs:    {','.join(selected)}")
    print()

    failed: list[str] = []
    for name in selected:
        op, default_iters = CODECS[name]
        iters = args.iters or default_iters
        slope, base_rss, end_rss, top = _run_one(
            name, op, iters, sample_every=max(1, args.sample_every)
        )
        delta_rss = end_rss - base_rss
        ok = slope <= args.leak_kib_per_iter
        marker = "OK  " if ok else "LEAK"
        if not ok or not args.quiet:
            print(f"  [{marker}] {name:<10} "
                  f"iters={iters:<5} slope={slope:+7.2f} KiB/iter "
                  f"  RSS {base_rss}→{end_rss} (Δ={delta_rss:+d} KiB)")
            if not ok and top:
                print(f"           top tracemalloc deltas:")
                for d in top[:3]:
                    if d.size_diff == 0:
                        continue
                    frame = d.traceback[0] if d.traceback else None
                    where = f"{frame.filename}:{frame.lineno}" if frame else "<?>"
                    print(f"             {d.size_diff:+10d} B   {where}")
        if not ok:
            failed.append(name)

    print()
    if failed:
        print(f"FAIL: {len(failed)} codec(s) leaked: {','.join(failed)}")
        return 1
    print(f"PASS: all {len(selected)} codec(s) stable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
