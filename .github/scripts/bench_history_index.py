#!/usr/bin/env python3
"""Emit website/results/index.json listing every benchmark snapshot the site
should expose, so the benchmark page can offer a history dropdown."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


_BENCH_RE = re.compile(r"^benchmarks-(.+)\.json$")


def read_release_tag(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        tag = data.get("release_tag")
        if isinstance(tag, str) and tag:
            return tag
    except (json.JSONDecodeError, OSError):
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        print(f"results dir not found: {results_dir}")
        return 1

    snapshots: list[dict] = []
    latest_tag: str | None = None

    for path in sorted(results_dir.iterdir()):
        if not path.is_file():
            continue
        match = _BENCH_RE.match(path.name)
        if not match:
            continue
        tag = match.group(1)
        if tag == "latest":
            latest_tag = read_release_tag(path) or latest_tag
            continue
        snapshot = {
            "tag": tag,
            "results": path.name,
        }
        txt = results_dir / f"benchmarks-{tag}.txt"
        if txt.is_file():
            snapshot["txt"] = txt.name
        sidecar = results_dir / f"java-backends-{tag}.json"
        if sidecar.is_file():
            snapshot["java_backends"] = sidecar.name
        snapshots.append(snapshot)

    snapshots.sort(key=lambda s: s["tag"], reverse=True)

    payload = {
        "schema": 1,
        "latest": latest_tag or (snapshots[0]["tag"] if snapshots else ""),
        "snapshots": snapshots,
    }

    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output} ({len(snapshots)} snapshots)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
