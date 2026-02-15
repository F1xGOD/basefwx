#!/usr/bin/env python3
"""Format VirusTotal JSON results into a readable text report."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _stats_line(stats: dict) -> str:
    order = [
        "malicious",
        "suspicious",
        "undetected",
        "harmless",
        "timeout",
        "failure",
        "type-unsupported",
    ]
    parts = [f"{key}={int(stats.get(key, 0))}" for key in order]
    return ", ".join(parts)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: format_vt_results.py <input.json> <output.txt>", file=sys.stderr)
        return 2

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    data = json.loads(in_path.read_text(encoding="utf-8"))
    files = data.get("files", [])

    lines: list[str] = [
        "BaseFWX VirusTotal Results",
        f"Release: {data.get('release_tag', '')}",
        f"Generated: {data.get('generated_at', '')}",
        f"Repository: {data.get('repository', '')}",
        "",
    ]

    for entry in files:
        name = entry.get("name", "")
        status = entry.get("status", "")
        analysis_url = entry.get("analysis_url", "")
        item_url = entry.get("item_url", "")
        stats = entry.get("stats", {}) or {}
        sha256 = entry.get("sha256", "")
        sha1 = entry.get("sha1", "")
        md5 = entry.get("md5", "")

        lines.extend(
            [
                f"File: {name}",
                f"  Status: {status}",
                f"  VirusTotal analysis: {analysis_url}",
                f"  VirusTotal file: {item_url}",
                f"  Stats: {_stats_line(stats)}",
                f"  SHA256: {sha256}",
                f"  SHA1: {sha1}",
                f"  MD5: {md5}",
                "",
            ]
        )

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
