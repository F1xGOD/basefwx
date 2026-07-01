#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Format VirusTotal link manifest into a readable text report."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: format_vt_results.py <input.json> <output.txt>", file=sys.stderr)
        return 2

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    data = json.loads(in_path.read_text(encoding="utf-8"))
    files = data.get("files", [])

    lines: list[str] = [
        "BaseFWX VirusTotal report links",
        f"Release: {data.get('release_tag', '')}",
        f"Generated: {data.get('generated_at', '')}",
        "",
        "Open each link on VirusTotal to review engine results.",
        "",
    ]
    note = data.get("note")
    if note:
        lines.extend([f"Note: {note}", ""])

    for entry in files:
        name = entry.get("name", "")
        scanned_payload = entry.get("scanned_payload", "")
        status = entry.get("status", "")
        gui_url = entry.get("gui_url", "")
        analysis_url = entry.get("analysis_url", "")
        error = entry.get("error", "")

        lines.append(f"File: {name}")
        if scanned_payload and scanned_payload != name:
            lines.append(f"  Scanned payload: {scanned_payload}")
        lines.append(f"  Status: {status}")
        if gui_url:
            lines.append(f"  Report: {gui_url}")
        if analysis_url:
            lines.append(f"  API analysis: {analysis_url}")
        if error:
            lines.append(f"  Error: {error}")
        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
