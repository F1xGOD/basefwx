#!/usr/bin/env python3
"""Append pure-Java + JNI FwxAESBenchmark numbers into a side-car JSON.

Independent of the main benchmarks-<tag>.json so older snapshots keep working;
the website renders an extra panel when this side-car is present and stays
silent otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


_LINE_RE = re.compile(
    r"^\s*(?P<label>\S+)\s+encrypt\s+(?P<enc_ms>[\d.]+)\s*ms\s*\((?P<enc_mibs>[\d.]+)\s*MiB/s\)"
    r"\s+decrypt\s+(?P<dec_ms>[\d.]+)\s*ms\s*\((?P<dec_mibs>[\d.]+)\s*MiB/s\)"
)


def parse_run(text: str) -> dict | None:
    for line in text.splitlines():
        match = _LINE_RE.match(line)
        if match:
            return {
                "encrypt_ms": float(match.group("enc_ms")),
                "decrypt_ms": float(match.group("dec_ms")),
                "encrypt_mibs": float(match.group("enc_mibs")),
                "decrypt_mibs": float(match.group("dec_mibs")),
            }
    return None


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MiB"
    return f"{n / 1024 / 1024 / 1024:.2f} GiB"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--pure-output", required=True)
    ap.add_argument("--jni-output", required=True)
    ap.add_argument("--append", required=True, help="JSON file to append the sample to")
    args = ap.parse_args()

    pure_text = Path(args.pure_output).read_text(encoding="utf-8")
    jni_text = Path(args.jni_output).read_text(encoding="utf-8")

    pure = parse_run(pure_text)
    jni = parse_run(jni_text)

    if pure is None:
        print("ERROR: could not parse pure-java benchmark output", file=sys.stderr)
        print(pure_text, file=sys.stderr)
        return 1

    out = Path(args.append)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        try:
            existing = json.loads(out.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    else:
        existing = {}

    samples = existing.get("samples")
    if not isinstance(samples, list):
        samples = []

    samples = [s for s in samples if s.get("size_bytes") != args.size]

    sample: dict = {
        "size_bytes": args.size,
        "size_human": human_size(args.size),
        "pure_java": pure,
    }
    if jni is None:
        sample["jni"] = {"available": False}
    else:
        sample["jni"] = dict(jni, available=True)

    samples.append(sample)
    samples.sort(key=lambda s: s.get("size_bytes", 0))

    payload = {
        "schema": 1,
        "release_tag": os.environ.get("BASEFWX_RELEASE_TAG", existing.get("release_tag", "")),
        "generated_at": existing.get("generated_at"),
        "samples": samples,
    }

    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
