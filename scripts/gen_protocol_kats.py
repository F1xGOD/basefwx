#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Generate repository protocol KAT fixtures from the C++ reference.

Usage (from repo root):
  python3 scripts/gen_protocol_kats.py

Builds cpp/tools/protocol_kat_gen if needed and writes the same vector snapshot
to the shared root fixture (used by C++/Python) and Java test resources.

Java and Python KAT tests must match these bytes exactly. Do not hand-edit
the output fields — regenerate from C++ after changing crypto helpers.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = (
    REPO / "testdata" / "protocol_kats" / "vectors.json",
    REPO / "java" / "src" / "test" / "resources" / "protocol_kats" / "vectors.json",
)
DEFAULT_BUILD = REPO / "cpp" / "build-kats"


def validate_kat_data(data: dict) -> None:
    """Reject incomplete generator output before touching either fixture."""
    required = (
        "hkdf_sha256_salted",
        "hkdf_sha256_empty_salt",
        "x25519",
        "ml_kem_768",
        "ml_kem_1024",
    )
    missing = [section for section in required if not data.get(section)]
    if missing:
        raise ValueError(
            "generated JSON missing required KAT sections "
            "(complete ML-KEM evidence is mandatory): "
            + ", ".join(missing)
        )
    if data.get("ml_kem_1024_available") is not True:
        raise ValueError(
            "generated JSON lacks complete ML-KEM evidence; rebuild protocol_kat_gen "
            "with liboqs before regenerating fixtures"
        )


def check_fixture_copies(outputs: Iterable[Path] = OUTPUTS) -> None:
    paths = tuple(outputs)
    if not paths:
        raise ValueError("no protocol KAT fixture outputs configured")
    try:
        expected = paths[0].read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to read protocol KAT fixture {paths[0]}: {exc}") from exc
    mismatches = []
    for output in paths[1:]:
        try:
            current = output.read_bytes()
        except OSError:
            current = None
        if current != expected:
            mismatches.append(output)
    if mismatches:
        raise ValueError(
            "protocol KAT fixture copies differ: "
            + ", ".join(str(path) for path in mismatches)
        )


def _stage_atomic_write(output: Path, serialized: str) -> Path:
    """Write and fsync a same-directory temporary file for atomic replacement."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
        delete=False,
    ) as handle:
        staged = Path(handle.name)
        try:
            handle.write(serialized)
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
    return staged


def write_fixture_copies(data: dict, outputs: Iterable[Path] = OUTPUTS) -> None:
    """Validate, stage every copy, then atomically replace each file.

    Each individual replacement is atomic. The two fixture paths are not one
    filesystem transaction; interruption between replacements can leave drift,
    which ``--check-copies`` detects.
    """
    validate_kat_data(data)
    paths = tuple(outputs)
    if not paths:
        raise ValueError("no protocol KAT fixture outputs configured")
    serialized = json.dumps(data, indent=2) + "\n"
    staged: list[tuple[Path, Path]] = []
    try:
        for output in paths:
            staged.append((output, _stage_atomic_write(output, serialized)))
        for output, temporary in staged:
            os.replace(temporary, output)
            print(f"wrote {output.relative_to(REPO) if output.is_relative_to(REPO) else output}")
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def configure_and_build(build_dir: Path) -> Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    cmake = ["cmake", "-S", str(REPO / "cpp"), "-B", str(build_dir),
             "-DBASEFWX_BUILD_CLI=OFF",
             "-DBASEFWX_BUILD_PROTOCOL_KAT_GEN=ON",
             "-DCMAKE_BUILD_TYPE=Release"]
    subprocess.check_call(cmake)
    subprocess.check_call(
        ["cmake", "--build", str(build_dir), "--target", "protocol_kat_gen", "-j"]
    )
    binary = build_dir / "protocol_kat_gen"
    if not binary.is_file():
        # Multi-config generators may place the binary under Release/
        alt = build_dir / "Release" / "protocol_kat_gen"
        if alt.is_file():
            return alt
        raise SystemExit(f"protocol_kat_gen not found under {build_dir}")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(os.environ.get("BASEFWX_KAT_BUILD", str(DEFAULT_BUILD))),
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=None,
        help="Use an existing protocol_kat_gen binary (skip cmake)",
    )
    parser.add_argument(
        "--check-copies",
        action="store_true",
        help="Verify that all repository fixture copies are byte-identical",
    )
    args = parser.parse_args()

    if args.check_copies:
        try:
            check_fixture_copies()
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        print("all protocol KAT fixture copies are byte-identical")
        return 0

    binary = args.binary if args.binary else configure_and_build(args.build_dir)
    raw = subprocess.check_output([str(binary)], text=True)
    data = json.loads(raw)
    try:
        write_fixture_copies(data)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"protocol KAT generation aborted without a complete update: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
