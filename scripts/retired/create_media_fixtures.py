#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Create fixtures used only by the retired media compatibility suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _write_png(path: Path, size: int) -> None:
    try:
        from PIL import Image

        image = Image.frombytes("RGB", (size, size), os.urandom(size * size * 3))
        image.save(path)
    except Exception:
        path.write_bytes(os.urandom(size * size * 3))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: create_media_fixtures.py <output-directory>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    mode = os.getenv("TEST_MODE", "default")
    if mode in ("fast", "quickest"):
        image_size = 96
    elif mode == "heavy":
        image_size = 320
    else:
        image_size = 192
    _write_png(root / "jmg_sample.png", image_size)

    payload_bytes = 2 * 1024 * 1024 if mode == "heavy" else 256 * 1024
    (root / "kfm_payload.bin").write_bytes(os.urandom(payload_bytes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
