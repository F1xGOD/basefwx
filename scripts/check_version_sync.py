#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    version = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise SystemExit("VERSION file is empty")

    vcpkg = json.loads((repo_root / "cpp" / "vcpkg.json").read_text(encoding="utf-8"))
    if vcpkg.get("version-string") != version:
        raise SystemExit(
            f"cpp/vcpkg.json version-string {vcpkg.get('version-string')!r} does not match VERSION {version!r}"
        )

    changelog = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[v{re.escape(version)}\](?:\s|$)", changelog, flags=re.MULTILINE):
        raise SystemExit(f"CHANGELOG.md does not contain a section for v{version}")

    print(f"Version sync OK: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
