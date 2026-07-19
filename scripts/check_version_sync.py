#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

from __future__ import annotations

import json
import re
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    version = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise SystemExit("VERSION file is empty")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?", version):
        raise SystemExit(
            f"VERSION {version!r} must be MAJOR.MINOR.PATCH with an optional -prerelease suffix"
        )

    vcpkg = json.loads((repo_root / "cpp" / "vcpkg.json").read_text(encoding="utf-8"))
    if vcpkg.get("version-string") != version:
        raise SystemExit(
            f"cpp/vcpkg.json version-string {vcpkg.get('version-string')!r} does not match VERSION {version!r}"
        )

    python_version = (repo_root / "python" / "VERSION").read_text(encoding="utf-8").strip()
    if python_version != version:
        raise SystemExit(f"python/VERSION {python_version!r} does not match VERSION {version!r}")

    version_info = (repo_root / "java" / "src" / "main" / "java" / "com" /
                    "fixcraft" / "basefwx" / "VersionInfo.java").read_text(encoding="utf-8")
    java_match = re.search(
        r'ENGINE_VERSION_FALLBACK\s*=\s*"([^"]+)"', version_info
    )
    if not java_match or java_match.group(1) != version:
        found = java_match.group(1) if java_match else None
        raise SystemExit(
            f"VersionInfo.java fallback {found!r} does not match VERSION {version!r}"
        )

    java_properties = (repo_root / "java" / "src" / "main" / "resources" /
                       "basefwx-build.properties").read_text(encoding="utf-8")
    properties_match = re.search(r"^version_fallback=(.+)$", java_properties,
                                 flags=re.MULTILINE)
    if not properties_match or properties_match.group(1).strip() != version:
        found = properties_match.group(1).strip() if properties_match else None
        raise SystemExit(
            f"basefwx-build.properties fallback {found!r} does not match VERSION {version!r}"
        )

    changelog = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[v{re.escape(version)}\](?:\s|$)", changelog, flags=re.MULTILINE):
        raise SystemExit(f"CHANGELOG.md does not contain a section for v{version}")

    print(f"Version sync OK: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
