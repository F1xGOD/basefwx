#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


CANONICAL_ASSETS = {
    "basefwx-linux-amd64": {"os": "linux", "arch": "amd64", "kind": "native", "linkage": "static"},
    "basefwx-linux-arm64": {"os": "linux", "arch": "arm64", "kind": "native", "linkage": "static"},
    "basefwx-windows-amd64.exe": {"os": "windows", "arch": "amd64", "kind": "native", "linkage": "static"},
    "basefwx-windows-x86.exe": {"os": "windows", "arch": "x86", "kind": "native", "linkage": "static"},
    "basefwx-mac-amd64": {"os": "macos", "arch": "amd64", "kind": "native", "linkage": "static"},
    "basefwx-mac-arm64": {"os": "macos", "arch": "arm64", "kind": "native", "linkage": "static"},
    "basefwx-java.jar": {"os": "cross-platform", "arch": "jvm", "kind": "java", "linkage": "jar"},
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_checksum_file(path: Path) -> str:
    line = path.read_text(encoding="utf-8").strip()
    if not line:
        raise SystemExit(f"Empty checksum file: {path}")
    return line.split()[0]


def classify_features(name: str) -> dict[str, bool]:
    if name == "basefwx-java.jar":
        return {"argon2": False, "oqs": False, "lzma": False}
    return {"argon2": True, "oqs": True, "lzma": True}


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        print("Usage: release_manifest.py <dist-dir> [release-tag]", file=sys.stderr)
        return 2

    dist_dir = Path(sys.argv[1]).resolve()
    release_tag = sys.argv[2] if len(sys.argv) == 3 else "unknown"
    if not dist_dir.is_dir():
        raise SystemExit(f"Not a directory: {dist_dir}")

    present_files = {path.name: path for path in dist_dir.iterdir() if path.is_file()}
    manifest_assets = []

    missing = []
    extras = []
    for name in CANONICAL_ASSETS:
        if name not in present_files:
            missing.append(name)
            continue
        for suffix in (".sha256", ".md5", ".sig"):
            if f"{name}{suffix}" not in present_files:
                missing.append(f"{name}{suffix}")
    for name in sorted(present_files):
        if name == "release-manifest.json":
            continue
        base_name = name
        for suffix in (".sha256", ".md5", ".sig"):
            if name.endswith(suffix):
                base_name = name[: -len(suffix)]
                break
        if base_name not in CANONICAL_ASSETS:
            extras.append(name)
    if missing or extras:
        problems = []
        if missing:
            problems.append("missing: " + ", ".join(sorted(missing)))
        if extras:
            problems.append("unexpected: " + ", ".join(sorted(extras)))
        raise SystemExit("Release artifact validation failed: " + "; ".join(problems))

    for name, meta in CANONICAL_ASSETS.items():
        binary = present_files[name]
        sha256_path = present_files[f"{name}.sha256"]
        md5_path = present_files[f"{name}.md5"]
        sig_path = present_files[f"{name}.sig"]
        sha256_value = sha256_file(binary)
        sha256_file_value = read_checksum_file(sha256_path)
        if sha256_value != sha256_file_value:
            raise SystemExit(f"SHA256 mismatch for {name}: manifest file does not match binary")
        manifest_assets.append(
            {
                "name": name,
                "size_bytes": binary.stat().st_size,
                "sha256": sha256_value,
                "sha256_file": sha256_file_value,
                "md5_file": read_checksum_file(md5_path),
                "signature": sig_path.name,
                "os": meta["os"],
                "arch": meta["arch"],
                "kind": meta["kind"],
                "linkage": meta["linkage"],
                "features": classify_features(name),
            }
        )

    manifest = {
        "project": "basefwx",
        "release_tag": release_tag,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": (dist_dir.parent / "VERSION").read_text(encoding="utf-8").strip()
        if (dist_dir.parent / "VERSION").exists()
        else "",
        "assets": manifest_assets,
    }
    (dist_dir / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
