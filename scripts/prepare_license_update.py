#!/usr/bin/env python3
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Dry-run/apply license header updates for BaseFWX source files."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

BASEFWX_GPL_NEW = "Licensed under the GNU General Public License v3.0 or later."
BASEFWX_LGPL_NEW = "Licensed under the GNU Lesser General Public License v3.0 or later."
BASEFWX_EXAMPLE_NEW = "SPDX-License-Identifier: MIT OR Apache-2.0"
BASEFWX_MIXED_NEW = "SPDX-License-Identifier: LGPL-3.0-or-later AND GPL-3.0-or-later"

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".java",
    ".mm",
    ".py",
    ".sh",
    ".txt",
}

SKIP_DIR_NAMES = {
    ".git",
    ".gradle",
    ".pytest_cache",
    "__pycache__",
    "build",
    "build-fix",
    "vendor",
    "third_party",
    "website",
    "debian",
    "docs",
    "AI_gen",
    ".venv",
    ".tmp_basefwx_tests",
}


def is_skipped(path: Path) -> bool:
    if path.name.startswith("LICENSE") or path.name.startswith("LICENCE"):
        return True
    rel_parts = path.relative_to(ROOT).parts
    for index, part in enumerate(rel_parts):
        if part in SKIP_DIR_NAMES:
            return True
        if index < len(rel_parts) - 1 and part.startswith("build-"):
            return True
        if part.startswith(".tmp"):
            return True
    return False


def license_for(path: Path) -> str | None:
    rel = path.relative_to(ROOT).as_posix()

    if rel.startswith("examples/plugins/"):
        return BASEFWX_EXAMPLE_NEW

    if rel.startswith("cpp/src/cli/") or rel.startswith("cpp/include/basefwx/cli/"):
        return BASEFWX_GPL_NEW
    if rel in {
        "cpp/include/basefwx/cli_colors.hpp",
        "cpp/src/main.cpp",
        "cpp/src/cli_colors.cpp",
        "python/basefwx/_cli.py",
        "python/basefwx/__main__.py",
        "java/src/main/java/com/fixcraft/basefwx/cli/BaseFwxCli.java",
        "java/src/main/java/com/fixcraft/basefwx/cli/BenchCommands.java",
        "java/src/main/java/com/fixcraft/basefwx/cli/CodecCommands.java",
        "java/src/main/java/com/fixcraft/basefwx/cli/CliOptions.java",
        "java/src/main/java/com/fixcraft/basefwx/cli/FileCommands.java",
        "java/src/main/java/com/fixcraft/basefwx/cli/MediaCommands.java",
        "java/src/main/java/com/fixcraft/basefwx/FwxAESBenchmark.java",
    }:
        return BASEFWX_GPL_NEW
    if rel in {
        "cpp/CMakeLists.txt",
        "python/basefwx/main.py",
        "python/pyproject.toml",
        "python/setup.py",
    }:
        return BASEFWX_MIXED_NEW
    if rel.startswith("tools/"):
        return BASEFWX_GPL_NEW
    if rel.startswith("scripts/") or rel.startswith("python/scripts/"):
        return BASEFWX_GPL_NEW
    if rel.startswith("python/tools/") or rel.startswith("python/tests/"):
        return BASEFWX_GPL_NEW
    if rel.startswith(".github/scripts/"):
        return BASEFWX_GPL_NEW

    if rel.startswith("cpp/"):
        return BASEFWX_LGPL_NEW
    if rel.startswith("java/src/main/java/com/fixcraft/basefwx/"):
        return BASEFWX_LGPL_NEW
    if rel.startswith("python/basefwx/"):
        return BASEFWX_LGPL_NEW

    return None


def header_lines_for(replacement: str) -> list[str] | None:
    if replacement == BASEFWX_EXAMPLE_NEW:
        return None
    lines = [
        "BaseFWX - Cryptography Engine",
        "Copyright (C) 2020-2026  FixCraft Inc.",
        replacement,
    ]
    return lines


def has_license_marker(text: str, replacement: str) -> bool:
    head = text[:1200]
    if replacement in head:
        return True
    if replacement == BASEFWX_LGPL_NEW:
        return "GNU Lesser General Public License v3.0 or later" in head
    if replacement == BASEFWX_GPL_NEW:
        return "GNU General Public License v3.0 or later" in head and "Lesser" not in head
    if replacement == BASEFWX_EXAMPLE_NEW:
        return BASEFWX_EXAMPLE_NEW in head
    if replacement == BASEFWX_MIXED_NEW:
        return BASEFWX_MIXED_NEW in head
    return False


def format_header(path: Path, lines: list[str]) -> str:
    prefix = "# "
    return "".join(f"{prefix}{line}\n" for line in lines)


def prepend_header(text: str, path: Path, header_lines: list[str]) -> tuple[str, int]:
    block = format_header(path, header_lines)
    if text.startswith("#!"):
        first_newline = text.find("\n")
        if first_newline == -1:
            return block + text, 1
        return text[: first_newline + 1] + block + text[first_newline + 1 :], 1
    return block + text, 1


def update_example_plugin_header(text: str, path: Path) -> tuple[str, int]:
    if "BaseFWX example" not in text[:512]:
        return text, 0
    if BASEFWX_EXAMPLE_NEW in text[:512]:
        return text, 0

    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines[:24]):
        if "Licensed under the GNU General Public License v3.0" not in line:
            continue
        prefix = line.split("Licensed under", 1)[0]
        j = i + 1
        while j < len(lines) and (
            "BaseFWX Plugin-Template Exception" in lines[j]
            or "You may use this file" in lines[j]
            or "Plugin under any license" in lines[j]
        ):
            j += 1
        note = (
            f"{prefix}This file is intentionally permissive so plugin authors "
            "can use it as a starting template.\n"
        )
        updated_lines = lines[:i] + [f"{prefix}{BASEFWX_EXAMPLE_NEW}\n", note] + lines[j:]
        updated = "".join(updated_lines)
        return (updated, 1) if updated != text else (text, 0)

    return text, 0


def process_file(path: Path, replacement: str, apply: bool) -> int:
    text = path.read_text(encoding="utf-8")
    updated = text
    count = 0

    if replacement == BASEFWX_EXAMPLE_NEW:
        updated, count = update_example_plugin_header(text, path)
    elif not has_license_marker(text, replacement):
        header_lines = header_lines_for(replacement)
        if header_lines is not None:
            updated, count = prepend_header(text, path, header_lines)

    if count and apply:
        path.write_text(updated, encoding="utf-8")
    return count


def source_files_under(base: Path):
    for path in base.rglob("*"):
        if not path.is_file() or is_skipped(path):
            continue
        if path.suffix in TEXT_EXTENSIONS or path.name == "CMakeLists.txt":
            yield path


def run(apply: bool) -> tuple[int, int]:
    files = 0
    edits = 0
    for path in source_files_under(ROOT):
        replacement = license_for(path)
        if replacement is None:
            continue
        if path.name == "prepare_license_update.py":
            continue
        count = process_file(path, replacement, apply)
        if count:
            files += 1
            edits += count
            rel = path.relative_to(ROOT)
            if replacement == BASEFWX_LGPL_NEW:
                tag = "LGPL-3.0-or-later"
            elif replacement == BASEFWX_MIXED_NEW:
                tag = "LGPL-3.0-or-later AND GPL-3.0-or-later"
            elif replacement == BASEFWX_EXAMPLE_NEW:
                tag = "MIT OR Apache-2.0"
            else:
                tag = "GPL-3.0-or-later"
            print(f"{rel} -> {tag}")
    return files, edits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write changes; default is dry-run only",
    )
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{mode}: BaseFWX license header update")
    files, edits = run(args.apply)
    print(f"{mode}: {edits} header line(s) in {files} file(s)")
    if not args.apply:
        print("No files changed. Re-run with --apply to write updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
