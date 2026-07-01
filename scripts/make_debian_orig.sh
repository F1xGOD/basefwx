#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '[:space:]' < "${repo_root}/VERSION")"

if [[ -z "${version}" ]]; then
  echo "failed to read BaseFWX version from VERSION" >&2
  exit 1
fi

out="${repo_root}/../basefwx_${version}.orig.tar.xz"
prefix="basefwx-${version}"

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git -C "${repo_root}" log -1 --format=%ct)"
  else
    SOURCE_DATE_EPOCH="$(date +%s)"
  fi
fi

cd "${repo_root}"

find . -mindepth 1 \
  \( -path './.git' \
     -o -path './.gradle' \
     -o -path './.venv' \
     -o -path './.tmp_basefwx_tests' \
     -o -path './build' \
     -o -path './build-*' \
     -o -path './debian' \
     -o -path './obj-*' \
     -o -path './vendor' \) -prune \
  -o \( -name '*.pyc' \
        -o -name '.DS_Store' \
        -o -name 'diagnose.log' \) -prune \
  -o -print0 \
  | LC_ALL=C sort -z \
  | tar --null --no-recursion --files-from - \
        --transform "s#^\\./#${prefix}/#" \
        --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        -cJf "${out}"

echo "${out}"
