#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cmake \
    -S "$ROOT/testdata/cmake_consumer" \
    -B "$TMP_DIR/build" \
    -DBASEFWX_SOURCE_DIR="$ROOT/cpp" \
    -DBASEFWX_BUILD_CLI=OFF \
    -DBASEFWX_REQUIRE_ARGON2=OFF \
    -DBASEFWX_REQUIRE_OQS=OFF \
    -DBASEFWX_USE_VENDOR_DEPS=OFF
cmake --build "$TMP_DIR/build" --target consumer_smoke

printf 'PASS: add_subdirectory consumer excludes BaseFWX internal tests\n'
