#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/benchmark_policy.sh
source "$ROOT/scripts/lib/benchmark_policy.sh"

expect_default_methods() {
    [[ "${BASEFWX_BENCH_TEXT_METHODS[*]}" == "b512 pb512 b64 n10" ]]
}

unset BASEFWX_BENCH_RETIRED
unset BASEFWX_ENABLE_RETIRED_MEDIA
basefwx_benchmark_configure_methods
expect_default_methods

for value in 0 false no off unexpected; do
    BASEFWX_BENCH_RETIRED="$value"
    basefwx_benchmark_configure_methods
    expect_default_methods
done

for value in 1 true yes on TRUE; do
    BASEFWX_BENCH_RETIRED="$value"
    unset BASEFWX_ENABLE_RETIRED_MEDIA
    basefwx_benchmark_configure_methods
    expect_default_methods

    BASEFWX_ENABLE_RETIRED_MEDIA=1
    basefwx_benchmark_configure_methods
    expect_default_methods
done

printf 'PASS: retired compatibility stays excluded from benchmarks\n'
