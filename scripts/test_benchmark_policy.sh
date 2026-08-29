#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/benchmark_policy.sh
source "$ROOT/scripts/lib/benchmark_policy.sh"

expect_default_methods() {
    [[ "$BASEFWX_BENCH_RETIRED_ENABLED" == "0" ]]
    [[ "${BASEFWX_BENCH_TEXT_METHODS[*]}" == "b512 pb512 b64 a512 n10" ]]
}

unset BASEFWX_BENCH_RETIRED
basefwx_benchmark_configure_methods
expect_default_methods

for value in 0 false no off unexpected; do
    BASEFWX_BENCH_RETIRED="$value"
    basefwx_benchmark_configure_methods
    expect_default_methods
done

for value in 1 true yes on TRUE; do
    BASEFWX_BENCH_RETIRED="$value"
    basefwx_benchmark_configure_methods
    [[ "$BASEFWX_BENCH_RETIRED_ENABLED" == "1" ]]
    [[ "${BASEFWX_BENCH_TEXT_METHODS[*]}" == "b256 b512 pb512 b64 a512 n10" ]]
done

printf 'PASS: retired benchmarks are opt-in\n'
