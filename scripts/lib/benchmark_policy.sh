#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

if [[ "${__BASEFWX_BENCHMARK_POLICY_LOADED:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
__BASEFWX_BENCHMARK_POLICY_LOADED=1

basefwx_benchmark_value_is_true() {
    local value="${1:-}"
    case "${value,,}" in
        1|true|yes|on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

basefwx_benchmark_configure_methods() {
    BASEFWX_BENCH_RETIRED_ENABLED=0
    BASEFWX_BENCH_TEXT_METHODS=("b512" "pb512" "b64" "a512" "n10")

    if basefwx_benchmark_value_is_true "${BASEFWX_BENCH_RETIRED:-0}"; then
        BASEFWX_BENCH_RETIRED_ENABLED=1
        BASEFWX_BENCH_TEXT_METHODS=("b256" "${BASEFWX_BENCH_TEXT_METHODS[@]}")
    fi
}
