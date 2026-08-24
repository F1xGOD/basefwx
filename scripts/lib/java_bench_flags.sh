#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

if [[ "${__BASEFWX_JAVA_BENCH_FLAGS_LOADED:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
__BASEFWX_JAVA_BENCH_FLAGS_LOADED=1

declare -a BASEFWX_JAVA_BENCH_FLAGS

basefwx_java_vm_accepts_flags() {
    local java_bin="$1"
    shift
    "$java_bin" "$@" -version >/dev/null 2>&1
}

basefwx_java_try_bench_flag() {
    local java_bin="$1"
    local flag="$2"
    if basefwx_java_vm_accepts_flags \
            "$java_bin" "${BASEFWX_JAVA_BENCH_FLAGS[@]}" "$flag"; then
        BASEFWX_JAVA_BENCH_FLAGS+=("$flag")
        return 0
    fi
    printf 'Java bench: JVM does not support %s; skipping default tuning flag\n' \
        "$flag" >&2
    return 1
}

basefwx_java_select_default_bench_flags() {
    local java_bin="$1"
    BASEFWX_JAVA_BENCH_FLAGS=()

    local flag
    for flag in \
        -server \
        -XX:+UseG1GC \
        -XX:+TieredCompilation \
        -XX:CompileThreshold=1000 \
        -XX:+UseStringDeduplication \
        -XX:MaxGCPauseMillis=200; do
        basefwx_java_try_bench_flag "$java_bin" "$flag" || true
    done

    # resource_guards.sh publishes its virtual-memory ceiling here. Heap
    # percentages are based on host/container RAM rather than RLIMIT_AS, so a
    # 75% heap paired with a 75% address-space cap leaves no room for thread
    # stacks, code cache, JNI libraries, or the JVM itself. Keep at least half
    # of the guarded address space available to those native allocations and
    # cap the default heap at 4 GiB for these small benchmark fixtures.
    local memory_limit="${BASEFWX_BENCH_MEMORY_LIMIT_BYTES:-}"
    local memory_limit_decimal=0
    local heap_mib=0
    if [[ "$memory_limit" =~ ^[0-9]+$ ]] \
            && (( ${#memory_limit} <= 18 )); then
        memory_limit_decimal=$((10#$memory_limit))
    fi
    if (( memory_limit_decimal >= 256 * 1024 * 1024 )); then
        heap_mib=$(( memory_limit_decimal / 1024 / 1024 / 2 ))
        (( heap_mib > 4096 )) && heap_mib=4096
    fi

    if (( heap_mib >= 128 )); then
        local initial_mib=$(( heap_mib / 4 ))
        (( initial_mib < 64 )) && initial_mib=64
        (( initial_mib > 512 )) && initial_mib=512
        if basefwx_java_vm_accepts_flags \
                "$java_bin" \
                "${BASEFWX_JAVA_BENCH_FLAGS[@]}" \
                "-Xms${initial_mib}m" \
                "-Xmx${heap_mib}m"; then
            BASEFWX_JAVA_BENCH_FLAGS+=(
                "-Xms${initial_mib}m"
                "-Xmx${heap_mib}m"
            )
        else
            printf '%s\n' \
                'Java bench: JVM rejected resource-guard heap limits; using RAM-percentage fallback' \
                >&2
            heap_mib=0
        fi
    fi

    if (( heap_mib == 0 )) && basefwx_java_vm_accepts_flags \
            "$java_bin" \
            "${BASEFWX_JAVA_BENCH_FLAGS[@]}" \
            -XX:InitialRAMPercentage=20 \
            -XX:MaxRAMPercentage=75; then
        BASEFWX_JAVA_BENCH_FLAGS+=(
            -XX:InitialRAMPercentage=20
            -XX:MaxRAMPercentage=75
        )
    elif (( heap_mib == 0 )); then
        printf '%s\n' \
            'Java bench: JVM lacks RAM-percentage flags; probing Java 8 RAM-fraction fallback' \
            >&2
        basefwx_java_try_bench_flag \
            "$java_bin" -XX:InitialRAMFraction=5 || true
        basefwx_java_try_bench_flag \
            "$java_bin" -XX:MaxRAMFraction=2 || true
    fi

    for flag in \
        -XX:+UseAES \
        -XX:+UnlockDiagnosticVMOptions \
        -XX:+UseAESIntrinsics \
        -XX:+UseAESCTRIntrinsics \
        -XX:+UseGHASHIntrinsics; do
        basefwx_java_try_bench_flag "$java_bin" "$flag" || true
    done

    if ! basefwx_java_vm_accepts_flags \
            "$java_bin" "${BASEFWX_JAVA_BENCH_FLAGS[@]}"; then
        printf '%s\n' \
            'Java bench: selected default JVM flag set failed final validation' \
            >&2
        return 1
    fi
}
