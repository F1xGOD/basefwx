#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.
#
# Resource guards for bench / test runners.
#
# Applied by default to keep heavy operations from monopolising the
# host's CPU and RAM. Users can opt out with --no-guards on the
# parent script, or by setting BASEFWX_NO_GUARDS=1 in the env.
#
# Default policy:
#
#   CPU: leave one logical core free. If `taskset` is available and
#        the runner has >= 2 logical cores, the parent shell (and any
#        child it execs) is pinned to a CPU-affinity mask that
#        excludes the last core. OMP/MKL/OpenBLAS thread caps are
#        also lowered to `nproc - 1`.
#
#   RAM: cap the process group's *virtual* memory via `ulimit -v` so
#        the shell can't accidentally grow past a safe ceiling.
#        Default ceiling is 75 % of total system RAM, computed from
#        /proc/meminfo (Linux). Users can override with
#        BASEFWX_MEM_CAP_PCT=<int 10..95>.
#
# What this does NOT do (intentional non-goals):
#
#   - Replace cgroups / systemd-run for hard isolation. ulimit is
#     advisory-ish; a single misbehaving C++ child can still allocate
#     past it on `mmap`-heavy paths, but the shell-side process tree
#     respects it. For hard caps, run inside a systemd-run --user
#     --property=MemoryMax= wrapper at the call site.
#   - Throttle disk / network I/O. Those don't OOM the box.
#
# Usage from a caller:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/resource_guards.sh"
#   bench_guards_parse_args "$@"   # consumes --no-guards / --max-cpu-cores N / --mem-cap-pct N
#   bench_guards_apply             # actually installs them
#
# The functions are idempotent and safe to call from sub-shells.

# Already sourced once? Don't redefine.
if [[ "${__BASEFWX_RESOURCE_GUARDS_LOADED:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi
__BASEFWX_RESOURCE_GUARDS_LOADED=1

BASEFWX_GUARDS_ENABLED=1
BASEFWX_GUARDS_CPU_LEAVE_FREE="${BASEFWX_GUARDS_CPU_LEAVE_FREE:-1}"
BASEFWX_GUARDS_MEM_CAP_PCT="${BASEFWX_MEM_CAP_PCT:-${BASEFWX_GUARDS_MEM_CAP_PCT:-75}}"
BASEFWX_GUARDS_MAX_CPU_CORES="${BASEFWX_GUARDS_MAX_CPU_CORES:-}"

if [[ "${BASEFWX_NO_GUARDS:-0}" == "1" ]]; then
    BASEFWX_GUARDS_ENABLED=0
fi

# ---------------------------------------------------------------------
# Arg parsing — strips guard-related flags out of the parent's $@ via
# the global BASEFWX_GUARDS_REMAINING_ARGS array. Callers should re-set
# their own positional args from it after the call.
# ---------------------------------------------------------------------

declare -a BASEFWX_GUARDS_REMAINING_ARGS

bench_guards_parse_args() {
    BASEFWX_GUARDS_REMAINING_ARGS=()
    local i=0
    local args=("$@")
    local n=${#args[@]}
    while (( i < n )); do
        local a="${args[i]}"
        case "$a" in
            --no-guards|--no-resource-guards)
                BASEFWX_GUARDS_ENABLED=0
                ;;
            --max-cpu-cores)
                (( i + 1 < n )) || { echo "--max-cpu-cores needs a value" >&2; return 2; }
                BASEFWX_GUARDS_MAX_CPU_CORES="${args[i+1]}"
                i=$((i+1))
                ;;
            --max-cpu-cores=*)
                BASEFWX_GUARDS_MAX_CPU_CORES="${a#*=}"
                ;;
            --mem-cap-pct)
                (( i + 1 < n )) || { echo "--mem-cap-pct needs a value" >&2; return 2; }
                BASEFWX_GUARDS_MEM_CAP_PCT="${args[i+1]}"
                i=$((i+1))
                ;;
            --mem-cap-pct=*)
                BASEFWX_GUARDS_MEM_CAP_PCT="${a#*=}"
                ;;
            *)
                BASEFWX_GUARDS_REMAINING_ARGS+=("$a")
                ;;
        esac
        i=$((i+1))
    done
}

# ---------------------------------------------------------------------
# Compute caps.
# ---------------------------------------------------------------------

bench_guards_total_logical_cores() {
    # Cross-platform-ish: prefer nproc, fall back to sysconf.
    local n
    if command -v nproc >/dev/null 2>&1; then
        n=$(nproc 2>/dev/null || echo 1)
    elif [[ -r /proc/cpuinfo ]]; then
        n=$(grep -c '^processor' /proc/cpuinfo)
    else
        n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    fi
    [[ -z "$n" || "$n" -lt 1 ]] && n=1
    printf '%s' "$n"
}

bench_guards_target_cpu_cores() {
    local total
    total=$(bench_guards_total_logical_cores)
    local target
    if [[ -n "$BASEFWX_GUARDS_MAX_CPU_CORES" ]]; then
        target="$BASEFWX_GUARDS_MAX_CPU_CORES"
    else
        target=$(( total - BASEFWX_GUARDS_CPU_LEAVE_FREE ))
    fi
    (( target < 1 )) && target=1
    (( target > total )) && target=$total
    printf '%s' "$target"
}

bench_guards_total_mem_kib() {
    local mem_kib
    if [[ -r /proc/meminfo ]]; then
        mem_kib=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
    elif command -v sysctl >/dev/null 2>&1; then
        local b
        b=$(sysctl -n hw.memsize 2>/dev/null)
        if [[ -n "$b" ]]; then
            mem_kib=$(( b / 1024 ))
        fi
    fi
    [[ -z "$mem_kib" || "$mem_kib" -lt 1 ]] && mem_kib=$((4 * 1024 * 1024))  # fallback 4 GiB
    printf '%s' "$mem_kib"
}

bench_guards_target_mem_kib() {
    local total
    total=$(bench_guards_total_mem_kib)
    local pct=$BASEFWX_GUARDS_MEM_CAP_PCT
    if ! [[ "$pct" =~ ^[0-9]+$ ]] || (( pct < 10 || pct > 95 )); then
        pct=75
    fi
    printf '%s' $(( total * pct / 100 ))
}

# ---------------------------------------------------------------------
# Apply.
# ---------------------------------------------------------------------

bench_guards_apply() {
    if [[ "$BASEFWX_GUARDS_ENABLED" != "1" ]]; then
        echo "[resource-guards] DISABLED (via --no-guards or BASEFWX_NO_GUARDS=1)." >&2
        return 0
    fi

    local total_cores target_cores total_mem_kib target_mem_kib target_mem_gib
    total_cores=$(bench_guards_total_logical_cores)
    target_cores=$(bench_guards_target_cpu_cores)
    total_mem_kib=$(bench_guards_total_mem_kib)
    target_mem_kib=$(bench_guards_target_mem_kib)
    target_mem_gib=$(awk -v k="$target_mem_kib" 'BEGIN { printf "%.1f", k / 1048576.0 }')

    # CPU caps — thread pools.
    export OMP_NUM_THREADS="$target_cores"
    export OPENBLAS_NUM_THREADS="$target_cores"
    export MKL_NUM_THREADS="$target_cores"
    export NUMEXPR_NUM_THREADS="$target_cores"
    export BASEFWX_MAX_THREADS="$target_cores"

    # CPU affinity — pin to the first $target_cores cores if taskset
    # is available and we have more than one core.
    local taskset_msg="(taskset not used)"
    if (( target_cores < total_cores )) && command -v taskset >/dev/null 2>&1; then
        local mask_hi=$(( target_cores - 1 ))
        if taskset -c -p 0-$mask_hi $$ >/dev/null 2>&1; then
            taskset_msg="taskset 0-$mask_hi -> $$"
        else
            taskset_msg="(taskset failed; affinity unchanged)"
        fi
    fi

    # Virtual-memory cap. Some shells reject `ulimit -v` on systems
    # without per-process VM accounting; treat that as a soft warning.
    local ulimit_msg
    if ulimit -v "$target_mem_kib" 2>/dev/null; then
        ulimit_msg="ulimit -v ${target_mem_kib} KiB"
    else
        ulimit_msg="(ulimit -v not supported; cap not enforced)"
    fi

    cat >&2 <<EOF
[resource-guards] enabled
  CPU:   ${target_cores}/${total_cores} logical cores in use
         (OMP/OPENBLAS/MKL/NUMEXPR/BASEFWX_MAX_THREADS = ${target_cores})
         ${taskset_msg}
  RAM:   cap ~${target_mem_gib} GiB (${BASEFWX_GUARDS_MEM_CAP_PCT}% of $(awk -v k="$total_mem_kib" 'BEGIN { printf "%.1f", k / 1048576.0 }') GiB total)
         ${ulimit_msg}
  Override: pass --no-guards or set BASEFWX_NO_GUARDS=1 to disable.
EOF
}
