#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_BIN="${BASEFWX_JAVA8_BIN:-${JAVA_BIN:-$(command -v java || true)}}"
INPUT_BYTES="${BASEFWX_BENCH_LIVE_REGRESSION_BYTES:-100663296}"
WORKERS="${BASEFWX_BENCH_LIVE_REGRESSION_WORKERS:-2}"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

if [[ -z "$JAVA_BIN" || ! -x "$JAVA_BIN" ]]; then
    printf 'Java runtime not found; set BASEFWX_JAVA8_BIN\n' >&2
    exit 1
fi
if [[ ! "$INPUT_BYTES" =~ ^[0-9]+$ || "$INPUT_BYTES" -lt 67108864 ]]; then
    printf 'BASEFWX_BENCH_LIVE_REGRESSION_BYTES must be at least 67108864\n' >&2
    exit 1
fi
if [[ ! "$WORKERS" =~ ^[0-9]+$ || "$WORKERS" -lt 2 ]]; then
    printf 'BASEFWX_BENCH_LIVE_REGRESSION_WORKERS must be at least 2\n' >&2
    exit 1
fi

JAR="${BASEFWX_JAVA_JAR:-$ROOT/java/build/libs/basefwx-java.jar}"
if [[ ! -f "$JAR" ]]; then
    printf 'Missing %s; build the Java jar first\n' "$JAR" >&2
    exit 1
fi

INPUT="$TMP_DIR/input.bin"
JAVA_TMP="$TMP_DIR/java-tmp"
OUTPUT="$TMP_DIR/output.log"
mkdir -m 700 "$JAVA_TMP"
truncate -s "$INPUT_BYTES" "$INPUT"

if ! env \
        BASEFWX_BENCH_PARALLEL=1 \
        BASEFWX_BENCH_WORKERS="$WORKERS" \
        BASEFWX_BENCH_WARMUP=0 \
        BASEFWX_BENCH_ITERS=1 \
        BASEFWX_TEST_KDF_ITERS=10000 \
        "$JAVA_BIN" \
        -Xms64m \
        -Xmx512m \
        -Dbasefwx.testing=true \
        -Djava.io.tmpdir="$JAVA_TMP" \
        -jar "$JAR" \
        bench-live "$INPUT" "correct-password" --no-master \
        >"$OUTPUT" 2>&1; then
    printf 'bounded Java live benchmark failed:\n' >&2
    sed -n '1,200p' "$OUTPUT" >&2
    exit 1
fi

if ! grep -Eq '^BENCH_NS=[0-9]+$' "$OUTPUT"; then
    printf 'bounded Java live benchmark did not report BENCH_NS:\n' >&2
    sed -n '1,200p' "$OUTPUT" >&2
    exit 1
fi
EXPECTED_VERIFIED_BYTES=$((INPUT_BYTES * WORKERS))
if ! grep -qx "BENCH_VERIFIED_BYTES=$EXPECTED_VERIFIED_BYTES" "$OUTPUT"; then
    printf 'bounded Java live benchmark did not verify the exact payload:\n' >&2
    sed -n '1,200p' "$OUTPUT" >&2
    exit 1
fi
if grep -q 'OutOfMemoryError' "$OUTPUT"; then
    printf 'bounded Java live benchmark exhausted its constrained heap\n' >&2
    exit 1
fi
if find "$JAVA_TMP" -mindepth 1 -print -quit | grep -q .; then
    printf 'bounded Java live benchmark leaked temporary files:\n' >&2
    find "$JAVA_TMP" -mindepth 1 -print >&2
    exit 1
fi

printf 'PASS: bounded Java live benchmark (%s bytes, %s workers, -Xmx512m)\n' \
    "$INPUT_BYTES" "$WORKERS"
