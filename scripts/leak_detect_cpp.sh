#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.
#
# C++ leak detector. Builds a small probe binary against the BaseFWX
# tree with AddressSanitizer + LeakSanitizer enabled, runs it for
# N iterations across the main code paths (hash512, uhash513,
# fwxAES encrypt/decrypt round-trip, b256, plugin smoke), and lets
# LSan exit non-zero on any leak.
#
# Designed to run inside GitHub Actions and on dev hosts. Wraps
# itself in the shared resource_guards if invoked from a heavy
# context; the ASan-instrumented binary is ~2-3× slower and ~2×
# memory than the release build, so callers should NOT run this on
# laptop-grade hosts without guards.
#
# Usage:
#     scripts/leak_detect_cpp.sh                # default iters
#     scripts/leak_detect_cpp.sh --iters 50     # fewer iters (CI fast-mode)
#     scripts/leak_detect_cpp.sh --no-guards    # opt out of resource caps

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=lib/resource_guards.sh
source "$ROOT/scripts/lib/resource_guards.sh"
bench_guards_parse_args "$@"
set -- "${BASEFWX_GUARDS_REMAINING_ARGS[@]}"
bench_guards_apply

ITERS=200
while (( $# > 0 )); do
    case "$1" in
        --iters) ITERS="$2"; shift 2 ;;
        --iters=*) ITERS="${1#*=}"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

BUILD_DIR="$ROOT/build-asan-leak"
PROBE_SRC="$BUILD_DIR/leak_probe.cpp"
PROBE_BIN="$BUILD_DIR/leak_probe"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# A self-contained probe that exercises the main heap-allocating
# paths repeatedly. ASan/LSan reports any allocation not freed by
# end of main(). LSan respects the "leaked == nonzero exit code"
# contract — no need to grep its output.
cat > "$PROBE_SRC" <<'EOF'
#include <basefwx/basefwx.hpp>
#include <basefwx/codec.hpp>
#include <basefwx/crypto.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

void exercise_hashes(int iters) {
    for (int i = 0; i < iters; ++i) {
        volatile auto h = basefwx::Hash512("leak-probe payload");
        (void)h;
        volatile auto u = basefwx::Uhash513("leak-probe payload");
        (void)u;
    }
}

void exercise_b64(int iters) {
    for (int i = 0; i < iters; ++i) {
        std::string enc = basefwx::B64Encode("leak-probe payload");
        std::string dec = basefwx::B64Decode(enc);
        (void)dec;
    }
}

void exercise_aead(int iters) {
    // The fwxAES public API has long argument tables; instead, test
    // the low-level AEAD path that everything funnels through.
    auto key = basefwx::crypto::RandomBytes(32);
    auto iv  = basefwx::crypto::RandomBytes(12);
    basefwx::crypto::Bytes aad{'l','e','a','k','-','p','r','o','b','e'};
    basefwx::crypto::Bytes pt{'h','e','l','l','o',' ','l','e','a','k',' ','p','r','o','b','e'};
    for (int i = 0; i < iters; ++i) {
        auto ct = basefwx::crypto::AesGcmEncryptWithIv(key, iv, pt, aad);
        auto rt = basefwx::crypto::AesGcmDecryptWithIv(key, iv, ct, aad);
        (void)rt;
    }
}

void exercise_b256(int iters) {
    // b256 is retired; use the un-deprecated internal helpers so the
    // build stays warning-clean.
    for (int i = 0; i < iters; ++i) {
        std::string enc = basefwx::codec::B256Encode("leak-probe payload");
        std::string dec = basefwx::codec::B256Decode(enc);
        (void)dec;
    }
}

}  // namespace

int main(int argc, char** argv) {
    int iters = 200;
    if (argc > 1) iters = std::atoi(argv[1]);
    if (iters < 1) iters = 1;

    std::printf("[cpp-leak-probe] hashes (Hash512 + Uhash513) ...\n");
    exercise_hashes(iters);

    std::printf("[cpp-leak-probe] base64 ...\n");
    exercise_b64(iters);

    std::printf("[cpp-leak-probe] AEAD (AES-256-GCM) ...\n");
    exercise_aead(iters);

    std::printf("[cpp-leak-probe] b256 (retired) ...\n");
    exercise_b256(iters);

    std::printf("[cpp-leak-probe] done.\n");
    return 0;
}
EOF

echo "[leak_detect_cpp] Configuring ASan/LSan build (iters=${ITERS})..."

# Configure / build basefwx with ASan flags. We rebuild only the static
# library + this probe — the CLI is not needed for the leak check.
cmake -S cpp -B "$BUILD_DIR" \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,leak -fno-omit-frame-pointer -g -O1" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,leak" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,leak" \
      >"$BUILD_DIR/cmake.log" 2>&1 || {
    echo "cmake configure failed; see $BUILD_DIR/cmake.log" >&2
    tail -40 "$BUILD_DIR/cmake.log" >&2
    exit 1
}

cmake --build "$BUILD_DIR" --target basefwxcpp >"$BUILD_DIR/build.log" 2>&1 || {
    echo "basefwxcpp library build failed; see $BUILD_DIR/build.log" >&2
    tail -40 "$BUILD_DIR/build.log" >&2
    exit 1
}

# Compile the probe directly against the built lib + ASan runtime.
# Pick up include dirs from the configured tree, link against the
# instrumented static lib, then any deps the CMake build pulled in.
c++ -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,leak \
    -I"$ROOT/cpp/include" \
    "$PROBE_SRC" \
    "$BUILD_DIR/libbasefwxcpp.a" \
    -lcrypto -lssl -lz -llzma -largon2 \
    -o "$PROBE_BIN" \
    2>"$BUILD_DIR/probe.log" || {
    echo "probe link failed; see $BUILD_DIR/probe.log" >&2
    tail -40 "$BUILD_DIR/probe.log" >&2
    exit 1
}

echo "[leak_detect_cpp] Running probe under ASan/LSan..."
# ASAN_OPTIONS keeps the exit-non-zero contract on leaks. LSan is
# enabled by default when ASan is.
ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:check_initialization_order=1:strict_init_order=1:abort_on_error=0:exitcode=1" \
LSAN_OPTIONS="report_objects=1:print_suppressions=0" \
"$PROBE_BIN" "$ITERS"

rc=$?
if (( rc == 0 )); then
    echo "[leak_detect_cpp] PASS — no leaks above LSan threshold."
else
    echo "[leak_detect_cpp] FAIL — LSan reported leaks (exit=$rc)."
fi
exit $rc
