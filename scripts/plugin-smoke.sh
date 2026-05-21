#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.
#
# Plugin smoke runner — exercises the 3.7.0 blackbox plugin contract
# end-to-end across C++, Python, and Java. Compiles the example
# plugins from scratch, dlopens / ServiceLoaders them, runs each
# plugin's selftest, performs a real round-trip with a custom
# payload, and verifies that the SAME .so loaded from C++ and Python
# produces byte-identical output (cross-runtime parity).
#
# Designed to be:
#  - Fast: total runtime ~30s on a modest box, no Argon2.
#  - Additive: does NOT duplicate existing crypto tests; runs once
#    at the end of test_all.sh OR standalone.
#  - Clean exit codes: 0 = all PASS, non-zero = first failure.
#
# Usage:
#   scripts/plugin-smoke.sh                    # plain run
#   scripts/plugin-smoke.sh --quiet            # only print failures
#   scripts/plugin-smoke.sh --keep-builds      # don't rm -rf the
#                                              # examples/plugins/*/build dirs
#
# Plugins are intended for ENCRYPTION pipelines (fwxAES, b512file,
# pb512file, livecipher, etc.) where the AEAD wraps the plaintext and
# the plugin transforms either the pre-AEAD plaintext or the
# post-AEAD ciphertext. Hash methods (hash512, uhash513, bi512) are
# one-way and have no AEAD step; the plugin contract doesn't apply
# to them. The smoke here therefore tests the plugin API surface
# itself, not its (deferred) integration into specific crypto methods.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUIET=0
KEEP_BUILDS=0
for arg in "$@"; do
    case "$arg" in
        --quiet) QUIET=1 ;;
        --keep-builds) KEEP_BUILDS=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# ----- pretty I/O (degrade if not a TTY) ---------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; CYAN=$'\033[1;36m'
    YELLOW=$'\033[1;33m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; CYAN=""; YELLOW=""; DIM=""; RESET=""
fi

PASS=0
FAIL=0
SKIP=0
declare -a FAILURES

step() {
    local label="$1"
    if [[ $QUIET -eq 0 ]]; then
        printf "%s▶%s %s ... " "$CYAN" "$RESET" "$label"
    fi
}

ok() {
    local elapsed="$1"
    PASS=$((PASS + 1))
    if [[ $QUIET -eq 0 ]]; then
        printf "%s✓%s %s%dms%s\n" "$GREEN" "$RESET" "$DIM" "$elapsed" "$RESET"
    fi
}

fail() {
    local elapsed="$1" reason="$2"
    FAIL=$((FAIL + 1))
    FAILURES+=("$reason")
    printf "%s✗%s %s%dms%s — %s\n" "$RED" "$RESET" "$DIM" "$elapsed" "$RESET" "$reason"
}

skip() {
    local reason="$1"
    SKIP=$((SKIP + 1))
    if [[ $QUIET -eq 0 ]]; then
        printf "%s—%s skipped (%s)\n" "$YELLOW" "$RESET" "$reason"
    fi
}

now_ms() { date +%s%3N; }
elapsed_ms() { echo $(( $(now_ms) - $1 )); }

run_step() {
    local label="$1" cmd_fn="$2"
    step "$label"
    local t=$(now_ms)
    local rc=0
    local err
    err=$("$cmd_fn" 2>&1); rc=$?
    local ms=$(elapsed_ms $t)
    if [[ $rc -eq 0 ]]; then
        ok "$ms"
    else
        fail "$ms" "$label: $err"
    fi
    return $rc
}

# =====================================================================
# helper invocations (each returns 0/non-0 + writes diagnostics to stdout)
# =====================================================================

CPP_PROBE_BIN=""

prepare_cpp_probe() {
    # One-shot compile of a probe that takes <so-path> and round-trips
    # a payload through forward/inverse, asserts selftest, prints
    # forward()-hex on success.
    CPP_PROBE_BIN=$(mktemp /tmp/basefwx-plugin-probe.XXXXXX)
    cat > "$CPP_PROBE_BIN.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "basefwx/plugin.h"
int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <so>\n", argv[0]); return 2; }
    const char* needs_key = (argc >= 3 && strcmp(argv[2], "needs-key") == 0) ? "1" : "0";
    void* h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }
    typedef const basefwx_plugin_vtable* (*fn)(void);
    fn entry = (fn)dlsym(h, "basefwx_plugin_entry");
    if (!entry) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 4; }
    const basefwx_plugin_vtable* v = entry();
    if (v->api_version != BASEFWX_PLUGIN_API_VERSION) {
        fprintf(stderr, "API mismatch: plugin=%u host=%u\n",
                v->api_version, BASEFWX_PLUGIN_API_VERSION); return 5;
    }
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(0x42 ^ i);
    basefwx_plugin_ctx* ctx = NULL;
    int rc = v->init(&ctx, needs_key[0]=='1' ? key : NULL,
                     needs_key[0]=='1' ? 32 : 0);
    if (rc != 0) { fprintf(stderr, "init rc=%d\n", rc); return 6; }
    if (v->selftest && v->selftest(ctx) != 0) {
        fprintf(stderr, "selftest fail\n"); v->destroy(ctx); return 7;
    }
    const char* msg = "plugin-smoke probe round-trip 3.7.0";
    size_t in_len = strlen(msg);
    size_t cap = v->max_output_for_input(ctx, in_len);
    uint8_t* mid = (uint8_t*)malloc(cap);
    uint8_t* back = (uint8_t*)malloc(cap + 1);
    size_t mid_len = 0, back_len = 0;
    if (v->forward(ctx, (const uint8_t*)msg, in_len, mid, cap, &mid_len) != 0) {
        fprintf(stderr, "forward fail\n"); return 8;
    }
    if (v->inverse(ctx, mid, mid_len, back, cap + 1, &back_len) != 0) {
        fprintf(stderr, "inverse fail\n"); return 9;
    }
    if (back_len != in_len || memcmp(back, msg, in_len) != 0) {
        fprintf(stderr, "round-trip mismatch\n"); return 10;
    }
    /* Print the forward() hex so the parity check can compare. */
    for (size_t i = 0; i < mid_len; ++i) printf("%02x", mid[i]);
    printf("\n");
    free(mid); free(back);
    v->destroy(ctx);
    dlclose(h);
    return 0;
}
EOF
    gcc -std=c99 -Wall -Icpp/include "$CPP_PROBE_BIN.c" -o "$CPP_PROBE_BIN" -ldl 2>&1 \
        || { echo "probe compile failed"; return 1; }
    rm -f "$CPP_PROBE_BIN.c"
}

cleanup() {
    [[ -n "$CPP_PROBE_BIN" ]] && rm -f "$CPP_PROBE_BIN" "$CPP_PROBE_BIN.c"
    if [[ $KEEP_BUILDS -eq 0 ]]; then
        rm -rf examples/plugins/passthrough/build \
               examples/plugins/xor-rotate/build \
               examples/plugins/xor-rotate-java/build
    fi
}
trap cleanup EXIT

# --- step helpers ---------------------------------------------------

cpp_build_passthrough() {
    rm -rf examples/plugins/passthrough/build
    cmake -S examples/plugins/passthrough -B examples/plugins/passthrough/build >/dev/null 2>&1 \
        && cmake --build examples/plugins/passthrough/build >/dev/null 2>&1 \
        && [[ -f examples/plugins/passthrough/build/libbasefwx-passthrough.so ]]
}

cpp_build_xor() {
    rm -rf examples/plugins/xor-rotate/build
    cmake -S examples/plugins/xor-rotate -B examples/plugins/xor-rotate/build >/dev/null 2>&1 \
        && cmake --build examples/plugins/xor-rotate/build >/dev/null 2>&1 \
        && [[ -f examples/plugins/xor-rotate/build/libbasefwx-xor-rotate.so ]]
}

java_build_xor() {
    # Don't pass --offline: on a fresh CI runner the gradle cache hasn't
    # been populated yet, so --offline fails to resolve BouncyCastle.
    # Capture gradle's stderr to a tmp file so a real failure surfaces
    # its actual diagnostic in the smoke output instead of a silent rc=1.
    local err_file
    err_file=$(mktemp /tmp/basefwx-plugin-smoke-gradle.XXXXXX.log)
    trap "rm -f '$err_file'" RETURN

    if [[ ! -f java/build/libs/basefwx-java.jar ]]; then
        if ! (cd java && gradle --no-daemon -q jar) >"$err_file" 2>&1; then
            # Echo gradle's last ~10 lines so the run_step capture
            # contains the real error, not just "build failed".
            echo "basefwx-java.jar build failed; gradle tail:"
            tail -n 12 "$err_file" | sed 's/^/    /'
            return 1
        fi
    fi
    if ! (cd examples/plugins/xor-rotate-java && rm -rf build && gradle --no-daemon -q jar) >"$err_file" 2>&1; then
        echo "xor-rotate-java jar build failed; gradle tail:"
        tail -n 20 "$err_file" | sed 's/^/    /'
        return 1
    fi
    ls examples/plugins/xor-rotate-java/build/libs/basefwx-xor-rotate-java-*.jar >/dev/null 2>&1
}

cpp_load_passthrough() {
    "$CPP_PROBE_BIN" examples/plugins/passthrough/build/libbasefwx-passthrough.so >/dev/null
}

cpp_load_xor() {
    "$CPP_PROBE_BIN" examples/plugins/xor-rotate/build/libbasefwx-xor-rotate.so needs-key >/dev/null
}

py_load_xor_native() {
    python3 - <<'PYEOF' >/dev/null 2>&1
import sys, importlib.util, pathlib
root = pathlib.Path().resolve()
spec = importlib.util.spec_from_file_location("basefwx_plugin", root/"python/basefwx/plugin.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["basefwx_plugin"] = mod
spec.loader.exec_module(mod)
shim = mod.load_native_plugin(str(root/"examples/plugins/xor-rotate/build/libbasefwx-xor-rotate.so"))
key = bytes([0x42 ^ i for i in range(32)])
with shim.instantiate(key) as p:
    msg = b"py smoke round-trip 3.7.0"
    assert p.inverse(p.forward(msg)) == msg
    assert p.selftest()
PYEOF
}

py_pure_plugin() {
    python3 - <<'PYEOF' >/dev/null 2>&1
import sys, importlib.util, pathlib, types
root = pathlib.Path().resolve()
spec = importlib.util.spec_from_file_location("basefwx_plugin", root/"python/basefwx/plugin.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["basefwx_plugin"] = mod
spec.loader.exec_module(mod)
sys.modules["basefwx.plugin"] = mod
basefwx_stub = types.ModuleType("basefwx")
basefwx_stub.plugin = mod
sys.modules["basefwx"] = basefwx_stub
sys.path.insert(0, str(root/"examples/plugins/xor-rotate-py"))
from xor_rotate_py import XorRotatePy
key = bytes([0x42 ^ i for i in range(32)])
with XorRotatePy(key) as p:
    msg = b"pure-py smoke 3.7.0"
    assert p.inverse(p.forward(msg)) == msg
    assert p.selftest()
PYEOF
}

java_load_xor() {
    local spi=java/build/libs/basefwx-java.jar
    local plg
    plg=$(ls examples/plugins/xor-rotate-java/build/libs/basefwx-xor-rotate-java-*.jar 2>/dev/null | head -1)
    [[ -f "$spi" && -f "$plg" ]] || return 1
    # javac demands the filename match the public class; put the file
    # in a per-PID tmp dir but keep the basename clean.
    local probe_dir=/tmp/basefwx-plugin-probe.$$
    mkdir -p "$probe_dir"
    local probe="$probe_dir/BasefwxPluginProbe.java"
    cat > "$probe" <<'EOF'
import com.fixcraft.basefwx.plugin.*;
import java.util.Arrays;
public class BasefwxPluginProbe {
    public static void main(String[] args) throws Exception {
        BasefwxPluginRegistry.discover();
        byte[] id = {(byte)0x8d,(byte)0x4c,(byte)0x2a,(byte)0x01,
                     (byte)0x1f,(byte)0x70,(byte)0x4d,(byte)0x3a,
                     (byte)0x91,(byte)0xab,(byte)0x2c,(byte)0x5e,
                     (byte)0x8f,(byte)0x91,(byte)0x7b,(byte)0x04};
        BasefwxPluginFactory f = BasefwxPluginRegistry.factoryFor(id);
        if (f == null) { System.err.println("plugin missing"); System.exit(1); }
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)(0x42 ^ i);
        try (BasefwxPlugin p = f.create(key)) {
            byte[] msg = "java smoke 3.7.0".getBytes("UTF-8");
            byte[] mid = new byte[p.maxOutputForInput(msg.length)];
            byte[] back = new byte[msg.length];
            int n1 = p.forward(msg, 0, msg.length, mid, 0);
            int n2 = p.inverse(mid, 0, n1, back, 0);
            if (n2 != msg.length || !Arrays.equals(msg, back)) {
                System.err.println("round-trip fail"); System.exit(2);
            }
            if (!p.selftest()) { System.err.println("selftest fail"); System.exit(3); }
        }
    }
}
EOF
    local out="$probe_dir/classes"
    mkdir -p "$out"
    javac -cp "$spi" -d "$out" "$probe" >/dev/null 2>&1 \
        && java -cp "$out:$spi:$plg" BasefwxPluginProbe >/dev/null 2>&1
    local rc=$?
    rm -rf "$probe_dir"
    return $rc
}

cross_runtime_parity() {
    # Both runtimes load the SAME xor-rotate.so and forward() the same
    # payload. Their byte-level outputs must match.
    local so=examples/plugins/xor-rotate/build/libbasefwx-xor-rotate.so
    local cpp_hex
    cpp_hex=$("$CPP_PROBE_BIN" "$so" needs-key | tr -d '[:space:]') || return 1
    local py_hex
    py_hex=$(python3 - <<'PYEOF'
import sys, importlib.util, pathlib
root = pathlib.Path().resolve()
spec = importlib.util.spec_from_file_location("basefwx_plugin", root/"python/basefwx/plugin.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["basefwx_plugin"] = mod
spec.loader.exec_module(mod)
shim = mod.load_native_plugin(str(root/"examples/plugins/xor-rotate/build/libbasefwx-xor-rotate.so"))
key = bytes([0x42 ^ i for i in range(32)])
with shim.instantiate(key) as p:
    # Same payload as the C++ probe — must produce identical output
    out = p.forward(b"plugin-smoke probe round-trip 3.7.0")
    print(out.hex())
PYEOF
)
    [[ "$cpp_hex" == "$py_hex" ]] || { echo "C++=${cpp_hex:0:32}... Py=${py_hex:0:32}..."; return 2; }
}

# =====================================================================
# Run order — each step takes a few hundred milliseconds.
# =====================================================================

start_total=$(now_ms)

if [[ $QUIET -eq 0 ]]; then
    printf "%s┌─ BaseFWX plugin smoke ─┐%s\n" "$CYAN" "$RESET"
fi

# Probe compile
if ! prepare_cpp_probe; then
    printf "%s✗%s probe compile failed; aborting\n" "$RED" "$RESET"
    exit 2
fi

# Builds (parallelizable in spirit; serial here for clean output)
run_step "build C++ passthrough .so"  cpp_build_passthrough
run_step "build C++ xor-rotate .so"   cpp_build_xor
run_step "build Java xor-rotate .jar" java_build_xor

# Loads + round-trips
run_step "C++ load passthrough + selftest + round-trip" cpp_load_passthrough
run_step "C++ load xor-rotate + selftest + round-trip"   cpp_load_xor
run_step "Python ctypes load xor-rotate.so + round-trip" py_load_xor_native
run_step "Python pure-Python plugin round-trip"          py_pure_plugin

# Java SPI smoke (best-effort: skip if BC jars not on user's gradle cache)
if [[ -f java/build/libs/basefwx-java.jar ]] && \
   ls examples/plugins/xor-rotate-java/build/libs/basefwx-xor-rotate-java-*.jar >/dev/null 2>&1; then
    run_step "Java ServiceLoader + round-trip" java_load_xor
else
    step "Java ServiceLoader + round-trip"
    skip "Java jars not built (run gradle first)"
fi

# Cross-runtime parity — proves the .so contract is byte-equivalent
run_step "cross-runtime parity (C++ ↔ Python same .so)" cross_runtime_parity

total_ms=$(elapsed_ms $start_total)

if [[ $QUIET -eq 0 ]]; then
    printf "%s└──────────────────────────┘%s\n" "$CYAN" "$RESET"
fi

if (( FAIL == 0 )); then
    printf "%sPASS%s  %d steps in %dms (skipped: %d)\n" \
        "$GREEN" "$RESET" "$PASS" "$total_ms" "$SKIP"
    exit 0
else
    printf "%sFAIL%s  %d/%d steps failed in %dms\n" \
        "$RED" "$RESET" "$FAIL" "$((PASS + FAIL))" "$total_ms"
    for f in "${FAILURES[@]}"; do
        printf "  - %s\n" "$f"
    done
    exit 1
fi
