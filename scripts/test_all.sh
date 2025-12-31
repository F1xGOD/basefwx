#!/usr/bin/env bash
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

USE_VENV="${USE_VENV:-1}"
VENV_DIR="${VENV_DIR:-$ROOT/.venv}"
VENV_PY="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"
PYTHON_BIN="${PYTHON_BIN:-}"
CPP_BIN="$ROOT/cpp/build/basefwx_cpp"

LOG="$ROOT/diagnose.log"
TMP_DIR="$ROOT/.tmp_basefwx_tests"
ORIG_DIR="$TMP_DIR/orig"
WORK_DIR="$TMP_DIR/work"
OUT_DIR="$TMP_DIR/out"
VERIFY_LIST="$TMP_DIR/verify_list.txt"
TEXT_ORIG="$TMP_DIR/text_orig.txt"
PY_HELPER="$TMP_DIR/py_helper.py"
GEN_HELPER="$TMP_DIR/gen_files.py"

PW="pw12345"
BAD_PW="wrongpw"

ENABLE_HUGE="${ENABLE_HUGE:-0}"
BIG_FILE_BYTES="${BIG_FILE_BYTES:-37748736}"
HUGE_200M_BYTES="${HUGE_200M_BYTES:-200000000}"
HUGE_1P2G_BYTES="${HUGE_1P2G_BYTES:-1200000000}"

for arg in "$@"; do
    case "$arg" in
        --huge)
            ENABLE_HUGE=1
            ;;
    esac
done

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export BASEFWX_USER_KDF="pbkdf2"
export BASEFWX_B512_AEAD="1"
export BASEFWX_OBFUSCATE="1"
export ENABLE_HUGE BIG_FILE_BYTES HUGE_200M_BYTES HUGE_1P2G_BYTES

declare -A TIMES
FAILURES=()
CPP_AVAILABLE=1
PBKDF2_ITERS=""
STEP_INDEX=0
STEP_TOTAL=0
PROGRESS_INTERVAL="${PROGRESS_INTERVAL:-15}"
if [[ ! "$PROGRESS_INTERVAL" =~ ^[0-9]+$ ]]; then
    PROGRESS_INTERVAL=15
fi

log() {
    printf "%s\n" "$*" >>"$LOG"
}

phase() {
    printf "%s\n" "$1"
}

time_cmd() {
    local key="$1"
    shift
    local start_ns end_ns dur_ns rc
    announce_step "$key"
    log "CMD[$key]: $*"
    start_ns=$(date +%s%N)
    run_with_heartbeat "$key" "$@"
    rc=$?
    end_ns=$(date +%s%N)
    dur_ns=$((end_ns - start_ns))
    TIMES["$key"]=$dur_ns
    log "TIME[$key]: ${dur_ns}ns rc=${rc}"
    if (( rc != 0 )); then
        FAILURES+=("$key (rc=$rc)")
    fi
    return $rc
}

time_cmd_no_fail() {
    local key="$1"
    shift
    local start_ns end_ns dur_ns rc
    log "CMD[$key]: $*"
    start_ns=$(date +%s%N)
    "$@" >>"$LOG" 2>&1
    rc=$?
    end_ns=$(date +%s%N)
    dur_ns=$((end_ns - start_ns))
    TIMES["$key"]=$dur_ns
    log "TIME[$key]: ${dur_ns}ns rc=${rc}"
    return $rc
}

announce_step() {
    local label="$1"
    STEP_INDEX=$((STEP_INDEX + 1))
    if (( STEP_TOTAL > 0 )); then
        printf "[%d/%d] %s\n" "$STEP_INDEX" "$STEP_TOTAL" "$label"
    else
        printf "[%d] %s\n" "$STEP_INDEX" "$label"
    fi
}

run_with_heartbeat() {
    local label="$1"
    shift
    local start_s=$SECONDS
    if (( PROGRESS_INTERVAL <= 0 )); then
        "$@" >>"$LOG" 2>&1
        return $?
    fi
    "$@" >>"$LOG" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        sleep "$PROGRESS_INTERVAL"
        if kill -0 "$pid" 2>/dev/null; then
            printf "  ... %s (%ds elapsed)\n" "$label" "$((SECONDS - start_s))"
        fi
    done
    wait "$pid"
}

ensure_venv() {
    if [[ "$USE_VENV" != "1" ]]; then
        PYTHON_BIN="${PYTHON_BIN:-python3}"
        return 0
    fi
    if [[ ! -x "$VENV_PY" ]]; then
        time_cmd_no_fail "venv_create" python3 -m venv "$VENV_DIR"
    fi
    PYTHON_BIN="$VENV_PY"
    time_cmd_no_fail "venv_pip" "$PIP_BIN" install -U pip setuptools wheel
    time_cmd_no_fail "venv_install" "$PIP_BIN" install -e "$ROOT"
}

add_verify() {
    printf "%s|%s\n" "$1" "$2" >>"$VERIFY_LIST"
}

case_tag() {
    local name="$1"
    name="${name##*/}"
    name="${name//[^a-zA-Z0-9]/_}"
    printf "%s\n" "$name"
}

calc_total_steps() {
    local b512_count="${#B512FILE_CASES[@]}"
    local pb512_count="${#PB512FILE_CASES[@]}"
    STEP_TOTAL=0
    STEP_TOTAL=$((STEP_TOTAL + 7))
    STEP_TOTAL=$((STEP_TOTAL + 2 * b512_count + 2 * pb512_count))
    if (( CPP_AVAILABLE == 1 )); then
        STEP_TOTAL=$((STEP_TOTAL + 7))
        STEP_TOTAL=$((STEP_TOTAL + 2 * b512_count + 2 * pb512_count))
        STEP_TOTAL=$((STEP_TOTAL + 8))
        STEP_TOTAL=$((STEP_TOTAL + 2 * b512_count + 2 * pb512_count))
    fi
}

strip_newline() {
    local path="$1"
    local content
    content="$(cat "$path")"
    printf "%s" "$content" >"$path"
}

cpp_has_file_cli() {
    if [[ ! -x "$CPP_BIN" ]]; then
        return 1
    fi
    local usage
    usage="$("$CPP_BIN" 2>&1 || true)"
    printf "%s" "$usage" | grep -q "b512file-enc"
}

with_suffix() {
    local path="$1"
    local suffix="$2"
    local dir="${path%/*}"
    local name="${path##*/}"
    local base="${name%.*}"
    if [[ "$name" == "$base" ]]; then
        base="$name"
    fi
    if [[ "$dir" == "$path" ]]; then
        printf "%s%s\n" "$base" "$suffix"
    else
        printf "%s/%s%s\n" "$dir" "$base" "$suffix"
    fi
}

copy_input() {
    local case_name="$1"
    local filename="$2"
    local dest_dir="$WORK_DIR/$case_name"
    mkdir -p "$dest_dir"
    cp "$ORIG_DIR/$filename" "$dest_dir/"
    printf "%s/%s\n" "$dest_dir" "$filename"
}

ensure_cpp() {
    local build_dir="$ROOT/cpp/build"
    if [[ -d "$build_dir" ]]; then
        time_cmd_no_fail "cpp_build" cmake --build "$build_dir"
    fi
    if [[ -x "$CPP_BIN" ]] && cpp_has_file_cli; then
        return 0
    fi
    log "C++ binary missing or stale; attempting build"
    time_cmd_no_fail "cpp_configure" cmake -S "$ROOT/cpp" -B "$build_dir" -DBASEFWX_REQUIRE_ARGON2=OFF -DBASEFWX_REQUIRE_OQS=OFF
    if [[ ! -d "$build_dir" ]]; then
        log "CMake configure failed; build dir missing"
    fi
    time_cmd_no_fail "cpp_build" cmake --build "$build_dir"
    if [[ -x "$CPP_BIN" ]] && cpp_has_file_cli; then
        return 0
    fi
    CPP_AVAILABLE=0
    FAILURES+=("cpp_build (binary missing or stale)")
    return 1
}

cpp_fwxAES_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-enc $input"
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --out "$enc"
    local rc=$?
    if (( rc != 0 )); then
        return $rc
    fi
    log "STEP: $CPP_BIN fwxaes-dec $enc"
    "$CPP_BIN" fwxaes-dec "$enc" -p "$PW" --out "$dec"
}

cpp_fwxAES_wrong() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-enc $input"
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --out "$enc" || return $?
    log "STEP: $CPP_BIN fwxaes-dec $enc (wrong pw)"
    "$CPP_BIN" fwxaes-dec "$enc" -p "$BAD_PW" --out "$dec"
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for fwxaes wrong password"
        return 1
    fi
    return 0
}

cpp_text_roundtrip() {
    local method="$1"
    local text_path="$2"
    local out_path="$3"
    local pw="$4"
    local enc_file="${out_path}.enc"
    local text
    text="$(cat "$text_path")"
    if [[ "$method" == "b256" ]]; then
        log "STEP: $CPP_BIN b256-enc"
        "$CPP_BIN" b256-enc "$text" >"$enc_file" || return $?
        local enc
        enc="$(cat "$enc_file")"
        log "STEP: $CPP_BIN b256-dec"
        "$CPP_BIN" b256-dec "$enc" >"$out_path" || return $?
        strip_newline "$out_path"
        return 0
    fi
    log "STEP: $CPP_BIN ${method}-enc"
    "$CPP_BIN" "${method}-enc" "$text" -p "$pw" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >"$enc_file" || return $?
    local enc
    enc="$(cat "$enc_file")"
    log "STEP: $CPP_BIN ${method}-dec"
    "$CPP_BIN" "${method}-dec" "$enc" -p "$pw" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >"$out_path" || return $?
    strip_newline "$out_path"
}

cpp_text_encode() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local pw="$4"
    local text
    text="$(cat "$text_path")"
    if [[ "$method" == "b256" ]]; then
        log "STEP: $CPP_BIN b256-enc"
        "$CPP_BIN" b256-enc "$text" >"$enc_file" || return $?
        strip_newline "$enc_file"
        return $?
    fi
    log "STEP: $CPP_BIN ${method}-enc"
    "$CPP_BIN" "${method}-enc" "$text" -p "$pw" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >"$enc_file" || return $?
    strip_newline "$enc_file"
}

cpp_text_decode() {
    local method="$1"
    local enc_file="$2"
    local out_path="$3"
    local pw="$4"
    local enc
    enc="$(cat "$enc_file")"
    if [[ "$method" == "b256" ]]; then
        log "STEP: $CPP_BIN b256-dec"
        "$CPP_BIN" b256-dec "$enc" >"$out_path" || return $?
        strip_newline "$out_path"
        return 0
    fi
    log "STEP: $CPP_BIN ${method}-dec"
    "$CPP_BIN" "${method}-dec" "$enc" -p "$pw" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >"$out_path" || return $?
    strip_newline "$out_path"
}

cpp_text_wrong() {
    local method="$1"
    local text_path="$2"
    local pw="$3"
    local enc_file="$4"
    local text
    text="$(cat "$text_path")"
    log "STEP: $CPP_BIN ${method}-enc"
    "$CPP_BIN" "${method}-enc" "$text" -p "$pw" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >"$enc_file" || return $?
    local enc
    enc="$(cat "$enc_file")"
    log "STEP: $CPP_BIN ${method}-dec (wrong pw)"
    "$CPP_BIN" "${method}-dec" "$enc" -p "$BAD_PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for ${method} wrong password"
        return 1
    fi
    return 0
}

py_b512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: python -m basefwx cryptin b512 $input"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$input" -p "$PW" --no-master || return $?
    log "STEP: python -m basefwx cryptin b512 $enc"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$enc" -p "$PW" --no-master
}

py_b512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: python -m basefwx cryptin b512 $input"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$input" -p "$PW" --no-master || return $?
    log "STEP: python -m basefwx cryptin b512 $enc (wrong pw)"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$enc" -p "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for b512file wrong password"
        return 1
    fi
    return 0
}

cpp_b512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $CPP_BIN b512file-enc $input"
    "$CPP_BIN" b512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: $CPP_BIN b512file-dec $enc"
    "$CPP_BIN" b512file-dec "$enc" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

cpp_b512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $CPP_BIN b512file-enc $input"
    "$CPP_BIN" b512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: $CPP_BIN b512file-dec $enc (wrong pw)"
    "$CPP_BIN" b512file-dec "$enc" -p "$BAD_PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for b512file wrong password"
        return 1
    fi
    return 0
}

py_pb512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: python -m basefwx cryptin pb512 $input"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$input" -p "$PW" --no-master || return $?
    log "STEP: python -m basefwx cryptin pb512 $enc"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$enc" -p "$PW" --no-master
}

py_pb512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: python -m basefwx cryptin pb512 $input"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$input" -p "$PW" --no-master || return $?
    log "STEP: python -m basefwx cryptin pb512 $enc (wrong pw)"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$enc" -p "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for pb512file wrong password"
        return 1
    fi
    return 0
}

cpp_pb512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $CPP_BIN pb512file-enc $input"
    "$CPP_BIN" pb512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: $CPP_BIN pb512file-dec $enc"
    "$CPP_BIN" pb512file-dec "$enc" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

cpp_pb512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $CPP_BIN pb512file-enc $input"
    "$CPP_BIN" pb512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: $CPP_BIN pb512file-dec $enc (wrong pw)"
    "$CPP_BIN" pb512file-dec "$enc" -p "$BAD_PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for pb512file wrong password"
        return 1
    fi
    return 0
}

fwxaes_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: python fwxaes-enc $input"
    "$PYTHON_BIN" "$PY_HELPER" fwxaes-enc "$input" "$enc" "$PW" || return $?
    log "STEP: $CPP_BIN fwxaes-dec $enc"
    "$CPP_BIN" fwxaes-dec "$enc" -p "$PW" --out "$dec"
}

fwxaes_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-enc $input"
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --out "$enc" || return $?
    log "STEP: python fwxaes-dec $enc"
    "$PYTHON_BIN" "$PY_HELPER" fwxaes-dec "$enc" "$dec" "$PW"
}

text_py_enc_cpp_dec() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local out_path="$4"
    log "STEP: python text-encode $method"
    "$PYTHON_BIN" "$PY_HELPER" text-encode "$method" "$text_path" "$enc_file" "$PW" || return $?
    cpp_text_decode "$method" "$enc_file" "$out_path" "$PW"
}

text_cpp_enc_py_dec() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local out_path="$4"
    cpp_text_encode "$method" "$text_path" "$enc_file" "$PW" || return $?
    log "STEP: python text-decode $method"
    "$PYTHON_BIN" "$PY_HELPER" text-decode "$method" "$enc_file" "$out_path" "$PW"
}

b512file_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    log "STEP: python -m basefwx cryptin b512 $input"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$input" -p "$PW" --no-master || return $?
    log "STEP: $CPP_BIN b512file-dec $enc"
    "$CPP_BIN" b512file-dec "$enc" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

b512file_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    log "STEP: $CPP_BIN b512file-enc $input"
    "$CPP_BIN" b512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: python -m basefwx cryptin b512 $enc"
    "$PYTHON_BIN" -m basefwx cryptin b512 "$enc" -p "$PW" --no-master
}

pb512file_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    log "STEP: python -m basefwx cryptin pb512 $input"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$input" -p "$PW" --no-master || return $?
    log "STEP: $CPP_BIN pb512file-dec $enc"
    "$CPP_BIN" pb512file-dec "$enc" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

pb512file_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    log "STEP: $CPP_BIN pb512file-enc $input"
    "$CPP_BIN" pb512file-enc "$input" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS" || return $?
    log "STEP: python -m basefwx cryptin pb512 $enc"
    "$PYTHON_BIN" -m basefwx cryptin pb512 "$enc" -p "$PW" --no-master
}

rm -rf "$TMP_DIR"
phase "PHASE1: generate temporary files"
mkdir -p "$ORIG_DIR" "$WORK_DIR" "$OUT_DIR"
printf "" >"$LOG"
printf "" >"$VERIFY_LIST"

ensure_venv

log "Python: $("$PYTHON_BIN" --version 2>&1)"
log "C++ binary: $CPP_BIN"
PBKDF2_ITERS="$("$PYTHON_BIN" - <<'PY' 2>>"$LOG"
from basefwx.main import basefwx
print(basefwx.USER_KDF_ITERATIONS)
PY
)"
if [[ -z "$PBKDF2_ITERS" || ! "$PBKDF2_ITERS" =~ ^[0-9]+$ ]]; then
    PBKDF2_ITERS="200000"
    log "PBKDF2_ITERS fallback: ${PBKDF2_ITERS}"
fi
log "PBKDF2_ITERS: ${PBKDF2_ITERS}"

cat >"$TEXT_ORIG" <<'TXT'
The quick brown fox jumps over the lazy dog 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz.
TXT
printf "%s" "$(cat "$TEXT_ORIG")" >"$TEXT_ORIG"

cat >"$GEN_HELPER" <<'PY'
import os
import sys
import random
from pathlib import Path

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)

text = ("The quick brown fox jumps over the lazy dog. " * 40).encode("ascii")
(root / "tiny.txt").write_bytes(text[:1024])

(root / "small.bin").write_bytes(os.urandom(64 * 1024))
(root / "medium.bin").write_bytes(os.urandom(512 * 1024))

png_path = root / "noise.png"
try:
    from PIL import Image
    w, h = 320, 320
    data = os.urandom(w * h * 3)
    img = Image.frombytes("RGB", (w, h), data)
    img.save(png_path)
except Exception:
    png_path.write_bytes(os.urandom(320 * 320 * 3))

enable_huge = os.getenv("ENABLE_HUGE", "0") == "1"
big_bytes = int(os.getenv("BIG_FILE_BYTES", "37748736"))
large_200m = int(os.getenv("HUGE_200M_BYTES", "200000000"))
large_1p2g = int(os.getenv("HUGE_1P2G_BYTES", "1200000000"))

def write_large(path: Path, size: int, seed: int) -> None:
    chunk = 4 * 1024 * 1024
    rng = random.Random(seed)
    with path.open("wb") as handle:
        remaining = size
        while remaining > 0:
            take = min(chunk, remaining)
            if hasattr(rng, "randbytes"):
                data = rng.randbytes(take)
            else:
                data = os.urandom(take)
            handle.write(data)
            remaining -= take

write_large(root / "large_36m.bin", big_bytes, seed=4242)
if enable_huge:
    write_large(root / "large_200m.bin", large_200m, seed=12345)
    write_large(root / "huge_1p2g.bin", large_1p2g, seed=98765)
PY

log "CMD[generate_fixtures]: $PYTHON_BIN $GEN_HELPER $ORIG_DIR"
run_with_heartbeat "generate_fixtures" "$PYTHON_BIN" "$GEN_HELPER" "$ORIG_DIR"
gen_rc=$?
log "TIME[generate_fixtures]: rc=${gen_rc}"
if (( gen_rc != 0 )); then
    FAILURES+=("generate_fixtures (rc=${gen_rc})")
    printf "\nFAILURES (%d):\n" "${#FAILURES[@]}"
    for failure in "${FAILURES[@]}"; do
        printf " - %s\n" "$failure"
    done
    printf "See diagnose.log for details.\n"
    exit 1
fi

cat >"$PY_HELPER" <<'PY'
import sys
from basefwx.main import basefwx

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()

def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)

def text_encode(method: str, text: str, pw: str) -> str:
    if method == "b256":
        return basefwx.b256encode(text)
    if method == "b512":
        return basefwx.b512encode(text, pw, use_master=False)
    if method == "pb512":
        return basefwx.pb512encode(text, pw, use_master=False)
    raise ValueError(f"Unsupported method {method}")

def text_decode(method: str, enc: str, pw: str) -> str:
    if method == "b256":
        return basefwx.b256decode(enc)
    if method == "b512":
        return basefwx.b512decode(enc, pw, use_master=False)
    if method == "pb512":
        return basefwx.pb512decode(enc, pw, use_master=False)
    raise ValueError(f"Unsupported method {method}")

def cmd_fwxaes_roundtrip(args: list[str]) -> int:
    inp, enc, dec, pw = args
    basefwx.fwxAES_file(inp, pw, output=enc)
    basefwx.fwxAES_file(enc, pw, output=dec)
    return 0

def cmd_fwxaes_enc(args: list[str]) -> int:
    inp, enc, pw = args
    basefwx.fwxAES_file(inp, pw, output=enc)
    return 0

def cmd_fwxaes_dec(args: list[str]) -> int:
    inp, dec, pw = args
    basefwx.fwxAES_file(inp, pw, output=dec)
    return 0

def cmd_fwxaes_wrong(args: list[str]) -> int:
    inp, enc, dec, pw, bad_pw = args
    basefwx.fwxAES_file(inp, pw, output=enc)
    try:
        basefwx.fwxAES_file(enc, bad_pw, output=dec)
    except Exception:
        return 0
    return 1

def cmd_text_roundtrip(args: list[str]) -> int:
    method, text_path, out_path, pw = args
    text = read_text(text_path)
    enc = text_encode(method, text, pw)
    dec = text_decode(method, enc, pw)
    write_text(out_path, dec)
    return 0

def cmd_text_encode(args: list[str]) -> int:
    method, text_path, out_path, pw = args
    text = read_text(text_path)
    enc = text_encode(method, text, pw)
    write_text(out_path, enc)
    return 0

def cmd_text_decode(args: list[str]) -> int:
    method, enc_path, out_path, pw = args
    enc = read_text(enc_path)
    dec = text_decode(method, enc, pw)
    write_text(out_path, dec)
    return 0

def cmd_text_decode_fail(args: list[str]) -> int:
    method, enc_path, pw = args
    enc = read_text(enc_path)
    try:
        text_decode(method, enc, pw)
    except Exception:
        return 0
    return 1

def cmd_text_wrong(args: list[str]) -> int:
    method, text_path, pw, bad_pw = args
    text = read_text(text_path)
    enc = text_encode(method, text, pw)
    try:
        text_decode(method, enc, bad_pw)
    except Exception:
        return 0
    return 1

def main() -> int:
    if len(sys.argv) < 2:
        return 2
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd == "fwxaes-roundtrip":
        return cmd_fwxaes_roundtrip(args)
    if cmd == "fwxaes-enc":
        return cmd_fwxaes_enc(args)
    if cmd == "fwxaes-dec":
        return cmd_fwxaes_dec(args)
    if cmd == "fwxaes-wrong":
        return cmd_fwxaes_wrong(args)
    if cmd == "text-roundtrip":
        return cmd_text_roundtrip(args)
    if cmd == "text-encode":
        return cmd_text_encode(args)
    if cmd == "text-decode":
        return cmd_text_decode(args)
    if cmd == "text-decode-fail":
        return cmd_text_decode_fail(args)
    if cmd == "text-wrong":
        return cmd_text_wrong(args)
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
PY

phase "PHASE2: run native Python/C++ tests"
ensure_cpp || log "C++ binary unavailable; C++ tests will be marked failed"

FWXAES_FILE="tiny.txt"
B512FILE_CASES=("noise.png" "large_36m.bin")
PB512FILE_CASES=("medium.bin" "large_36m.bin")
if [[ "$ENABLE_HUGE" == "1" ]]; then
    B512FILE_CASES+=("large_200m.bin")
    PB512FILE_CASES+=("huge_1p2g.bin")
fi
STEP_INDEX=0
calc_total_steps

# fwxAES correct
fwxaes_py_input="$(copy_input "fwxaes_py_correct" "$FWXAES_FILE")"
fwxaes_py_enc="$(with_suffix "$fwxaes_py_input" ".fwx")"
fwxaes_py_dec="$WORK_DIR/fwxaes_py_correct/decoded_${FWXAES_FILE}"
time_cmd "fwxaes_py_correct" "$PYTHON_BIN" "$PY_HELPER" fwxaes-roundtrip "$fwxaes_py_input" "$fwxaes_py_enc" "$fwxaes_py_dec" "$PW"
add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_py_dec"

fwxaes_cpp_input="$(copy_input "fwxaes_cpp_correct" "$FWXAES_FILE")"
fwxaes_cpp_enc="$(with_suffix "$fwxaes_cpp_input" ".fwx")"
fwxaes_cpp_dec="$WORK_DIR/fwxaes_cpp_correct/decoded_${FWXAES_FILE}"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "fwxaes_cpp_correct" cpp_fwxAES_roundtrip "$fwxaes_cpp_input" "$fwxaes_cpp_enc" "$fwxaes_cpp_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_cpp_dec"
else
    FAILURES+=("fwxaes_cpp_correct (cpp unavailable)")
fi

# fwxAES wrong password
fwxaes_py_wrong_input="$(copy_input "fwxaes_py_wrong" "$FWXAES_FILE")"
fwxaes_py_wrong_enc="$(with_suffix "$fwxaes_py_wrong_input" ".fwx")"
fwxaes_py_wrong_dec="$WORK_DIR/fwxaes_py_wrong/decoded_${FWXAES_FILE}"
time_cmd "fwxaes_py_wrong" "$PYTHON_BIN" "$PY_HELPER" fwxaes-wrong "$fwxaes_py_wrong_input" "$fwxaes_py_wrong_enc" "$fwxaes_py_wrong_dec" "$PW" "$BAD_PW"

fwxaes_cpp_wrong_input="$(copy_input "fwxaes_cpp_wrong" "$FWXAES_FILE")"
fwxaes_cpp_wrong_enc="$(with_suffix "$fwxaes_cpp_wrong_input" ".fwx")"
fwxaes_cpp_wrong_dec="$WORK_DIR/fwxaes_cpp_wrong/decoded_${FWXAES_FILE}"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "fwxaes_cpp_wrong" cpp_fwxAES_wrong "$fwxaes_cpp_wrong_input" "$fwxaes_cpp_wrong_enc" "$fwxaes_cpp_wrong_dec"
else
    FAILURES+=("fwxaes_cpp_wrong (cpp unavailable)")
fi

# b256 correct
b256_py_out="$OUT_DIR/b256_py.txt"
time_cmd "b256_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip b256 "$TEXT_ORIG" "$b256_py_out" "$PW"
add_verify "$TEXT_ORIG" "$b256_py_out"

b256_cpp_out="$OUT_DIR/b256_cpp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b256_cpp_correct" cpp_text_roundtrip b256 "$TEXT_ORIG" "$b256_cpp_out" "$PW"
    add_verify "$TEXT_ORIG" "$b256_cpp_out"
else
    FAILURES+=("b256_cpp_correct (cpp unavailable)")
fi

# b512 correct
b512_py_out="$OUT_DIR/b512_py.txt"
time_cmd "b512_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip b512 "$TEXT_ORIG" "$b512_py_out" "$PW"
add_verify "$TEXT_ORIG" "$b512_py_out"

b512_cpp_out="$OUT_DIR/b512_cpp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b512_cpp_correct" cpp_text_roundtrip b512 "$TEXT_ORIG" "$b512_cpp_out" "$PW"
    add_verify "$TEXT_ORIG" "$b512_cpp_out"
else
    FAILURES+=("b512_cpp_correct (cpp unavailable)")
fi

# b512 wrong password
time_cmd "b512_py_wrong" "$PYTHON_BIN" "$PY_HELPER" text-wrong b512 "$TEXT_ORIG" "$PW" "$BAD_PW"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b512_cpp_wrong" cpp_text_wrong b512 "$TEXT_ORIG" "$PW" "$OUT_DIR/b512_cpp_wrong.enc"
else
    FAILURES+=("b512_cpp_wrong (cpp unavailable)")
fi

# pb512 correct
pb512_py_out="$OUT_DIR/pb512_py.txt"
time_cmd "pb512_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip pb512 "$TEXT_ORIG" "$pb512_py_out" "$PW"
add_verify "$TEXT_ORIG" "$pb512_py_out"

pb512_cpp_out="$OUT_DIR/pb512_cpp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "pb512_cpp_correct" cpp_text_roundtrip pb512 "$TEXT_ORIG" "$pb512_cpp_out" "$PW"
    add_verify "$TEXT_ORIG" "$pb512_cpp_out"
else
    FAILURES+=("pb512_cpp_correct (cpp unavailable)")
fi

# pb512 wrong password
time_cmd "pb512_py_wrong" "$PYTHON_BIN" "$PY_HELPER" text-wrong pb512 "$TEXT_ORIG" "$PW" "$BAD_PW"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "pb512_cpp_wrong" cpp_text_wrong pb512 "$TEXT_ORIG" "$PW" "$OUT_DIR/pb512_cpp_wrong.enc"
else
    FAILURES+=("pb512_cpp_wrong (cpp unavailable)")
fi

B512FILE_PY_TOTAL=0
B512FILE_CPP_TOTAL=0
for file_name in "${B512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    # b512file correct
    b512file_py_input="$(copy_input "b512file_py_correct_${tag}" "$file_name")"
    key="b512file_py_correct_${tag}"
    time_cmd "$key" py_b512file_roundtrip "$b512file_py_input"
    B512FILE_PY_TOTAL=$((B512FILE_PY_TOTAL + ${TIMES[$key]:-0}))
    add_verify "$ORIG_DIR/$file_name" "$b512file_py_input"

    b512file_cpp_input="$(copy_input "b512file_cpp_correct_${tag}" "$file_name")"
    if (( CPP_AVAILABLE == 1 )); then
        key="b512file_cpp_correct_${tag}"
        time_cmd "$key" cpp_b512file_roundtrip "$b512file_cpp_input"
        B512FILE_CPP_TOTAL=$((B512FILE_CPP_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$b512file_cpp_input"
    else
        FAILURES+=("b512file_cpp_correct_${tag} (cpp unavailable)")
    fi

    # b512file wrong password
    b512file_py_wrong_input="$(copy_input "b512file_py_wrong_${tag}" "$file_name")"
    time_cmd "b512file_py_wrong_${tag}" py_b512file_wrong "$b512file_py_wrong_input"

    b512file_cpp_wrong_input="$(copy_input "b512file_cpp_wrong_${tag}" "$file_name")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "b512file_cpp_wrong_${tag}" cpp_b512file_wrong "$b512file_cpp_wrong_input"
    else
        FAILURES+=("b512file_cpp_wrong_${tag} (cpp unavailable)")
    fi
done

PB512FILE_PY_TOTAL=0
PB512FILE_CPP_TOTAL=0
for file_name in "${PB512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    # pb512file correct
    pb512file_py_input="$(copy_input "pb512file_py_correct_${tag}" "$file_name")"
    key="pb512file_py_correct_${tag}"
    time_cmd "$key" py_pb512file_roundtrip "$pb512file_py_input"
    PB512FILE_PY_TOTAL=$((PB512FILE_PY_TOTAL + ${TIMES[$key]:-0}))
    add_verify "$ORIG_DIR/$file_name" "$pb512file_py_input"

    pb512file_cpp_input="$(copy_input "pb512file_cpp_correct_${tag}" "$file_name")"
    if (( CPP_AVAILABLE == 1 )); then
        key="pb512file_cpp_correct_${tag}"
        time_cmd "$key" cpp_pb512file_roundtrip "$pb512file_cpp_input"
        PB512FILE_CPP_TOTAL=$((PB512FILE_CPP_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$pb512file_cpp_input"
    else
        FAILURES+=("pb512file_cpp_correct_${tag} (cpp unavailable)")
    fi

    # pb512file wrong password
    pb512file_py_wrong_input="$(copy_input "pb512file_py_wrong_${tag}" "$file_name")"
    time_cmd "pb512file_py_wrong_${tag}" py_pb512file_wrong "$pb512file_py_wrong_input"

    pb512file_cpp_wrong_input="$(copy_input "pb512file_cpp_wrong_${tag}" "$file_name")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "pb512file_cpp_wrong_${tag}" cpp_pb512file_wrong "$pb512file_cpp_wrong_input"
    else
        FAILURES+=("pb512file_cpp_wrong_${tag} (cpp unavailable)")
    fi
done

phase "PHASE2.2: cross-compat tests"

# fwxAES cross-compat
fwxaes_pycc_input="$(copy_input "fwxaes_pycc" "$FWXAES_FILE")"
fwxaes_pycc_enc="$(with_suffix "$fwxaes_pycc_input" ".fwx")"
fwxaes_pycc_dec="$WORK_DIR/fwxaes_pycc/decoded_${FWXAES_FILE}"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "fwxaes_py_enc_cpp_dec" fwxaes_py_enc_cpp_dec "$fwxaes_pycc_input" "$fwxaes_pycc_enc" "$fwxaes_pycc_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_pycc_dec"
else
    FAILURES+=("fwxaes_py_enc_cpp_dec (cpp unavailable)")
fi

fwxaes_cpyp_input="$(copy_input "fwxaes_cpyp" "$FWXAES_FILE")"
fwxaes_cpyp_enc="$(with_suffix "$fwxaes_cpyp_input" ".fwx")"
fwxaes_cpyp_dec="$WORK_DIR/fwxaes_cpyp/decoded_${FWXAES_FILE}"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "fwxaes_cpp_enc_py_dec" fwxaes_cpp_enc_py_dec "$fwxaes_cpyp_input" "$fwxaes_cpyp_enc" "$fwxaes_cpyp_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_cpyp_dec"
else
    FAILURES+=("fwxaes_cpp_enc_py_dec (cpp unavailable)")
fi

# b256 cross-compat
b256_py_enc="$OUT_DIR/b256_py_enc.txt"
b256_pycc_out="$OUT_DIR/b256_pycc.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b256_py_enc_cpp_dec" text_py_enc_cpp_dec b256 "$TEXT_ORIG" "$b256_py_enc" "$b256_pycc_out"
    add_verify "$TEXT_ORIG" "$b256_pycc_out"
else
    FAILURES+=("b256_py_enc_cpp_dec (cpp unavailable)")
fi

b256_cpp_enc="$OUT_DIR/b256_cpp_enc.txt"
b256_cpyp_out="$OUT_DIR/b256_cpyp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b256_cpp_enc_py_dec" text_cpp_enc_py_dec b256 "$TEXT_ORIG" "$b256_cpp_enc" "$b256_cpyp_out"
    add_verify "$TEXT_ORIG" "$b256_cpyp_out"
else
    FAILURES+=("b256_cpp_enc_py_dec (cpp unavailable)")
fi

# b512 cross-compat
b512_py_enc="$OUT_DIR/b512_py_enc.txt"
b512_pycc_out="$OUT_DIR/b512_pycc.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b512_py_enc_cpp_dec" text_py_enc_cpp_dec b512 "$TEXT_ORIG" "$b512_py_enc" "$b512_pycc_out"
    add_verify "$TEXT_ORIG" "$b512_pycc_out"
else
    FAILURES+=("b512_py_enc_cpp_dec (cpp unavailable)")
fi

b512_cpp_enc="$OUT_DIR/b512_cpp_enc.txt"
b512_cpyp_out="$OUT_DIR/b512_cpyp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "b512_cpp_enc_py_dec" text_cpp_enc_py_dec b512 "$TEXT_ORIG" "$b512_cpp_enc" "$b512_cpyp_out"
    add_verify "$TEXT_ORIG" "$b512_cpyp_out"
else
    FAILURES+=("b512_cpp_enc_py_dec (cpp unavailable)")
fi

# pb512 cross-compat
pb512_py_enc="$OUT_DIR/pb512_py_enc.txt"
pb512_pycc_out="$OUT_DIR/pb512_pycc.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "pb512_py_enc_cpp_dec" text_py_enc_cpp_dec pb512 "$TEXT_ORIG" "$pb512_py_enc" "$pb512_pycc_out"
    add_verify "$TEXT_ORIG" "$pb512_pycc_out"
else
    FAILURES+=("pb512_py_enc_cpp_dec (cpp unavailable)")
fi

pb512_cpp_enc="$OUT_DIR/pb512_cpp_enc.txt"
pb512_cpyp_out="$OUT_DIR/pb512_cpyp.txt"
if (( CPP_AVAILABLE == 1 )); then
    time_cmd "pb512_cpp_enc_py_dec" text_cpp_enc_py_dec pb512 "$TEXT_ORIG" "$pb512_cpp_enc" "$pb512_cpyp_out"
    add_verify "$TEXT_ORIG" "$pb512_cpyp_out"
else
    FAILURES+=("pb512_cpp_enc_py_dec (cpp unavailable)")
fi

# b512file cross-compat
for file_name in "${B512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    b512file_pycc_input="$(copy_input "b512file_pycc_${tag}" "$file_name")"
    b512file_pycc_enc="$(with_suffix "$b512file_pycc_input" ".fwx")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "b512file_py_enc_cpp_dec_${tag}" b512file_py_enc_cpp_dec "$b512file_pycc_input" "$b512file_pycc_enc"
        add_verify "$ORIG_DIR/$file_name" "$b512file_pycc_input"
    else
        FAILURES+=("b512file_py_enc_cpp_dec_${tag} (cpp unavailable)")
    fi

    b512file_cpyp_input="$(copy_input "b512file_cpyp_${tag}" "$file_name")"
    b512file_cpyp_enc="$(with_suffix "$b512file_cpyp_input" ".fwx")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "b512file_cpp_enc_py_dec_${tag}" b512file_cpp_enc_py_dec "$b512file_cpyp_input" "$b512file_cpyp_enc"
        add_verify "$ORIG_DIR/$file_name" "$b512file_cpyp_input"
    else
        FAILURES+=("b512file_cpp_enc_py_dec_${tag} (cpp unavailable)")
    fi
done

# pb512file cross-compat
for file_name in "${PB512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    pb512file_pycc_input="$(copy_input "pb512file_pycc_${tag}" "$file_name")"
    pb512file_pycc_enc="$(with_suffix "$pb512file_pycc_input" ".fwx")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "pb512file_py_enc_cpp_dec_${tag}" pb512file_py_enc_cpp_dec "$pb512file_pycc_input" "$pb512file_pycc_enc"
        add_verify "$ORIG_DIR/$file_name" "$pb512file_pycc_input"
    else
        FAILURES+=("pb512file_py_enc_cpp_dec_${tag} (cpp unavailable)")
    fi

    pb512file_cpyp_input="$(copy_input "pb512file_cpyp_${tag}" "$file_name")"
    pb512file_cpyp_enc="$(with_suffix "$pb512file_cpyp_input" ".fwx")"
    if (( CPP_AVAILABLE == 1 )); then
        time_cmd "pb512file_cpp_enc_py_dec_${tag}" pb512file_cpp_enc_py_dec "$pb512file_cpyp_input" "$pb512file_cpyp_enc"
        add_verify "$ORIG_DIR/$file_name" "$pb512file_cpyp_input"
    else
        FAILURES+=("pb512file_cpp_enc_py_dec_${tag} (cpp unavailable)")
    fi
done

phase "PHASE3: verify outputs"
if [[ -f "$VERIFY_LIST" ]]; then
    while IFS="|" read -r orig out; do
        if [[ -z "$orig" || -z "$out" ]]; then
            continue
        fi
        if ! cmp -s "$orig" "$out"; then
            log "VERIFY FAIL: $orig vs $out"
            FAILURES+=("verify_mismatch ($out)")
        fi
    done <"$VERIFY_LIST"
fi

phase "PHASE4: cleanup and summary"
if [[ "${BASEFWX_KEEP_TMP:-0}" != "1" ]]; then
    rm -rf "$TMP_DIR"
fi

format_ns() {
    awk -v ns="$1" 'BEGIN { printf "%.3f", ns / 1000000000 }'
}

compare_speed() {
    local label="$1"
    local py_key="$2"
    local cpp_key="$3"
    local py_ns="${TIMES[$py_key]:-}"
    local cpp_ns="${TIMES[$cpp_key]:-}"
    if [[ -z "$py_ns" || -z "$cpp_ns" ]]; then
        printf "%s: missing timing data\n" "$label"
        return
    fi
    local py_s cpp_s
    py_s=$(format_ns "$py_ns")
    cpp_s=$(format_ns "$cpp_ns")
    local diff_ns=$((py_ns - cpp_ns))
    local faster="C++"
    if (( diff_ns < 0 )); then
        diff_ns=$((0 - diff_ns))
        faster="Python"
    fi
    local diff_s
    diff_s=$(format_ns "$diff_ns")
    printf "%s: Python %ss, C++ %ss, %s faster by %ss\n" "$label" "$py_s" "$cpp_s" "$faster" "$diff_s"
}

printf "\nTiming summary (native):\n"
compare_speed "fwxAES" "fwxaes_py_correct" "fwxaes_cpp_correct"
compare_speed "b256" "b256_py_correct" "b256_cpp_correct"
compare_speed "b512" "b512_py_correct" "b512_cpp_correct"
compare_speed "pb512" "pb512_py_correct" "pb512_cpp_correct"
TIMES["b512file_py_total"]=$B512FILE_PY_TOTAL
TIMES["b512file_cpp_total"]=$B512FILE_CPP_TOTAL
TIMES["pb512file_py_total"]=$PB512FILE_PY_TOTAL
TIMES["pb512file_cpp_total"]=$PB512FILE_CPP_TOTAL
compare_speed "b512file" "b512file_py_total" "b512file_cpp_total"
compare_speed "pb512file" "pb512file_py_total" "pb512file_cpp_total"

if (( ${#FAILURES[@]} > 0 )); then
    printf "\nFAILURES (%d):\n" "${#FAILURES[@]}"
    for failure in "${FAILURES[@]}"; do
        printf " - %s\n" "$failure"
    done
    printf "See diagnose.log for details.\n"
    exit 1
fi

printf "\nAll tests passed. See diagnose.log for details.\n"
exit 0
