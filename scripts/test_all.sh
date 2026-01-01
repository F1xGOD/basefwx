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
TEST_MODE="${TEST_MODE:-default}"
SKIP_WRONG=0
SKIP_CROSS=0
TEST_KDF_ITERS=""

for arg in "$@"; do
    case "$arg" in
        --huge)
            ENABLE_HUGE=1
            ;;
        --fast)
            ENABLE_HUGE=0
            BIG_FILE_BYTES=348160
            TEST_MODE="fast"
            SKIP_WRONG=1
            SKIP_CROSS=1
            TEST_KDF_ITERS="${TEST_KDF_ITERS:-5000}"
            ;;
        --quickest)
            ENABLE_HUGE=0
            BIG_FILE_BYTES=800
            TEST_MODE="quickest"
            SKIP_WRONG=1
            SKIP_CROSS=1
            TEST_KDF_ITERS="${TEST_KDF_ITERS:-1000}"
            ;;
    esac
done
if [[ "$TEST_MODE" != "default" ]]; then
    ENABLE_HUGE=0
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export BASEFWX_USER_KDF="pbkdf2"
export BASEFWX_B512_AEAD="1"
export BASEFWX_OBFUSCATE="1"
if [[ -n "$TEST_KDF_ITERS" ]]; then
    export BASEFWX_TEST_KDF_ITERS="$TEST_KDF_ITERS"
fi
export ENABLE_HUGE BIG_FILE_BYTES HUGE_200M_BYTES HUGE_1P2G_BYTES TEST_MODE SKIP_WRONG SKIP_CROSS

COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-}"
if [[ -z "$COOLDOWN_SECONDS" ]]; then
    if [[ "$TEST_MODE" == "default" ]]; then
        COOLDOWN_SECONDS=2
    else
        COOLDOWN_SECONDS=1
    fi
fi
if [[ ! "$COOLDOWN_SECONDS" =~ ^[0-9]+$ ]]; then
    COOLDOWN_SECONDS=1
fi

FFMPEG_AVAILABLE=0
if command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
    FFMPEG_AVAILABLE=1
fi
export FFMPEG_AVAILABLE COOLDOWN_SECONDS

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

COLOR_ENABLED=1
if [[ ! -t 1 || -n "${NO_COLOR:-}" || "${TERM:-}" == "dumb" ]]; then
    COLOR_ENABLED=0
fi
if (( COLOR_ENABLED == 1 )); then
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    MAGENTA=$'\033[35m'
    CYAN=$'\033[36m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    MAGENTA=""
    CYAN=""
    BOLD=""
    RESET=""
fi

EMOJI_PHASE="🧪"
EMOJI_STEP="🔹"
EMOJI_PROGRESS="⏳"
EMOJI_OK="✅"
EMOJI_FAIL="❌"
EMOJI_FAST="⚡"
EMOJI_SLOW="🐢"
EMOJI_WARN="⚠️"

log() {
    printf "%s\n" "$*" >>"$LOG"
}

phase() {
    printf "%s%s %s%s\n" "${BOLD}${MAGENTA}" "$EMOJI_PHASE" "$1" "$RESET"
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
        printf "%s%s [%d/%d]%s %s\n" "${CYAN}" "$EMOJI_STEP" "$STEP_INDEX" "$STEP_TOTAL" "$RESET" "$label"
    else
        printf "%s%s [%d]%s %s\n" "${CYAN}" "$EMOJI_STEP" "$STEP_INDEX" "$RESET" "$label"
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
    local next_tick=$((start_s + PROGRESS_INTERVAL))
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        local now=$SECONDS
        if (( now >= next_tick )); then
            if kill -0 "$pid" 2>/dev/null; then
                printf "  %s %s%s%s (%ds elapsed)\n" "$EMOJI_PROGRESS" "$YELLOW" "$label" "$RESET" "$((now - start_s))"
            fi
            next_tick=$((next_tick + PROGRESS_INTERVAL))
        fi
    done
    wait "$pid"
}

cooldown() {
    local reason="$1"
    if (( COOLDOWN_SECONDS <= 0 )); then
        return 0
    fi
    printf "  %s cooldown %ss%s\n" "$EMOJI_PROGRESS" "$COOLDOWN_SECONDS" "$RESET"
    log "COOLDOWN[$reason]: ${COOLDOWN_SECONDS}s"
    sleep "$COOLDOWN_SECONDS"
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
    local jmg_count="${#JMG_CASES[@]}"
    STEP_TOTAL=0
    local py_base=4
    local py_wrong=0
    local file_unit=2
    if [[ "$SKIP_WRONG" == "1" ]]; then
        file_unit=1
    else
        py_wrong=3
    fi
    STEP_TOTAL=$((STEP_TOTAL + py_base + py_wrong))
    STEP_TOTAL=$((STEP_TOTAL + file_unit * b512_count + file_unit * pb512_count))
    if (( jmg_count > 0 )); then
        STEP_TOTAL=$((STEP_TOTAL + jmg_count))
    fi
    if (( CPP_AVAILABLE == 1 )); then
        local cpp_base=4
        local cpp_wrong=0
        if [[ "$SKIP_WRONG" != "1" ]]; then
            cpp_wrong=3
        fi
        STEP_TOTAL=$((STEP_TOTAL + cpp_base + cpp_wrong))
        STEP_TOTAL=$((STEP_TOTAL + file_unit * b512_count + file_unit * pb512_count))
        if (( jmg_count > 0 )); then
            STEP_TOTAL=$((STEP_TOTAL + jmg_count))
        fi
        if [[ "$SKIP_CROSS" != "1" ]]; then
            STEP_TOTAL=$((STEP_TOTAL + 8))
            STEP_TOTAL=$((STEP_TOTAL + 2 * b512_count + 2 * pb512_count))
            if (( jmg_count > 0 )); then
                STEP_TOTAL=$((STEP_TOTAL + 2 * jmg_count))
            fi
        fi
    fi
}

strip_newline() {
    local path="$1"
    local content
    content="$(cat "$path")"
    printf "%s" "$content" >"$path"
}

hash_file() {
    local path="$1"
    if command -v md5sum >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
        local md5 sha
        md5=$(md5sum "$path" | awk '{print $1}')
        sha=$(sha256sum "$path" | awk '{print $1}')
        printf "%s|%s\n" "$md5" "$sha"
        return 0
    fi
    "$PYTHON_BIN" - "$path" <<'PY'
import hashlib
import sys

path = sys.argv[1]
md5 = hashlib.md5()
sha = hashlib.sha256()
with open(path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        md5.update(chunk)
        sha.update(chunk)
print(f"{md5.hexdigest()}|{sha.hexdigest()}")
PY
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
    log "C++ binary missing or stale; attempting build"
    time_cmd_no_fail "cpp_configure" cmake -S "$ROOT/cpp" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DBASEFWX_REQUIRE_ARGON2=OFF -DBASEFWX_REQUIRE_OQS=OFF
    if [[ ! -d "$build_dir" ]]; then
        log "CMake configure failed; build dir missing"
    fi
    time_cmd_no_fail "cpp_build" cmake --build "$build_dir" --config Release
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
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --no-master --out "$enc" || return $?
    log "STEP: $CPP_BIN fwxaes-dec $enc (wrong pw)"
    "$CPP_BIN" fwxaes-dec "$enc" -p "$BAD_PW" --no-master --out "$dec" >/dev/null 2>&1
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

py_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: python jmg-enc $input"
    "$PYTHON_BIN" "$PY_HELPER" jmg-roundtrip "$input" "$enc" "$dec" "$PW"
}

py_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: python jmg-enc $input"
    "$PYTHON_BIN" "$PY_HELPER" jmg-enc "$input" "$enc" "$PW"
}

py_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: python jmg-dec $input"
    "$PYTHON_BIN" "$PY_HELPER" jmg-dec "$input" "$dec" "$PW"
}

cpp_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN jmge $input"
    "$CPP_BIN" jmge "$input" -p "$PW" --out "$enc" || return $?
    log "STEP: $CPP_BIN jmgd $enc"
    "$CPP_BIN" jmgd "$enc" -p "$PW" --out "$dec"
}

cpp_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: $CPP_BIN jmge $input"
    "$CPP_BIN" jmge "$input" -p "$PW" --out "$enc"
}

cpp_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: $CPP_BIN jmgd $input"
    "$CPP_BIN" jmgd "$input" -p "$PW" --out "$dec"
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

jmg_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_jmg_enc "$input" "$enc" || return $?
    cpp_jmg_dec "$enc" "$dec"
}

jmg_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_jmg_enc "$input" "$enc" || return $?
    py_jmg_dec "$enc" "$dec"
}

rm -rf "$TMP_DIR"
phase "PHASE1: generate temporary files"
mkdir -p "$ORIG_DIR" "$WORK_DIR" "$OUT_DIR"
printf "" >"$LOG"
printf "" >"$VERIFY_LIST"

ensure_venv

log "Python: $("$PYTHON_BIN" --version 2>&1)"
log "C++ binary: $CPP_BIN"
log "FFMPEG_AVAILABLE: $FFMPEG_AVAILABLE"
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
import shutil
import subprocess
from pathlib import Path

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)

mode = os.getenv("TEST_MODE", "default")

text = ("The quick brown fox jumps over the lazy dog. " * 40).encode("ascii")
(root / "tiny.txt").write_bytes(text[:1024])

def write_png(path: Path, size: int) -> None:
    try:
        from PIL import Image
        data = os.urandom(size * size * 3)
        img = Image.frombytes("RGB", (size, size), data)
        img.save(path)
    except Exception:
        path.write_bytes(os.urandom(size * size * 3))

jmg_size = 96 if mode in ("fast", "quickest") else 192
write_png(root / "jmg_sample.png", jmg_size)

if mode not in ("fast", "quickest"):
    (root / "small.bin").write_bytes(os.urandom(64 * 1024))
    (root / "medium.bin").write_bytes(os.urandom(512 * 1024))

    png_path = root / "noise.png"
    write_png(png_path, 320)

ffmpeg = shutil.which("ffmpeg")
if ffmpeg:
    duration = "0.6" if mode == "quickest" else ("1.0" if mode == "fast" else "2.0")
    v_size = "160x160" if mode in ("fast", "quickest") else "320x320"
    mp4_path = root / "jmg_sample.mp4"
    m4a_path = root / "jmg_sample.m4a"
    try:
        subprocess.run(
            [
                ffmpeg, "-y",
                "-f", "lavfi", "-i", f"testsrc=size={v_size}:rate=12",
                "-f", "lavfi", "-i", f"sine=frequency=880:sample_rate=44100",
                "-t", duration,
                "-pix_fmt", "yuv420p",
                "-c:v", "libx264",
                "-preset", "ultrafast",
                "-c:a", "aac",
                "-b:a", "64k",
                str(mp4_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            [
                ffmpeg, "-y",
                "-f", "lavfi", "-i", f"sine=frequency=440:duration={duration}",
                "-c:a", "aac",
                "-b:a", "64k",
                str(m4a_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

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

if mode in ("fast", "quickest"):
    payload = os.urandom(max(1, big_bytes))
    (root / "sample_payload.bin").write_bytes(payload)
    (root / "sample_payload_copy.bin").write_bytes(payload)
else:
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
    basefwx.fwxAES_file(inp, pw, output=enc, use_master=False)
    try:
        basefwx.fwxAES_file(enc, bad_pw, output=dec, use_master=False)
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

def cmd_jmg_roundtrip(args: list[str]) -> int:
    inp, enc, dec, pw = args
    basefwx.MediaCipher.encrypt_media(inp, pw, output=enc)
    basefwx.MediaCipher.decrypt_media(enc, pw, output=dec)
    return 0

def cmd_jmg_enc(args: list[str]) -> int:
    inp, enc, pw = args
    basefwx.MediaCipher.encrypt_media(inp, pw, output=enc)
    return 0

def cmd_jmg_dec(args: list[str]) -> int:
    inp, dec, pw = args
    basefwx.MediaCipher.decrypt_media(inp, pw, output=dec)
    return 0

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
    if cmd == "jmg-roundtrip":
        return cmd_jmg_roundtrip(args)
    if cmd == "jmg-enc":
        return cmd_jmg_enc(args)
    if cmd == "jmg-dec":
        return cmd_jmg_dec(args)
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
PY

phase "PHASE2: run native Python/C++ tests"
ensure_cpp || log "C++ binary unavailable; C++ tests will be marked failed"

FWXAES_FILE="tiny.txt"
if [[ "$TEST_MODE" == "fast" || "$TEST_MODE" == "quickest" ]]; then
    B512FILE_CASES=("sample_payload.bin" "sample_payload_copy.bin")
    PB512FILE_CASES=("sample_payload.bin" "sample_payload_copy.bin")
else
    B512FILE_CASES=("noise.png" "large_36m.bin")
    PB512FILE_CASES=("medium.bin" "large_36m.bin")
    if [[ "$ENABLE_HUGE" == "1" ]]; then
        B512FILE_CASES+=("large_200m.bin")
        PB512FILE_CASES+=("huge_1p2g.bin")
    fi
fi
JMG_CASES=()
for file_name in "jmg_sample.png" "jmg_sample.mp4" "jmg_sample.m4a"; do
    if [[ -f "$ORIG_DIR/$file_name" ]]; then
        JMG_CASES+=("$file_name")
    fi
done
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
    cooldown "fwxaes_py_to_cpp_correct"
    time_cmd "fwxaes_cpp_correct" cpp_fwxAES_roundtrip "$fwxaes_cpp_input" "$fwxaes_cpp_enc" "$fwxaes_cpp_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_cpp_dec"
else
    FAILURES+=("fwxaes_cpp_correct (cpp unavailable)")
fi

# fwxAES wrong password
if [[ "$SKIP_WRONG" != "1" ]]; then
    fwxaes_py_wrong_input="$(copy_input "fwxaes_py_wrong" "$FWXAES_FILE")"
    fwxaes_py_wrong_enc="$(with_suffix "$fwxaes_py_wrong_input" ".fwx")"
    fwxaes_py_wrong_dec="$WORK_DIR/fwxaes_py_wrong/decoded_${FWXAES_FILE}"
    time_cmd "fwxaes_py_wrong" "$PYTHON_BIN" "$PY_HELPER" fwxaes-wrong "$fwxaes_py_wrong_input" "$fwxaes_py_wrong_enc" "$fwxaes_py_wrong_dec" "$PW" "$BAD_PW"

    fwxaes_cpp_wrong_input="$(copy_input "fwxaes_cpp_wrong" "$FWXAES_FILE")"
    fwxaes_cpp_wrong_enc="$(with_suffix "$fwxaes_cpp_wrong_input" ".fwx")"
    fwxaes_cpp_wrong_dec="$WORK_DIR/fwxaes_cpp_wrong/decoded_${FWXAES_FILE}"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "fwxaes_py_to_cpp_wrong"
        time_cmd "fwxaes_cpp_wrong" cpp_fwxAES_wrong "$fwxaes_cpp_wrong_input" "$fwxaes_cpp_wrong_enc" "$fwxaes_cpp_wrong_dec"
    else
        FAILURES+=("fwxaes_cpp_wrong (cpp unavailable)")
    fi
fi

# b256 correct
b256_py_out="$OUT_DIR/b256_py.txt"
time_cmd "b256_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip b256 "$TEXT_ORIG" "$b256_py_out" "$PW"
add_verify "$TEXT_ORIG" "$b256_py_out"

b256_cpp_out="$OUT_DIR/b256_cpp.txt"
if (( CPP_AVAILABLE == 1 )); then
    cooldown "b256_py_to_cpp_correct"
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
    cooldown "b512_py_to_cpp_correct"
    time_cmd "b512_cpp_correct" cpp_text_roundtrip b512 "$TEXT_ORIG" "$b512_cpp_out" "$PW"
    add_verify "$TEXT_ORIG" "$b512_cpp_out"
else
    FAILURES+=("b512_cpp_correct (cpp unavailable)")
fi

# b512 wrong password
if [[ "$SKIP_WRONG" != "1" ]]; then
    time_cmd "b512_py_wrong" "$PYTHON_BIN" "$PY_HELPER" text-wrong b512 "$TEXT_ORIG" "$PW" "$BAD_PW"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "b512_py_to_cpp_wrong"
        time_cmd "b512_cpp_wrong" cpp_text_wrong b512 "$TEXT_ORIG" "$PW" "$OUT_DIR/b512_cpp_wrong.enc"
    else
        FAILURES+=("b512_cpp_wrong (cpp unavailable)")
    fi
fi

# pb512 correct
pb512_py_out="$OUT_DIR/pb512_py.txt"
time_cmd "pb512_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip pb512 "$TEXT_ORIG" "$pb512_py_out" "$PW"
add_verify "$TEXT_ORIG" "$pb512_py_out"

pb512_cpp_out="$OUT_DIR/pb512_cpp.txt"
if (( CPP_AVAILABLE == 1 )); then
    cooldown "pb512_py_to_cpp_correct"
    time_cmd "pb512_cpp_correct" cpp_text_roundtrip pb512 "$TEXT_ORIG" "$pb512_cpp_out" "$PW"
    add_verify "$TEXT_ORIG" "$pb512_cpp_out"
else
    FAILURES+=("pb512_cpp_correct (cpp unavailable)")
fi

# pb512 wrong password
if [[ "$SKIP_WRONG" != "1" ]]; then
    time_cmd "pb512_py_wrong" "$PYTHON_BIN" "$PY_HELPER" text-wrong pb512 "$TEXT_ORIG" "$PW" "$BAD_PW"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "pb512_py_to_cpp_wrong"
        time_cmd "pb512_cpp_wrong" cpp_text_wrong pb512 "$TEXT_ORIG" "$PW" "$OUT_DIR/pb512_cpp_wrong.enc"
    else
        FAILURES+=("pb512_cpp_wrong (cpp unavailable)")
    fi
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
        cooldown "b512file_py_to_cpp_correct_${tag}"
        key="b512file_cpp_correct_${tag}"
        time_cmd "$key" cpp_b512file_roundtrip "$b512file_cpp_input"
        B512FILE_CPP_TOTAL=$((B512FILE_CPP_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$b512file_cpp_input"
    else
        FAILURES+=("b512file_cpp_correct_${tag} (cpp unavailable)")
    fi

    if [[ "$SKIP_WRONG" != "1" ]]; then
        # b512file wrong password
        b512file_py_wrong_input="$(copy_input "b512file_py_wrong_${tag}" "$file_name")"
        time_cmd "b512file_py_wrong_${tag}" py_b512file_wrong "$b512file_py_wrong_input"

        b512file_cpp_wrong_input="$(copy_input "b512file_cpp_wrong_${tag}" "$file_name")"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "b512file_py_to_cpp_wrong_${tag}"
            time_cmd "b512file_cpp_wrong_${tag}" cpp_b512file_wrong "$b512file_cpp_wrong_input"
        else
            FAILURES+=("b512file_cpp_wrong_${tag} (cpp unavailable)")
        fi
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
        cooldown "pb512file_py_to_cpp_correct_${tag}"
        key="pb512file_cpp_correct_${tag}"
        time_cmd "$key" cpp_pb512file_roundtrip "$pb512file_cpp_input"
        PB512FILE_CPP_TOTAL=$((PB512FILE_CPP_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$pb512file_cpp_input"
    else
        FAILURES+=("pb512file_cpp_correct_${tag} (cpp unavailable)")
    fi

    if [[ "$SKIP_WRONG" != "1" ]]; then
        # pb512file wrong password
        pb512file_py_wrong_input="$(copy_input "pb512file_py_wrong_${tag}" "$file_name")"
        time_cmd "pb512file_py_wrong_${tag}" py_pb512file_wrong "$pb512file_py_wrong_input"

        pb512file_cpp_wrong_input="$(copy_input "pb512file_cpp_wrong_${tag}" "$file_name")"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "pb512file_py_to_cpp_wrong_${tag}"
            time_cmd "pb512file_cpp_wrong_${tag}" cpp_pb512file_wrong "$pb512file_cpp_wrong_input"
        else
            FAILURES+=("pb512file_cpp_wrong_${tag} (cpp unavailable)")
        fi
    fi
done

if (( ${#JMG_CASES[@]} > 0 )); then
    phase "PHASE2.1: jMG media tests"
    for file_name in "${JMG_CASES[@]}"; do
        tag="$(case_tag "$file_name")"
        jmg_py_input="$(copy_input "jmg_py_${tag}" "$file_name")"
        jmg_py_enc="$WORK_DIR/jmg_py_${tag}/enc_${file_name}"
        jmg_py_dec="$WORK_DIR/jmg_py_${tag}/dec_${file_name}"
        time_cmd "jmg_py_${tag}" py_jmg_roundtrip "$jmg_py_input" "$jmg_py_enc" "$jmg_py_dec"
        add_verify "$ORIG_DIR/$file_name" "$jmg_py_dec"

        jmg_cpp_input="$(copy_input "jmg_cpp_${tag}" "$file_name")"
        jmg_cpp_enc="$WORK_DIR/jmg_cpp_${tag}/enc_${file_name}"
        jmg_cpp_dec="$WORK_DIR/jmg_cpp_${tag}/dec_${file_name}"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "jmg_py_to_cpp_${tag}"
            time_cmd "jmg_cpp_${tag}" cpp_jmg_roundtrip "$jmg_cpp_input" "$jmg_cpp_enc" "$jmg_cpp_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_cpp_dec"
        else
            FAILURES+=("jmg_cpp_${tag} (cpp unavailable)")
        fi
    done
else
    phase "PHASE2.1: jMG media tests (skipped)"
fi

if [[ "$SKIP_CROSS" == "1" ]]; then
    phase "PHASE2.2: cross-compat tests (skipped)"
else
    phase "PHASE2.2: cross-compat tests"
fi

if [[ "$SKIP_CROSS" != "1" ]]; then
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

    if (( ${#JMG_CASES[@]} > 0 )); then
        for file_name in "${JMG_CASES[@]}"; do
            tag="$(case_tag "$file_name")"
            if (( CPP_AVAILABLE == 1 )); then
                jmg_pycc_input="$(copy_input "jmg_pycc_${tag}" "$file_name")"
                jmg_pycc_enc="$WORK_DIR/jmg_pycc_${tag}/enc_${file_name}"
                jmg_pycc_dec="$WORK_DIR/jmg_pycc_${tag}/dec_${file_name}"
                time_cmd "jmg_py_enc_cpp_dec_${tag}" jmg_py_enc_cpp_dec "$jmg_pycc_input" "$jmg_pycc_enc" "$jmg_pycc_dec"
                add_verify "$ORIG_DIR/$file_name" "$jmg_pycc_dec"

                jmg_cpyp_input="$(copy_input "jmg_cpyp_${tag}" "$file_name")"
                jmg_cpyp_enc="$WORK_DIR/jmg_cpyp_${tag}/enc_${file_name}"
                jmg_cpyp_dec="$WORK_DIR/jmg_cpyp_${tag}/dec_${file_name}"
                time_cmd "jmg_cpp_enc_py_dec_${tag}" jmg_cpp_enc_py_dec "$jmg_cpyp_input" "$jmg_cpyp_enc" "$jmg_cpyp_dec"
                add_verify "$ORIG_DIR/$file_name" "$jmg_cpyp_dec"
            else
                FAILURES+=("jmg_cross_${tag} (cpp unavailable)")
            fi
        done
    fi
fi

phase "PHASE3: verify outputs"
if [[ -f "$VERIFY_LIST" ]]; then
    while IFS="|" read -r orig out; do
        if [[ -z "$orig" || -z "$out" ]]; then
            continue
        fi
        orig_hash="$(hash_file "$orig")"
        out_hash="$(hash_file "$out")"
        if [[ "$orig_hash" != "$out_hash" ]]; then
            log "VERIFY FAIL: $orig vs $out (orig=${orig_hash} out=${out_hash})"
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
        printf "%s: %s missing timing data%s\n" "$label" "$YELLOW$EMOJI_WARN" "$RESET"
        return
    fi
    local py_s cpp_s
    py_s=$(format_ns "$py_ns")
    cpp_s=$(format_ns "$cpp_ns")
    local diff_ns=$((py_ns - cpp_ns))
    if (( diff_ns < 0 )); then
        diff_ns=$((0 - diff_ns))
    fi
    local diff_s
    diff_s=$(format_ns "$diff_ns")
    local pct_raw pct_abs pct_equal display_equal
    pct_raw=$(awk -v py="$py_ns" -v cpp="$cpp_ns" 'BEGIN { if (py <= 0) { printf "0.0"; } else { val=(py-cpp)/py*100; if (val<0) val=-val; printf "%.6f", val; } }')
    pct_abs=$(awk -v v="$pct_raw" 'BEGIN { printf "%.2f", v; }')
    pct_equal=$(awk -v v="$pct_raw" 'BEGIN { if (v < 0.01) print 1; else print 0; }')
    display_equal=0
    if [[ "$py_s" == "$cpp_s" || "$diff_s" == "0.000" ]]; then
        display_equal=1
    fi
    local verdict=""
    if (( pct_equal == 1 || display_equal == 1 )); then
        verdict="${CYAN}☕ equal${RESET}"
    elif (( py_ns >= cpp_ns )); then
        verdict="${GREEN}${EMOJI_FAST} C++ +${pct_abs}% faster${RESET}"
    else
        verdict="${RED}${EMOJI_SLOW} C++ -${pct_abs}% slower${RESET}"
    fi
    printf "%s: Python %ss, C++ %ss, %s (%ss)\n" "$label" "$py_s" "$cpp_s" "$verdict" "$diff_s"
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
    printf "\n%sFAILURES%s (%d):\n" "$RED$EMOJI_FAIL " "$RESET" "${#FAILURES[@]}"
    for failure in "${FAILURES[@]}"; do
        printf " - %s\n" "$failure"
    done
    printf "See diagnose.log for details.\n"
    exit 1
fi

printf "\n%sAll tests passed.%s See diagnose.log for details.\n" "$GREEN$EMOJI_OK " "$RESET"
exit 0
