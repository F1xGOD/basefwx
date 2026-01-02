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
RUN_PY_TESTS="${RUN_PY_TESTS:-1}"
CPP_BIN="$ROOT/cpp/build/basefwx_cpp"
RUN_CPP_TESTS="${RUN_CPP_TESTS:-1}"
JAVA_DIR="$ROOT/java"
JAVA_BUILD_DIR="$JAVA_DIR/build"
JAVA_JAR="$JAVA_BUILD_DIR/libs/basefwx-java.jar"
JAVA_BIN="${JAVA_BIN:-}"
JAVAC_BIN="${JAVAC_BIN:-}"
JAR_BIN="${JAR_BIN:-}"
RUN_JAVA_TESTS="${RUN_JAVA_TESTS:-1}"
PYPY_BIN="${PYPY_BIN:-}"
RUN_PYPY_TESTS="${RUN_PYPY_TESTS:-1}"
PY_VERSION_TAG=""
PYPY_VERSION_TAG=""
CPP_VERSION_TAG=""
JAVA_VERSION_TAG=""
TIME_BIN="${TIME_BIN:-}"

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
BASELINE_LANG="${BASELINE_LANG:-py}"
EXPECT_BASELINE=0

for arg in "$@"; do
    if (( EXPECT_BASELINE == 1 )); then
        BASELINE_LANG="$arg"
        EXPECT_BASELINE=0
        continue
    fi
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
        --baseline)
            EXPECT_BASELINE=1
            ;;
        --baseline=*)
            BASELINE_LANG="${arg#*=}"
            ;;
    esac
done
if [[ "$TEST_MODE" != "default" ]]; then
    ENABLE_HUGE=0
fi
if (( EXPECT_BASELINE == 1 )); then
    BASELINE_LANG="py"
fi
BASELINE_LANG="$(printf "%s" "$BASELINE_LANG" | tr '[:upper:]' '[:lower:]')"
case "$BASELINE_LANG" in
    py|python)
        BASELINE_LANG="py"
        ;;
    pypy)
        BASELINE_LANG="pypy"
        ;;
    cpp|c++)
        BASELINE_LANG="cpp"
        ;;
    java|jvm)
        BASELINE_LANG="java"
        ;;
    *)
        BASELINE_LANG="py"
        ;;
esac

RUN_PY_TESTS_ORIG="$RUN_PY_TESTS"
RUN_PYPY_TESTS_ORIG="$RUN_PYPY_TESTS"
RUN_CPP_TESTS_ORIG="$RUN_CPP_TESTS"
RUN_JAVA_TESTS_ORIG="$RUN_JAVA_TESTS"

if [[ -z "$TIME_BIN" && -x /usr/bin/time ]]; then
    TIME_BIN="/usr/bin/time"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export BASEFWX_USER_KDF="pbkdf2"
export BASEFWX_B512_AEAD="1"
export BASEFWX_OBFUSCATE="1"
export BASEFWX_OBFUSCATE_CODECS="1"
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
INTRA_LANG_COOLDOWN="${INTRA_LANG_COOLDOWN:-0}"

LANG_COOLDOWN_SECONDS="${LANG_COOLDOWN_SECONDS:-3}"
if [[ ! "$LANG_COOLDOWN_SECONDS" =~ ^[0-9]+$ ]]; then
    LANG_COOLDOWN_SECONDS=3
fi

FFMPEG_AVAILABLE=0
if command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
    FFMPEG_AVAILABLE=1
fi
export FFMPEG_AVAILABLE COOLDOWN_SECONDS

TEXT_NOPASS_METHODS=("b64" "b256" "a512")
TEXT_PASS_METHODS=("b512" "pb512")
HASH_METHODS=("hash512" "uhash513" "bi512" "b1024")

declare -A TIMES
FAILURES=()
CPP_AVAILABLE=1
JAVA_AVAILABLE=1
PYPY_AVAILABLE=1
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
EMOJI_SLOW="🐌"
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
    local start_ns end_ns dur_ns rc real_s time_file
    announce_step "$key"
    log "CMD[$key]: $*"
    start_ns=$(date +%s%N)
    local cmd_type=""
    if declare -F "$1" >/dev/null 2>&1; then
        cmd_type="function"
    else
        cmd_type="$(type -t "$1" || true)"
    fi
    if [[ -n "$TIME_BIN" && "$cmd_type" == "file" ]]; then
        time_file="$TMP_DIR/time_${key}.txt"
        rm -f "$time_file"
        run_with_heartbeat "$key" "$TIME_BIN" -p -o "$time_file" "$@"
        rc=$?
        end_ns=$(date +%s%N)
        if [[ -f "$time_file" ]]; then
            real_s="$(awk '$1=="real"{print $2}' "$time_file")"
        fi
        if [[ -n "$real_s" ]]; then
            dur_ns="$(awk -v t="$real_s" 'BEGIN { printf "%.0f", t * 1000000000 }')"
        else
            dur_ns=$((end_ns - start_ns))
        fi
    else
        run_with_heartbeat "$key" "$@"
        rc=$?
        end_ns=$(date +%s%N)
        dur_ns=$((end_ns - start_ns))
    fi
    TIMES["$key"]=$dur_ns
    log "TIME[$key]: ${dur_ns}ns rc=${rc}"
    if (( rc != 0 )); then
        FAILURES+=("$key (rc=$rc)")
    fi
    return $rc
}

time_cmd_bench() {
    local key="$1"
    shift
    local output rc bench_ns
    announce_step "$key"
    log "CMD[$key]: $*"
    output="$("$@" 2>>"$LOG")"
    rc=$?
    if [[ -n "$output" ]]; then
        log "$output"
    fi
    bench_ns="$(printf "%s" "$output" | awk -F= '/BENCH_NS=/{print $2; exit}')"
    if [[ -z "$bench_ns" ]]; then
        log "TIME[$key]: missing BENCH_NS rc=${rc}"
        if (( rc == 0 )); then
            rc=1
        fi
        FAILURES+=("$key (bench missing)")
        return $rc
    fi
    TIMES["$key"]=$bench_ns
    log "TIME[$key]: ${bench_ns}ns rc=${rc}"
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
    if (( STEP_TOTAL > 0 && STEP_INDEX > STEP_TOTAL )); then
        STEP_TOTAL=$STEP_INDEX
    fi
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
    if [[ "${INTRA_LANG_COOLDOWN:-1}" == "0" ]]; then
        return 0
    fi
    if (( COOLDOWN_SECONDS <= 0 )); then
        return 0
    fi
    printf "  %s cooldown %ss%s\n" "$EMOJI_PROGRESS" "$COOLDOWN_SECONDS" "$RESET"
    log "COOLDOWN[$reason]: ${COOLDOWN_SECONDS}s"
    sleep "$COOLDOWN_SECONDS"
}

lang_cooldown() {
    local reason="$1"
    if (( LANG_COOLDOWN_SECONDS <= 0 )); then
        return 0
    fi
    printf "  %s cooldown %ss%s\n" "$EMOJI_PROGRESS" "$LANG_COOLDOWN_SECONDS" "$RESET"
    log "LANG_COOLDOWN[$reason]: ${LANG_COOLDOWN_SECONDS}s"
    sleep "$LANG_COOLDOWN_SECONDS"
}

ensure_venv() {
    local pip_cmd
    if [[ "$USE_VENV" != "1" ]]; then
        if [[ -z "$PYTHON_BIN" ]]; then
            PYTHON_BIN="$(command -v python3 || command -v python || true)"
        fi
        if [[ -z "$PYTHON_BIN" ]]; then
            RUN_PY_TESTS=0
            log "Python: unavailable (no interpreter)"
            return 1
        fi
        pip_cmd=("$PYTHON_BIN" "-m" "pip")
        time_cmd_no_fail "venv_pip" "${pip_cmd[@]}" install -U pip setuptools wheel
        time_cmd_no_fail "venv_install" "${pip_cmd[@]}" install -e "$ROOT"
        return 0
    fi
    if [[ ! -x "$VENV_PY" ]]; then
        time_cmd_no_fail "venv_create" python3 -m venv "$VENV_DIR"
    fi
    if [[ -x "$VENV_PY" ]]; then
        PYTHON_BIN="$VENV_PY"
        pip_cmd=("$PYTHON_BIN" "-m" "pip")
    else
        PYTHON_BIN="$(command -v python3 || command -v python || true)"
        if [[ -z "$PYTHON_BIN" ]]; then
            RUN_PY_TESTS=0
            log "Python: unavailable (venv creation failed)"
            return 1
        fi
        pip_cmd=("$PYTHON_BIN" "-m" "pip")
    fi
    time_cmd_no_fail "venv_pip" "${pip_cmd[@]}" install -U pip setuptools wheel
    time_cmd_no_fail "venv_install" "${pip_cmd[@]}" install -e "$ROOT"
    return 0
}

add_verify() {
    printf "%s|%s\n" "$1" "$2" >>"$VERIFY_LIST"
}

compare_outputs() {
    local label="$1"
    local first="$2"
    local second="$3"
    if [[ ! -f "$first" || ! -f "$second" ]]; then
        log "VERIFY FAIL: missing output for $label ($first, $second)"
        FAILURES+=("verify_mismatch ($label)")
        return
    fi
    local hash_a hash_b
    hash_a="$(hash_file "$first")"
    hash_b="$(hash_file "$second")"
    if [[ "$hash_a" != "$hash_b" ]]; then
        log "VERIFY FAIL: $label (${hash_a} != ${hash_b})"
        FAILURES+=("verify_mismatch ($label)")
    fi
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
    local nopass_count="${#TEXT_NOPASS_METHODS[@]}"
    local pass_count="${#TEXT_PASS_METHODS[@]}"
    local hash_count="${#HASH_METHODS[@]}"
    local reversible_count=$((nopass_count + pass_count))
    STEP_TOTAL=0
    local file_unit=2
    if [[ "$SKIP_WRONG" == "1" ]]; then
        file_unit=1
    fi
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        local py_base=$((1 + nopass_count + pass_count + hash_count))
        local py_wrong=0
        if [[ "$SKIP_WRONG" != "1" ]]; then
            py_wrong=$((1 + pass_count))
        fi
        STEP_TOTAL=$((STEP_TOTAL + py_base + py_wrong))
        STEP_TOTAL=$((STEP_TOTAL + file_unit * b512_count + file_unit * pb512_count))
        STEP_TOTAL=$((STEP_TOTAL + 3))
        if (( jmg_count > 0 )); then
            STEP_TOTAL=$((STEP_TOTAL + jmg_count))
        fi
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        local pypy_base=$((1 + nopass_count + pass_count + hash_count))
        STEP_TOTAL=$((STEP_TOTAL + pypy_base))
        STEP_TOTAL=$((STEP_TOTAL + b512_count + pb512_count))
        STEP_TOTAL=$((STEP_TOTAL + 2))
        if (( jmg_count > 0 )); then
            STEP_TOTAL=$((STEP_TOTAL + jmg_count))
        fi
    fi
    if [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
        local cpp_base=$((1 + nopass_count + pass_count + hash_count))
        local cpp_wrong=0
        if [[ "$SKIP_WRONG" != "1" ]]; then
            cpp_wrong=$((1 + pass_count))
        fi
        STEP_TOTAL=$((STEP_TOTAL + cpp_base + cpp_wrong))
        STEP_TOTAL=$((STEP_TOTAL + file_unit * b512_count + file_unit * pb512_count))
        STEP_TOTAL=$((STEP_TOTAL + 3))
        if (( jmg_count > 0 )); then
            STEP_TOTAL=$((STEP_TOTAL + jmg_count))
        fi
    fi
    if [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
        local java_base=$((1 + nopass_count + pass_count + hash_count))
        local java_wrong=0
        if [[ "$SKIP_WRONG" != "1" ]]; then
            java_wrong=$((1 + pass_count))
        fi
        STEP_TOTAL=$((STEP_TOTAL + java_base + java_wrong))
        STEP_TOTAL=$((STEP_TOTAL + file_unit * b512_count + file_unit * pb512_count))
        STEP_TOTAL=$((STEP_TOTAL + 3))
    fi
    if [[ "$SKIP_CROSS" != "1" ]]; then
        if [[ "$RUN_PY_TESTS" == "1" && "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
            STEP_TOTAL=$((STEP_TOTAL + 2 * reversible_count + 2))
            STEP_TOTAL=$((STEP_TOTAL + 2 * b512_count + 2 * pb512_count))
            if (( jmg_count > 0 )); then
                STEP_TOTAL=$((STEP_TOTAL + 2 * jmg_count))
            fi
        fi
        if [[ "$RUN_PY_TESTS" == "1" && "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
            STEP_TOTAL=$((STEP_TOTAL + 2 * reversible_count + 2))
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
import time

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

ensure_java() {
    if [[ ! -d "$JAVA_DIR" ]]; then
        JAVA_AVAILABLE=0
        FAILURES+=("java_build (java module missing)")
        return 1
    fi
    JAVA_BIN="${JAVA_BIN:-$(command -v java || true)}"
    JAVAC_BIN="${JAVAC_BIN:-$(command -v javac || true)}"
    JAR_BIN="${JAR_BIN:-$(command -v jar || true)}"
    if [[ -z "$JAVA_BIN" || -z "$JAVAC_BIN" || -z "$JAR_BIN" ]]; then
        JAVA_AVAILABLE=0
        FAILURES+=("java_build (java tools missing)")
        return 1
    fi
    local sources
    sources=()
    while IFS= read -r -d '' file; do
        sources+=("$file")
    done < <(find "$JAVA_DIR/src/main/java" -type f -name "*.java" -print0)
    if (( ${#sources[@]} == 0 )); then
        JAVA_AVAILABLE=0
        FAILURES+=("java_build (no sources)")
        return 1
    fi
    local needs_build=0
    if [[ ! -f "$JAVA_JAR" ]]; then
        needs_build=1
    else
        for src in "${sources[@]}"; do
            if [[ "$src" -nt "$JAVA_JAR" ]]; then
                needs_build=1
                break
            fi
        done
    fi
    if (( needs_build == 1 )); then
        mkdir -p "$JAVA_BUILD_DIR/classes" "$JAVA_BUILD_DIR/libs"
        if ! time_cmd_no_fail "java_build" "$JAVAC_BIN" -source 8 -target 8 -d "$JAVA_BUILD_DIR/classes" "${sources[@]}"; then
            JAVA_AVAILABLE=0
            FAILURES+=("java_build (compile failed)")
            return 1
        fi
        if ! time_cmd_no_fail "java_jar" "$JAR_BIN" cfe "$JAVA_JAR" com.fixcraft.basefwx.cli.BaseFwxCli -C "$JAVA_BUILD_DIR/classes" .; then
            JAVA_AVAILABLE=0
            FAILURES+=("java_build (jar failed)")
            return 1
        fi
    fi
    if [[ ! -f "$JAVA_JAR" ]]; then
        JAVA_AVAILABLE=0
        FAILURES+=("java_build (jar missing)")
        return 1
    fi
    local java_line
    java_line="$("$JAVA_BIN" -version 2>&1 | head -n 1)"
    JAVA_VERSION_TAG="$(printf "%s" "$java_line" | sed -E 's/.*version \"([^\"]+)\".*/java\1/')"
    if [[ -z "$JAVA_VERSION_TAG" || "$JAVA_VERSION_TAG" == "$java_line" ]]; then
        JAVA_VERSION_TAG="java"
    fi
    return 0
}

ensure_pypy() {
    if [[ -z "$PYPY_BIN" ]]; then
        PYPY_BIN="$(command -v pypy3 || true)"
    fi
    if [[ -z "$PYPY_BIN" ]]; then
        PYPY_BIN="$(command -v pypy || true)"
    fi
    if [[ -z "$PYPY_BIN" ]]; then
        for candidate in "$HOME"/pypy/*/bin/pypy3 "$HOME"/pypy/*/bin/pypy; do
            if [[ -x "$candidate" ]]; then
                PYPY_BIN="$candidate"
                break
            fi
        done
    fi
    if [[ -z "$PYPY_BIN" ]]; then
        PYPY_AVAILABLE=0
        log "PyPy: unavailable"
        return 1
    fi
    local pypy_check
    pypy_check="$("$PYPY_BIN" - <<'PY' 2>&1
import basefwx
from basefwx.main import basefwx
print(basefwx.ENGINE_VERSION)
PY
)"
    local pypy_rc=$?
    if (( pypy_rc != 0 )); then
        PYPY_AVAILABLE=0
        log "PyPy: unavailable (import failed)"
        log "$pypy_check"
        return 1
    fi
    log "PyPy engine: $pypy_check"
    PYPY_VERSION_TAG="$("$PYPY_BIN" - <<'PY' 2>/dev/null
import sys
info = getattr(sys, "pypy_version_info", None)
if info:
    print(f"pypy{info.major}.{info.minor}.{info.micro}")
else:
    print("pypy")
PY
)"
    if [[ -z "$PYPY_VERSION_TAG" ]]; then
        PYPY_VERSION_TAG="pypy"
    fi
    log "PyPy: $("$PYPY_BIN" -V 2>&1 | head -n 1)"
    return 0
}

cpp_fwxAES_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-enc $input"
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --no-master --out "$enc"
    local rc=$?
    if (( rc != 0 )); then
        return $rc
    fi
    log "STEP: $CPP_BIN fwxaes-dec $enc"
    "$CPP_BIN" fwxaes-dec "$enc" -p "$PW" --no-master --out "$dec"
}

cpp_fwxAES_stream_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-stream-enc $input"
    "$CPP_BIN" fwxaes-stream-enc "$input" -p "$PW" --no-master --out "$enc" || return $?
    log "STEP: $CPP_BIN fwxaes-stream-dec $enc"
    "$CPP_BIN" fwxaes-stream-dec "$enc" -p "$PW" --no-master --out "$dec"
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
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $CPP_BIN ${method}-enc"
        "$CPP_BIN" "${method}-enc" "$text" >"$enc_file" || return $?
        local enc
        enc="$(cat "$enc_file")"
        log "STEP: $CPP_BIN ${method}-dec"
        "$CPP_BIN" "${method}-dec" "$enc" >"$out_path" || return $?
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
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $CPP_BIN ${method}-enc"
        "$CPP_BIN" "${method}-enc" "$text" >"$enc_file" || return $?
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
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $CPP_BIN ${method}-dec"
        "$CPP_BIN" "${method}-dec" "$enc" >"$out_path" || return $?
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

cpp_text_hash() {
    local method="$1"
    local text_path="$2"
    local out_path="$3"
    local text
    text="$(cat "$text_path")"
    local cmd="$method"
    if [[ "$method" == "bi512" ]]; then
        cmd="bi512-enc"
    elif [[ "$method" == "b1024" ]]; then
        cmd="b1024-enc"
    fi
    log "STEP: $CPP_BIN $cmd"
    "$CPP_BIN" "$cmd" "$text" >"$out_path" || return $?
    strip_newline "$out_path"
}

java_fwxAES_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-dec $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-dec "$enc" "$dec" "$PW" --no-master
}

java_fwxAES_stream_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-stream-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-stream-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-stream-dec $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-stream-dec "$enc" "$dec" "$PW" --no-master
}

java_fwxAES_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-enc "$input" "$enc" "$PW" --no-master
}

java_fwxAES_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-dec $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-dec "$input" "$dec" "$PW" --no-master
}

java_fwxAES_wrong() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR fwxaes-dec $enc (wrong pw)"
    "$JAVA_BIN" -jar "$JAVA_JAR" fwxaes-dec "$enc" "$dec" "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for fwxaes wrong password (java)"
        return 1
    fi
    return 0
}

java_text_roundtrip() {
    local method="$1"
    local text_path="$2"
    local out_path="$3"
    local pw="$4"
    local enc_file="${out_path}.enc"
    local text
    text="$(cat "$text_path")"
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-enc"
        "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-enc" "$text" >"$enc_file" || return $?
        local enc
        enc="$(cat "$enc_file")"
        log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-dec"
        "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-dec" "$enc" >"$out_path" || return $?
        strip_newline "$out_path"
        return 0
    fi
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-enc" "$text" "$pw" --no-master >"$enc_file" || return $?
    local enc
    enc="$(cat "$enc_file")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-dec"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-dec" "$enc" "$pw" --no-master >"$out_path" || return $?
    strip_newline "$out_path"
}

java_text_encode() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local pw="$4"
    local text
    text="$(cat "$text_path")"
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-enc"
        "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-enc" "$text" >"$enc_file" || return $?
        strip_newline "$enc_file"
        return $?
    fi
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-enc" "$text" "$pw" --no-master >"$enc_file" || return $?
    strip_newline "$enc_file"
}

java_text_decode() {
    local method="$1"
    local enc_file="$2"
    local out_path="$3"
    local pw="$4"
    local enc
    enc="$(cat "$enc_file")"
    if [[ "$method" == "b256" || "$method" == "b64" || "$method" == "a512" ]]; then
        log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-dec"
        "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-dec" "$enc" >"$out_path" || return $?
        strip_newline "$out_path"
        return 0
    fi
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-dec"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-dec" "$enc" "$pw" --no-master >"$out_path" || return $?
    strip_newline "$out_path"
}

java_text_wrong() {
    local method="$1"
    local text_path="$2"
    local pw="$3"
    local enc_file="$4"
    local text
    text="$(cat "$text_path")"
    if [[ "$method" == "b256" ]]; then
        return 0
    fi
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-enc" "$text" "$pw" --no-master >"$enc_file" || return $?
    local enc
    enc="$(cat "$enc_file")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR ${method}-dec (wrong pw)"
    "$JAVA_BIN" -jar "$JAVA_JAR" "${method}-dec" "$enc" "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for ${method} wrong password (java)"
        return 1
    fi
    return 0
}

java_text_hash() {
    local method="$1"
    local text_path="$2"
    local out_path="$3"
    local text
    text="$(cat "$text_path")"
    local cmd="$method"
    if [[ "$method" == "bi512" ]]; then
        cmd="bi512-enc"
    elif [[ "$method" == "b1024" ]]; then
        cmd="b1024-enc"
    fi
    log "STEP: $JAVA_BIN -jar $JAVA_JAR $cmd"
    "$JAVA_BIN" -jar "$JAVA_JAR" "$cmd" "$text" >"$out_path" || return $?
    strip_newline "$out_path"
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

pypy_b512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: pypy -m basefwx cryptin b512 $input"
    "$PYPY_BIN" -m basefwx cryptin b512 "$input" -p "$PW" --no-master || return $?
    log "STEP: pypy -m basefwx cryptin b512 $enc"
    "$PYPY_BIN" -m basefwx cryptin b512 "$enc" -p "$PW" --no-master
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

java_b512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR b512file-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" b512file-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR b512file-dec $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" b512file-dec "$enc" "$input" "$PW" --no-master
}

py_b512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: python b512file-bytes $input"
    "$PYTHON_BIN" "$PY_HELPER" b512file-bytes-roundtrip "$input" "$out" "$PW"
}

pypy_b512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: pypy b512file-bytes $input"
    "$PYPY_BIN" "$PY_HELPER" b512file-bytes-roundtrip "$input" "$out" "$PW"
}

py_pb512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: python pb512file-bytes $input"
    "$PYTHON_BIN" "$PY_HELPER" pb512file-bytes-roundtrip "$input" "$out" "$PW"
}

pypy_pb512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: pypy pb512file-bytes $input"
    "$PYPY_BIN" "$PY_HELPER" pb512file-bytes-roundtrip "$input" "$out" "$PW"
}

cpp_b512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN b512file-bytes-rt $input"
    "$CPP_BIN" b512file-bytes-rt "$input" "$out" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

cpp_pb512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN pb512file-bytes-rt $input"
    "$CPP_BIN" pb512file-bytes-rt "$input" "$out" -p "$PW" --no-master --kdf pbkdf2 --pbkdf2-iters "$PBKDF2_ITERS"
}

java_b512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR b512file-bytes-rt $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" b512file-bytes-rt "$input" "$out" "$PW" --no-master
}

java_pb512file_bytes_roundtrip() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR pb512file-bytes-rt $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" pb512file-bytes-rt "$input" "$out" "$PW" --no-master
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

java_b512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR b512file-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" b512file-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR b512file-dec $enc (wrong pw)"
    "$JAVA_BIN" -jar "$JAVA_JAR" b512file-dec "$enc" "$input" "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for b512file wrong password (java)"
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

pypy_pb512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: pypy -m basefwx cryptin pb512 $input"
    "$PYPY_BIN" -m basefwx cryptin pb512 "$input" -p "$PW" --no-master || return $?
    log "STEP: pypy -m basefwx cryptin pb512 $enc"
    "$PYPY_BIN" -m basefwx cryptin pb512 "$enc" -p "$PW" --no-master
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

java_pb512file_roundtrip() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR pb512file-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" pb512file-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR pb512file-dec $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" pb512file-dec "$enc" "$input" "$PW" --no-master
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

java_pb512file_wrong() {
    local input="$1"
    local enc
    enc="$(with_suffix "$input" ".fwx")"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR pb512file-enc $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" pb512file-enc "$input" "$enc" "$PW" --no-master || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR pb512file-dec $enc (wrong pw)"
    "$JAVA_BIN" -jar "$JAVA_JAR" pb512file-dec "$enc" "$input" "$BAD_PW" --no-master >/dev/null 2>&1
    local rc=$?
    if (( rc == 0 )); then
        log "Unexpected success for pb512file wrong password (java)"
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

pypy_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: pypy jmg-enc $input"
    "$PYPY_BIN" "$PY_HELPER" jmg-roundtrip "$input" "$enc" "$dec" "$PW"
}

py_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: python jmg-enc $input"
    "$PYTHON_BIN" "$PY_HELPER" jmg-enc "$input" "$enc" "$PW"
}

pypy_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: pypy jmg-enc $input"
    "$PYPY_BIN" "$PY_HELPER" jmg-enc "$input" "$enc" "$PW"
}

py_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: python jmg-dec $input"
    "$PYTHON_BIN" "$PY_HELPER" jmg-dec "$input" "$dec" "$PW"
}

pypy_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: pypy jmg-dec $input"
    "$PYPY_BIN" "$PY_HELPER" jmg-dec "$input" "$dec" "$PW"
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
    "$CPP_BIN" fwxaes-dec "$enc" -p "$PW" --no-master --out "$dec"
}

fwxaes_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN fwxaes-enc $input"
    "$CPP_BIN" fwxaes-enc "$input" -p "$PW" --no-master --out "$enc" || return $?
    log "STEP: python fwxaes-dec $enc"
    "$PYTHON_BIN" "$PY_HELPER" fwxaes-dec "$enc" "$dec" "$PW"
}

fwxaes_py_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: python fwxaes-enc $input"
    "$PYTHON_BIN" "$PY_HELPER" fwxaes-enc "$input" "$enc" "$PW" || return $?
    java_fwxAES_dec "$enc" "$dec"
}

fwxaes_java_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_fwxAES_enc "$input" "$enc" || return $?
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

text_py_enc_java_dec() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local out_path="$4"
    log "STEP: python text-encode $method"
    "$PYTHON_BIN" "$PY_HELPER" text-encode "$method" "$text_path" "$enc_file" "$PW" || return $?
    java_text_decode "$method" "$enc_file" "$out_path" "$PW"
}

text_java_enc_py_dec() {
    local method="$1"
    local text_path="$2"
    local enc_file="$3"
    local out_path="$4"
    java_text_encode "$method" "$text_path" "$enc_file" "$PW" || return $?
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

if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
    fallback_py="$(command -v python3 || command -v python || true)"
    if [[ -n "$fallback_py" ]]; then
        PYTHON_BIN="$fallback_py"
    fi
fi
if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
    FAILURES+=("python_unavailable (no interpreter)")
    printf "\nFAILURES (%d):\n" "${#FAILURES[@]}"
    for failure in "${FAILURES[@]}"; do
        printf " - %s\n" "$failure"
    done
    printf "See diagnose.log for details.\n"
    exit 1
fi

log "Python: $("$PYTHON_BIN" --version 2>&1)"
log "C++ binary: $CPP_BIN"
if [[ -z "$JAVA_BIN" ]]; then
    JAVA_BIN="$(command -v java || true)"
fi
if [[ -n "$JAVA_BIN" ]]; then
    log "Java: $("$JAVA_BIN" -version 2>&1 | head -n 1)"
    log "Java jar: $JAVA_JAR"
else
    log "Java: unavailable"
fi
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
ENGINE_VERSION="$("$PYTHON_BIN" - <<'PY' 2>>"$LOG"
from basefwx.main import basefwx
print(basefwx.ENGINE_VERSION)
PY
)"
if [[ -z "$ENGINE_VERSION" ]]; then
    ENGINE_VERSION="unknown"
fi
PY_VERSION_TAG="$("$PYTHON_BIN" - <<'PY' 2>>"$LOG"
import sys
print(f"py{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
PY
)"
if [[ -z "$PY_VERSION_TAG" ]]; then
    PY_VERSION_TAG="py"
fi
CPP_VERSION_TAG="$ENGINE_VERSION"
if [[ -n "$CPP_VERSION_TAG" && "$CPP_VERSION_TAG" != "unknown" && "$CPP_VERSION_TAG" != v* ]]; then
    CPP_VERSION_TAG="v${CPP_VERSION_TAG}"
fi

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
    duration = "1.0"
    fps = "24"
    v_size = "128x72"
    mp4_path = root / "jmg_sample.mp4"
    m4a_path = root / "jmg_sample.m4a"
    try:
        subprocess.run(
            [
                ffmpeg, "-y",
                "-f", "lavfi", "-i", f"testsrc=size={v_size}:rate={fps}",
                "-f", "lavfi", "-i", f"sine=frequency=880:sample_rate=44100",
                "-t", duration,
                "-r", fps,
                "-pix_fmt", "yuv420p",
                "-c:v", "libx264",
                "-preset", "ultrafast",
                "-crf", "38",
                "-b:v", "90k",
                "-maxrate", "90k",
                "-bufsize", "180k",
                "-c:a", "aac",
                "-b:a", "24k",
                "-movflags", "+faststart",
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
                "-b:a", "32k",
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
    printf "\n---- diagnose.log ----\n"
    cat "$LOG"
    exit 1
fi

cat >"$PY_HELPER" <<'PY'
import sys
import time
import tempfile
from pathlib import Path
import basefwx as basefwx_mod
from basefwx.main import basefwx

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()

def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)

def text_encode(method: str, text: str, pw: str) -> str:
    if method == "b64":
        return basefwx.b64encode(text)
    if method == "b256":
        return basefwx.b256encode(text)
    if method == "a512":
        return basefwx.a512encode(text)
    if method == "b512":
        return basefwx.b512encode(text, pw, use_master=False)
    if method == "pb512":
        return basefwx.pb512encode(text, pw, use_master=False)
    raise ValueError(f"Unsupported method {method}")

def text_decode(method: str, enc: str, pw: str) -> str:
    if method == "b64":
        return basefwx.b64decode(enc)
    if method == "b256":
        return basefwx.b256decode(enc)
    if method == "a512":
        return basefwx.a512decode(enc)
    if method == "b512":
        return basefwx.b512decode(enc, pw, use_master=False)
    if method == "pb512":
        return basefwx.pb512decode(enc, pw, use_master=False)
    raise ValueError(f"Unsupported method {method}")

def text_hash(method: str, text: str) -> str:
    if method == "hash512":
        return basefwx.hash512(text)
    if method == "uhash513":
        return basefwx.uhash513(text)
    if method == "bi512":
        return basefwx.bi512encode(text)
    if method == "b1024":
        return basefwx.b1024encode(text)
    raise ValueError(f"Unsupported hash method {method}")

def _fwxaes_call(path: str, pw: str, output: str) -> None:
    basefwx_mod.fwxAES(
        path,
        pw,
        output=output,
        use_master=False,
        light=False,
        legacy=False,
    )

def cmd_fwxaes_roundtrip(args: list[str]) -> int:
    inp, enc, dec, pw = args
    _fwxaes_call(inp, pw, enc)
    _fwxaes_call(enc, pw, dec)
    return 0

def cmd_fwxaes_enc(args: list[str]) -> int:
    inp, enc, pw = args
    _fwxaes_call(inp, pw, enc)
    return 0

def cmd_fwxaes_dec(args: list[str]) -> int:
    inp, dec, pw = args
    _fwxaes_call(inp, pw, dec)
    return 0

def cmd_fwxaes_wrong(args: list[str]) -> int:
    inp, enc, dec, pw, bad_pw = args
    _fwxaes_call(inp, pw, enc)
    try:
        _fwxaes_call(enc, bad_pw, dec)
    except Exception:
        return 0
    return 1

def cmd_fwxaes_stream_roundtrip(args: list[str]) -> int:
    inp, enc, dec, pw = args
    with open(inp, "rb") as src, open(enc, "wb") as dst:
        basefwx_mod.fwxAES_encrypt_stream(src, dst, pw, use_master=False)
    with open(enc, "rb") as src, open(dec, "wb") as dst:
        basefwx_mod.fwxAES_decrypt_stream(src, dst, pw, use_master=False)
    return 0

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

def cmd_text_hash(args: list[str]) -> int:
    method, text_path, out_path = args
    text = read_text(text_path)
    digest = text_hash(method, text)
    write_text(out_path, digest)
    return 0

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

def cmd_b512file_bytes_roundtrip(args: list[str]) -> int:
    inp, out_path, pw = args
    data = Path(inp).read_bytes()
    ext = Path(inp).suffix
    blob = basefwx_mod.b512file_encode_bytes(data, ext, pw, use_master=False)
    decoded, _ext = basefwx_mod.b512file_decode_bytes(blob, pw, use_master=False)
    Path(out_path).write_bytes(decoded)
    return 0

def cmd_pb512file_bytes_roundtrip(args: list[str]) -> int:
    inp, out_path, pw = args
    data = Path(inp).read_bytes()
    ext = Path(inp).suffix
    blob = basefwx_mod.pb512file_encode_bytes(data, ext, pw, use_master=False)
    decoded, _ext = basefwx_mod.pb512file_decode_bytes(blob, pw, use_master=False)
    Path(out_path).write_bytes(decoded)
    return 0

def _bench(warmup: int, fn) -> None:
    if warmup < 0:
        warmup = 0
    for _ in range(warmup):
        fn()
    start = time.perf_counter_ns()
    fn()
    end = time.perf_counter_ns()
    print(f"BENCH_NS={end - start}")

def _warmup_env(default: int = 0) -> int:
    value = basefwx.os.getenv("BASEFWX_BENCH_WARMUP")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default

def cmd_bench_text(args: list[str]) -> int:
    if len(args) < 3:
        return 2
    method, text_path, pw = args[:3]
    text = read_text(text_path)
    warmup = _warmup_env()
    def run() -> int:
        enc = text_encode(method, text, pw)
        dec = text_decode(method, enc, pw)
        return len(dec)
    _bench(warmup, run)
    return 0

def cmd_bench_hash(args: list[str]) -> int:
    if len(args) < 2:
        return 2
    method, text_path = args[:2]
    text = read_text(text_path)
    warmup = _warmup_env()
    def run() -> int:
        digest = text_hash(method, text)
        return len(digest)
    _bench(warmup, run)
    return 0

def cmd_bench_fwxaes(args: list[str]) -> int:
    if len(args) < 2:
        return 2
    inp, pw = args[:2]
    data = Path(inp).read_bytes()
    warmup = _warmup_env()
    def run() -> int:
        blob = basefwx.fwxAES_encrypt_raw(data, pw, use_master=False)
        plain = basefwx.fwxAES_decrypt_raw(blob, pw, use_master=False)
        return len(plain)
    _bench(warmup, run)
    return 0

def cmd_bench_b512file(args: list[str]) -> int:
    if len(args) < 2:
        return 2
    inp, pw = args[:2]
    warmup = _warmup_env()
    source = Path(inp)
    with tempfile.TemporaryDirectory(prefix="basefwx-bench-") as tmpdir:
        tmp = Path(tmpdir)
        enc_path = tmp / "bench.fwx"
        def run() -> int:
            basefwx._b512_encode_path(
                source,
                pw,
                use_master=False,
                output_path=enc_path,
                keep_input=True,
            )
            decoded_path, _size = basefwx._b512_decode_path(
                enc_path,
                pw,
                strip_metadata=False,
                use_master=False,
            )
            return decoded_path.stat().st_size
        _bench(warmup, run)
    return 0

def cmd_bench_pb512file(args: list[str]) -> int:
    if len(args) < 2:
        return 2
    inp, pw = args[:2]
    warmup = _warmup_env()
    source = Path(inp)
    with tempfile.TemporaryDirectory(prefix="basefwx-bench-") as tmpdir:
        tmp = Path(tmpdir)
        enc_path = tmp / "bench.fwx"
        def run() -> int:
            basefwx._aes_heavy_encode_path(
                source,
                pw,
                use_master=False,
                output_path=enc_path,
                keep_input=True,
            )
            decoded_path, _size = basefwx._aes_heavy_decode_path(
                enc_path,
                pw,
                strip_metadata=False,
                use_master=False,
            )
            return decoded_path.stat().st_size
        _bench(warmup, run)
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
    if cmd == "fwxaes-stream-roundtrip":
        return cmd_fwxaes_stream_roundtrip(args)
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
    if cmd == "text-hash":
        return cmd_text_hash(args)
    if cmd == "jmg-roundtrip":
        return cmd_jmg_roundtrip(args)
    if cmd == "jmg-enc":
        return cmd_jmg_enc(args)
    if cmd == "jmg-dec":
        return cmd_jmg_dec(args)
    if cmd == "b512file-bytes-roundtrip":
        return cmd_b512file_bytes_roundtrip(args)
    if cmd == "pb512file-bytes-roundtrip":
        return cmd_pb512file_bytes_roundtrip(args)
    if cmd == "bench-text":
        return cmd_bench_text(args)
    if cmd == "bench-hash":
        return cmd_bench_hash(args)
    if cmd == "bench-fwxaes":
        return cmd_bench_fwxaes(args)
    if cmd == "bench-b512file":
        return cmd_bench_b512file(args)
    if cmd == "bench-pb512file":
        return cmd_bench_pb512file(args)
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
PY

run_native_tests_block() {
    local label="${PHASE2_LABEL:-Python/C++/Java}"
    phase "PHASE2: run native ${label} tests"

    # keep STEP_INDEX/STEP_TOTAL managed by caller
    if [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" && ! -x "$CPP_BIN" ]]; then
        CPP_AVAILABLE=0
        FAILURES+=("cpp_build (binary missing or stale)")
    fi
    if [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" && ! -f "$JAVA_JAR" ]]; then
        JAVA_AVAILABLE=0
        FAILURES+=("java_build (jar missing)")
    fi

# fwxAES correct
if [[ "$RUN_PY_TESTS" == "1" ]]; then
    fwxaes_py_input="$(copy_input "fwxaes_py_correct" "$FWXAES_FILE")"
    fwxaes_py_enc="$(with_suffix "$fwxaes_py_input" ".fwx")"
    fwxaes_py_dec="$WORK_DIR/fwxaes_py_correct/decoded_${FWXAES_FILE}"
    time_cmd "fwxaes_py_correct" "$PYTHON_BIN" "$PY_HELPER" fwxaes-roundtrip "$fwxaes_py_input" "$fwxaes_py_enc" "$fwxaes_py_dec" "$PW"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_py_dec"
fi

if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    fwxaes_pypy_input="$(copy_input "fwxaes_pypy_correct" "$FWXAES_FILE")"
    fwxaes_pypy_enc="$(with_suffix "$fwxaes_pypy_input" ".fwx")"
    fwxaes_pypy_dec="$WORK_DIR/fwxaes_pypy_correct/decoded_${FWXAES_FILE}"
    time_cmd "fwxaes_pypy_correct" "$PYPY_BIN" "$PY_HELPER" fwxaes-roundtrip "$fwxaes_pypy_input" "$fwxaes_pypy_enc" "$fwxaes_pypy_dec" "$PW"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_pypy_dec"
fi

if [[ "$RUN_CPP_TESTS" == "1" ]]; then
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
fi

if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    fwxaes_java_input="$(copy_input "fwxaes_java_correct" "$FWXAES_FILE")"
    fwxaes_java_enc="$(with_suffix "$fwxaes_java_input" ".fwx")"
    fwxaes_java_dec="$WORK_DIR/fwxaes_java_correct/decoded_${FWXAES_FILE}"
    if (( JAVA_AVAILABLE == 1 )); then
        cooldown "fwxaes_cpp_to_java_correct"
        time_cmd "fwxaes_java_correct" java_fwxAES_roundtrip "$fwxaes_java_input" "$fwxaes_java_enc" "$fwxaes_java_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_java_dec"
    else
        FAILURES+=("fwxaes_java_correct (java unavailable)")
    fi
fi

# fwxAES wrong password
if [[ "$SKIP_WRONG" != "1" ]]; then
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        fwxaes_py_wrong_input="$(copy_input "fwxaes_py_wrong" "$FWXAES_FILE")"
        fwxaes_py_wrong_enc="$(with_suffix "$fwxaes_py_wrong_input" ".fwx")"
        fwxaes_py_wrong_dec="$WORK_DIR/fwxaes_py_wrong/decoded_${FWXAES_FILE}"
        time_cmd "fwxaes_py_wrong" "$PYTHON_BIN" "$PY_HELPER" fwxaes-wrong "$fwxaes_py_wrong_input" "$fwxaes_py_wrong_enc" "$fwxaes_py_wrong_dec" "$PW" "$BAD_PW"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
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

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        fwxaes_java_wrong_input="$(copy_input "fwxaes_java_wrong" "$FWXAES_FILE")"
        fwxaes_java_wrong_enc="$(with_suffix "$fwxaes_java_wrong_input" ".fwx")"
        fwxaes_java_wrong_dec="$WORK_DIR/fwxaes_java_wrong/decoded_${FWXAES_FILE}"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "fwxaes_cpp_to_java_wrong"
            time_cmd "fwxaes_java_wrong" java_fwxAES_wrong "$fwxaes_java_wrong_input" "$fwxaes_java_wrong_enc" "$fwxaes_java_wrong_dec"
        else
            FAILURES+=("fwxaes_java_wrong (java unavailable)")
        fi
    fi
fi

# fwxAES stream roundtrip (API)
if [[ "$RUN_PY_TESTS" == "1" ]]; then
    fwxaes_py_stream_input="$(copy_input "fwxaes_py_stream" "$FWXAES_FILE")"
    fwxaes_py_stream_enc="$(with_suffix "$fwxaes_py_stream_input" ".fwx")"
    fwxaes_py_stream_dec="$WORK_DIR/fwxaes_py_stream/decoded_${FWXAES_FILE}"
    time_cmd "fwxaes_py_stream" "$PYTHON_BIN" "$PY_HELPER" fwxaes-stream-roundtrip \
        "$fwxaes_py_stream_input" "$fwxaes_py_stream_enc" "$fwxaes_py_stream_dec" "$PW"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_py_stream_dec"
fi

if [[ "$RUN_CPP_TESTS" == "1" ]]; then
    fwxaes_cpp_stream_input="$(copy_input "fwxaes_cpp_stream" "$FWXAES_FILE")"
    fwxaes_cpp_stream_enc="$(with_suffix "$fwxaes_cpp_stream_input" ".fwx")"
    fwxaes_cpp_stream_dec="$WORK_DIR/fwxaes_cpp_stream/decoded_${FWXAES_FILE}"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "fwxaes_py_to_cpp_stream"
        time_cmd "fwxaes_cpp_stream" cpp_fwxAES_stream_roundtrip \
            "$fwxaes_cpp_stream_input" "$fwxaes_cpp_stream_enc" "$fwxaes_cpp_stream_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_cpp_stream_dec"
    else
        FAILURES+=("fwxaes_cpp_stream (cpp unavailable)")
    fi
fi

if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    fwxaes_java_stream_input="$(copy_input "fwxaes_java_stream" "$FWXAES_FILE")"
    fwxaes_java_stream_enc="$(with_suffix "$fwxaes_java_stream_input" ".fwx")"
    fwxaes_java_stream_dec="$WORK_DIR/fwxaes_java_stream/decoded_${FWXAES_FILE}"
    if (( JAVA_AVAILABLE == 1 )); then
        cooldown "fwxaes_cpp_to_java_stream"
        time_cmd "fwxaes_java_stream" java_fwxAES_stream_roundtrip \
            "$fwxaes_java_stream_input" "$fwxaes_java_stream_enc" "$fwxaes_java_stream_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_java_stream_dec"
    else
        FAILURES+=("fwxaes_java_stream (java unavailable)")
    fi
fi

# b512file bytes roundtrip (API)
if [[ "$RUN_PY_TESTS" == "1" ]]; then
    b512_py_bytes_input="$(copy_input "b512file_py_bytes" "$FWXAES_FILE")"
    b512_py_bytes_dec="$WORK_DIR/b512file_py_bytes/decoded_${FWXAES_FILE}"
    time_cmd "b512file_py_bytes" py_b512file_bytes_roundtrip "$b512_py_bytes_input" "$b512_py_bytes_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$b512_py_bytes_dec"
fi

if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    b512_pypy_bytes_input="$(copy_input "b512file_pypy_bytes" "$FWXAES_FILE")"
    b512_pypy_bytes_dec="$WORK_DIR/b512file_pypy_bytes/decoded_${FWXAES_FILE}"
    time_cmd "b512file_pypy_bytes" pypy_b512file_bytes_roundtrip "$b512_pypy_bytes_input" "$b512_pypy_bytes_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$b512_pypy_bytes_dec"
fi

if [[ "$RUN_CPP_TESTS" == "1" ]]; then
    b512_cpp_bytes_input="$(copy_input "b512file_cpp_bytes" "$FWXAES_FILE")"
    b512_cpp_bytes_dec="$WORK_DIR/b512file_cpp_bytes/decoded_${FWXAES_FILE}"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "b512file_py_to_cpp_bytes"
        time_cmd "b512file_cpp_bytes" cpp_b512file_bytes_roundtrip "$b512_cpp_bytes_input" "$b512_cpp_bytes_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$b512_cpp_bytes_dec"
    else
        FAILURES+=("b512file_cpp_bytes (cpp unavailable)")
    fi
fi

if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    b512_java_bytes_input="$(copy_input "b512file_java_bytes" "$FWXAES_FILE")"
    b512_java_bytes_dec="$WORK_DIR/b512file_java_bytes/decoded_${FWXAES_FILE}"
    if (( JAVA_AVAILABLE == 1 )); then
        cooldown "b512file_cpp_to_java_bytes"
        time_cmd "b512file_java_bytes" java_b512file_bytes_roundtrip "$b512_java_bytes_input" "$b512_java_bytes_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$b512_java_bytes_dec"
    else
        FAILURES+=("b512file_java_bytes (java unavailable)")
    fi
fi

# pb512file bytes roundtrip (API)
if [[ "$RUN_PY_TESTS" == "1" ]]; then
    pb512_py_bytes_input="$(copy_input "pb512file_py_bytes" "$FWXAES_FILE")"
    pb512_py_bytes_dec="$WORK_DIR/pb512file_py_bytes/decoded_${FWXAES_FILE}"
    time_cmd "pb512file_py_bytes" py_pb512file_bytes_roundtrip "$pb512_py_bytes_input" "$pb512_py_bytes_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$pb512_py_bytes_dec"
fi

if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    pb512_pypy_bytes_input="$(copy_input "pb512file_pypy_bytes" "$FWXAES_FILE")"
    pb512_pypy_bytes_dec="$WORK_DIR/pb512file_pypy_bytes/decoded_${FWXAES_FILE}"
    time_cmd "pb512file_pypy_bytes" pypy_pb512file_bytes_roundtrip "$pb512_pypy_bytes_input" "$pb512_pypy_bytes_dec"
    add_verify "$ORIG_DIR/$FWXAES_FILE" "$pb512_pypy_bytes_dec"
fi

if [[ "$RUN_CPP_TESTS" == "1" ]]; then
    pb512_cpp_bytes_input="$(copy_input "pb512file_cpp_bytes" "$FWXAES_FILE")"
    pb512_cpp_bytes_dec="$WORK_DIR/pb512file_cpp_bytes/decoded_${FWXAES_FILE}"
    if (( CPP_AVAILABLE == 1 )); then
        cooldown "pb512file_py_to_cpp_bytes"
        time_cmd "pb512file_cpp_bytes" cpp_pb512file_bytes_roundtrip "$pb512_cpp_bytes_input" "$pb512_cpp_bytes_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$pb512_cpp_bytes_dec"
    else
        FAILURES+=("pb512file_cpp_bytes (cpp unavailable)")
    fi
fi
if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    pb512_java_bytes_input="$(copy_input "pb512file_java_bytes" "$FWXAES_FILE")"
    pb512_java_bytes_dec="$WORK_DIR/pb512file_java_bytes/decoded_${FWXAES_FILE}"
    if (( JAVA_AVAILABLE == 1 )); then
        cooldown "pb512file_cpp_to_java_bytes"
        time_cmd "pb512file_java_bytes" java_pb512file_bytes_roundtrip "$pb512_java_bytes_input" "$pb512_java_bytes_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$pb512_java_bytes_dec"
    else
        FAILURES+=("pb512file_java_bytes (java unavailable)")
    fi
fi

# reversible no-password methods
for method in "${TEXT_NOPASS_METHODS[@]}"; do
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        py_out="$OUT_DIR/${method}_py.txt"
        time_cmd "${method}_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip "$method" "$TEXT_ORIG" "$py_out" "$PW"
        add_verify "$TEXT_ORIG" "$py_out"
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        pypy_out="$OUT_DIR/${method}_pypy.txt"
        time_cmd "${method}_pypy_correct" "$PYPY_BIN" "$PY_HELPER" text-roundtrip "$method" "$TEXT_ORIG" "$pypy_out" "$PW"
        add_verify "$TEXT_ORIG" "$pypy_out"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
        cpp_out="$OUT_DIR/${method}_cpp.txt"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "${method}_py_to_cpp_correct"
            time_cmd "${method}_cpp_correct" cpp_text_roundtrip "$method" "$TEXT_ORIG" "$cpp_out" "$PW"
            add_verify "$TEXT_ORIG" "$cpp_out"
        else
            FAILURES+=("${method}_cpp_correct (cpp unavailable)")
        fi
    fi

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        java_out="$OUT_DIR/${method}_java.txt"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "${method}_cpp_to_java_correct"
            time_cmd "${method}_java_correct" java_text_roundtrip "$method" "$TEXT_ORIG" "$java_out" "$PW"
            add_verify "$TEXT_ORIG" "$java_out"
        else
            FAILURES+=("${method}_java_correct (java unavailable)")
        fi
    fi
done

# reversible password methods
for method in "${TEXT_PASS_METHODS[@]}"; do
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        py_out="$OUT_DIR/${method}_py.txt"
        time_cmd "${method}_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-roundtrip "$method" "$TEXT_ORIG" "$py_out" "$PW"
        add_verify "$TEXT_ORIG" "$py_out"
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        pypy_out="$OUT_DIR/${method}_pypy.txt"
        time_cmd "${method}_pypy_correct" "$PYPY_BIN" "$PY_HELPER" text-roundtrip "$method" "$TEXT_ORIG" "$pypy_out" "$PW"
        add_verify "$TEXT_ORIG" "$pypy_out"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
        cpp_out="$OUT_DIR/${method}_cpp.txt"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "${method}_py_to_cpp_correct"
            time_cmd "${method}_cpp_correct" cpp_text_roundtrip "$method" "$TEXT_ORIG" "$cpp_out" "$PW"
            add_verify "$TEXT_ORIG" "$cpp_out"
        else
            FAILURES+=("${method}_cpp_correct (cpp unavailable)")
        fi
    fi

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        java_out="$OUT_DIR/${method}_java.txt"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "${method}_cpp_to_java_correct"
            time_cmd "${method}_java_correct" java_text_roundtrip "$method" "$TEXT_ORIG" "$java_out" "$PW"
            add_verify "$TEXT_ORIG" "$java_out"
        else
            FAILURES+=("${method}_java_correct (java unavailable)")
        fi
    fi

    if [[ "$SKIP_WRONG" != "1" ]]; then
        if [[ "$RUN_PY_TESTS" == "1" ]]; then
            time_cmd "${method}_py_wrong" "$PYTHON_BIN" "$PY_HELPER" text-wrong "$method" "$TEXT_ORIG" "$PW" "$BAD_PW"
        fi
        if [[ "$RUN_CPP_TESTS" == "1" ]]; then
            if (( CPP_AVAILABLE == 1 )); then
                cooldown "${method}_py_to_cpp_wrong"
                time_cmd "${method}_cpp_wrong" cpp_text_wrong "$method" "$TEXT_ORIG" "$PW" "$OUT_DIR/${method}_cpp_wrong.enc"
            else
                FAILURES+=("${method}_cpp_wrong (cpp unavailable)")
            fi
        fi
        if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
            if (( JAVA_AVAILABLE == 1 )); then
                cooldown "${method}_cpp_to_java_wrong"
                time_cmd "${method}_java_wrong" java_text_wrong "$method" "$TEXT_ORIG" "$PW" "$OUT_DIR/${method}_java_wrong.enc"
            else
                FAILURES+=("${method}_java_wrong (java unavailable)")
            fi
        fi
    fi
done

# hash-only methods
for method in "${HASH_METHODS[@]}"; do
    py_out="$OUT_DIR/${method}_py.txt"
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        time_cmd "${method}_py_correct" "$PYTHON_BIN" "$PY_HELPER" text-hash "$method" "$TEXT_ORIG" "$py_out"
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        pypy_out="$OUT_DIR/${method}_pypy.txt"
        time_cmd "${method}_pypy_correct" "$PYPY_BIN" "$PY_HELPER" text-hash "$method" "$TEXT_ORIG" "$pypy_out"
        if [[ -f "$py_out" ]]; then
            compare_outputs "${method}_py_pypy" "$py_out" "$pypy_out"
        fi
    fi
    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
        cpp_out="$OUT_DIR/${method}_cpp.txt"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "${method}_py_to_cpp_correct"
            time_cmd "${method}_cpp_correct" cpp_text_hash "$method" "$TEXT_ORIG" "$cpp_out"
            if [[ -f "$py_out" ]]; then
                compare_outputs "${method}_py_cpp" "$py_out" "$cpp_out"
            fi
        else
            FAILURES+=("${method}_cpp_correct (cpp unavailable)")
        fi
    fi
    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        java_out="$OUT_DIR/${method}_java.txt"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "${method}_cpp_to_java_correct"
            time_cmd "${method}_java_correct" java_text_hash "$method" "$TEXT_ORIG" "$java_out"
            if [[ -f "$py_out" ]]; then
                compare_outputs "${method}_py_java" "$py_out" "$java_out"
            fi
        else
            FAILURES+=("${method}_java_correct (java unavailable)")
        fi
    fi
done

if [[ "$RUN_PY_TESTS" == "1" ]]; then
    B512FILE_PY_TOTAL=0
fi
if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    B512FILE_PYPY_TOTAL=0
fi
if [[ "$RUN_CPP_TESTS" == "1" ]]; then
    B512FILE_CPP_TOTAL=0
fi
if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    B512FILE_JAVA_TOTAL=0
fi
for file_name in "${B512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    # b512file correct
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        b512file_py_input="$(copy_input "b512file_py_correct_${tag}" "$file_name")"
        key="b512file_py_correct_${tag}"
        time_cmd "$key" py_b512file_roundtrip "$b512file_py_input"
        B512FILE_PY_TOTAL=$((B512FILE_PY_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$b512file_py_input"
    fi

    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        b512file_pypy_input="$(copy_input "b512file_pypy_correct_${tag}" "$file_name")"
        key="b512file_pypy_correct_${tag}"
        time_cmd "$key" pypy_b512file_roundtrip "$b512file_pypy_input"
        B512FILE_PYPY_TOTAL=$((B512FILE_PYPY_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$b512file_pypy_input"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
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
    fi

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        b512file_java_input="$(copy_input "b512file_java_correct_${tag}" "$file_name")"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "b512file_cpp_to_java_correct_${tag}"
            key="b512file_java_correct_${tag}"
            time_cmd "$key" java_b512file_roundtrip "$b512file_java_input"
            B512FILE_JAVA_TOTAL=$((B512FILE_JAVA_TOTAL + ${TIMES[$key]:-0}))
            add_verify "$ORIG_DIR/$file_name" "$b512file_java_input"
        else
            FAILURES+=("b512file_java_correct_${tag} (java unavailable)")
        fi
    fi

    if [[ "$SKIP_WRONG" != "1" ]]; then
        # b512file wrong password
        if [[ "$RUN_PY_TESTS" == "1" ]]; then
            b512file_py_wrong_input="$(copy_input "b512file_py_wrong_${tag}" "$file_name")"
            time_cmd "b512file_py_wrong_${tag}" py_b512file_wrong "$b512file_py_wrong_input"
        fi

        if [[ "$RUN_CPP_TESTS" == "1" ]]; then
            b512file_cpp_wrong_input="$(copy_input "b512file_cpp_wrong_${tag}" "$file_name")"
            if (( CPP_AVAILABLE == 1 )); then
                cooldown "b512file_py_to_cpp_wrong_${tag}"
                time_cmd "b512file_cpp_wrong_${tag}" cpp_b512file_wrong "$b512file_cpp_wrong_input"
            else
                FAILURES+=("b512file_cpp_wrong_${tag} (cpp unavailable)")
            fi
        fi
        if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
            b512file_java_wrong_input="$(copy_input "b512file_java_wrong_${tag}" "$file_name")"
            if (( JAVA_AVAILABLE == 1 )); then
                cooldown "b512file_cpp_to_java_wrong_${tag}"
                time_cmd "b512file_java_wrong_${tag}" java_b512file_wrong "$b512file_java_wrong_input"
            else
                FAILURES+=("b512file_java_wrong_${tag} (java unavailable)")
            fi
        fi
    fi
done

if [[ "$RUN_PY_TESTS" == "1" ]]; then
    PB512FILE_PY_TOTAL=0
fi
if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    PB512FILE_PYPY_TOTAL=0
fi
if [[ "$RUN_CPP_TESTS" == "1" ]]; then
    PB512FILE_CPP_TOTAL=0
fi
if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
    PB512FILE_JAVA_TOTAL=0
fi
for file_name in "${PB512FILE_CASES[@]}"; do
    tag="$(case_tag "$file_name")"
    # pb512file correct
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        pb512file_py_input="$(copy_input "pb512file_py_correct_${tag}" "$file_name")"
        key="pb512file_py_correct_${tag}"
        time_cmd "$key" py_pb512file_roundtrip "$pb512file_py_input"
        PB512FILE_PY_TOTAL=$((PB512FILE_PY_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$pb512file_py_input"
    fi

    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        pb512file_pypy_input="$(copy_input "pb512file_pypy_correct_${tag}" "$file_name")"
        key="pb512file_pypy_correct_${tag}"
        time_cmd "$key" pypy_pb512file_roundtrip "$pb512file_pypy_input"
        PB512FILE_PYPY_TOTAL=$((PB512FILE_PYPY_TOTAL + ${TIMES[$key]:-0}))
        add_verify "$ORIG_DIR/$file_name" "$pb512file_pypy_input"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
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
    fi

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        pb512file_java_input="$(copy_input "pb512file_java_correct_${tag}" "$file_name")"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "pb512file_cpp_to_java_correct_${tag}"
            key="pb512file_java_correct_${tag}"
            time_cmd "$key" java_pb512file_roundtrip "$pb512file_java_input"
            PB512FILE_JAVA_TOTAL=$((PB512FILE_JAVA_TOTAL + ${TIMES[$key]:-0}))
            add_verify "$ORIG_DIR/$file_name" "$pb512file_java_input"
        else
            FAILURES+=("pb512file_java_correct_${tag} (java unavailable)")
        fi
    fi

    if [[ "$SKIP_WRONG" != "1" ]]; then
        # pb512file wrong password
        if [[ "$RUN_PY_TESTS" == "1" ]]; then
            pb512file_py_wrong_input="$(copy_input "pb512file_py_wrong_${tag}" "$file_name")"
            time_cmd "pb512file_py_wrong_${tag}" py_pb512file_wrong "$pb512file_py_wrong_input"
        fi

        if [[ "$RUN_CPP_TESTS" == "1" ]]; then
            pb512file_cpp_wrong_input="$(copy_input "pb512file_cpp_wrong_${tag}" "$file_name")"
            if (( CPP_AVAILABLE == 1 )); then
                cooldown "pb512file_py_to_cpp_wrong_${tag}"
                time_cmd "pb512file_cpp_wrong_${tag}" cpp_pb512file_wrong "$pb512file_cpp_wrong_input"
            else
                FAILURES+=("pb512file_cpp_wrong_${tag} (cpp unavailable)")
            fi
        fi
        if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
            pb512file_java_wrong_input="$(copy_input "pb512file_java_wrong_${tag}" "$file_name")"
            if (( JAVA_AVAILABLE == 1 )); then
                cooldown "pb512file_cpp_to_java_wrong_${tag}"
                time_cmd "pb512file_java_wrong_${tag}" java_pb512file_wrong "$pb512file_java_wrong_input"
            else
                FAILURES+=("pb512file_java_wrong_${tag} (java unavailable)")
            fi
        fi
    fi
done

if (( ${#JMG_CASES[@]} > 0 )) && { [[ "$RUN_PY_TESTS" == "1" ]] || [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]] || [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; }; then
    phase "PHASE2.1: jMG media tests (${PHASE2_LABEL:-native})"
    for file_name in "${JMG_CASES[@]}"; do
        tag="$(case_tag "$file_name")"
        if [[ "$RUN_PY_TESTS" == "1" ]]; then
            jmg_py_input="$(copy_input "jmg_py_${tag}" "$file_name")"
            jmg_py_enc="$WORK_DIR/jmg_py_${tag}/enc_${file_name}"
            jmg_py_dec="$WORK_DIR/jmg_py_${tag}/dec_${file_name}"
            time_cmd "jmg_py_${tag}" py_jmg_roundtrip "$jmg_py_input" "$jmg_py_enc" "$jmg_py_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_py_dec"
        fi
        if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
            jmg_pypy_input="$(copy_input "jmg_pypy_${tag}" "$file_name")"
            jmg_pypy_enc="$WORK_DIR/jmg_pypy_${tag}/enc_${file_name}"
            jmg_pypy_dec="$WORK_DIR/jmg_pypy_${tag}/dec_${file_name}"
            time_cmd "jmg_pypy_${tag}" pypy_jmg_roundtrip "$jmg_pypy_input" "$jmg_pypy_enc" "$jmg_pypy_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_pypy_dec"
        fi

        if [[ "$RUN_CPP_TESTS" == "1" ]]; then
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
        fi
    done
else
    if [[ "$RUN_PYPY_TESTS" == "1" && "$RUN_PY_TESTS" != "1" && "$RUN_CPP_TESTS" != "1" ]]; then
        phase "PHASE2.1: jMG media tests (${PHASE2_LABEL:-native}, skipped - PyPy phase)"
    else
        phase "PHASE2.1: jMG media tests (${PHASE2_LABEL:-native}, skipped)"
    fi
fi
}

phase "PHASE2: prepare native runtimes"
if [[ "$RUN_CPP_TESTS_ORIG" == "1" ]]; then
    if ! ensure_cpp; then
        log "C++ binary unavailable; C++ tests will be skipped"
        CPP_AVAILABLE=0
        RUN_CPP_TESTS_ORIG=0
    fi
else
    CPP_AVAILABLE=0
fi
if [[ "$RUN_JAVA_TESTS_ORIG" == "1" ]]; then
    if ! ensure_java; then
        log "Java CLI unavailable; Java tests will be skipped"
        JAVA_AVAILABLE=0
        RUN_JAVA_TESTS_ORIG=0
    fi
else
    JAVA_AVAILABLE=0
fi
if [[ "$RUN_PYPY_TESTS_ORIG" == "1" ]]; then
    if ! ensure_pypy; then
        log "PyPy unavailable; PyPy tests will be skipped"
        PYPY_AVAILABLE=0
        RUN_PYPY_TESTS_ORIG=0
    fi
else
    PYPY_AVAILABLE=0
fi

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

LANG_PHASES=()
if [[ "$RUN_PY_TESTS_ORIG" == "1" ]]; then
    LANG_PHASES+=("py")
fi
if [[ "$RUN_PYPY_TESTS_ORIG" == "1" ]]; then
    LANG_PHASES+=("pypy")
fi
if [[ "$RUN_CPP_TESTS_ORIG" == "1" ]]; then
    LANG_PHASES+=("cpp")
fi
if [[ "$RUN_JAVA_TESTS_ORIG" == "1" ]]; then
    LANG_PHASES+=("java")
fi

for idx in "${!LANG_PHASES[@]}"; do
    lang="${LANG_PHASES[$idx]}"
    RUN_PY_TESTS=0
    RUN_PYPY_TESTS=0
    RUN_CPP_TESTS=0
    RUN_JAVA_TESTS=0
    case "$lang" in
        py)
            PHASE2_LABEL="Python"
            RUN_PY_TESTS=1
            ;;
        pypy)
            PHASE2_LABEL="PyPy"
            RUN_PYPY_TESTS=1
            ;;
        cpp)
            PHASE2_LABEL="C++"
            RUN_CPP_TESTS=1
            ;;
        java)
            PHASE2_LABEL="Java"
            RUN_JAVA_TESTS=1
            ;;
    esac
    INTRA_LANG_COOLDOWN=0
    run_native_tests_block
    INTRA_LANG_COOLDOWN=1
    if (( idx < ${#LANG_PHASES[@]} - 1 )); then
        lang_cooldown "${PHASE2_LABEL}"
    fi
done

RUN_PY_TESTS="$RUN_PY_TESTS_ORIG"
RUN_PYPY_TESTS="$RUN_PYPY_TESTS_ORIG"
RUN_CPP_TESTS="$RUN_CPP_TESTS_ORIG"
RUN_JAVA_TESTS="$RUN_JAVA_TESTS_ORIG"

if [[ "$SKIP_CROSS" == "1" ]]; then
    phase "PHASE2.2: cross-compat tests (skipped)"
else
    phase "PHASE2.2: cross-compat tests"
fi

if [[ "$SKIP_CROSS" != "1" ]]; then
    if [[ "$RUN_PY_TESTS" == "1" && "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
        # fwxAES cross-compat (Python <-> C++)
        fwxaes_pycc_input="$(copy_input "fwxaes_pycc" "$FWXAES_FILE")"
        fwxaes_pycc_enc="$(with_suffix "$fwxaes_pycc_input" ".fwx")"
        fwxaes_pycc_dec="$WORK_DIR/fwxaes_pycc/decoded_${FWXAES_FILE}"
        time_cmd "fwxaes_py_enc_cpp_dec" fwxaes_py_enc_cpp_dec "$fwxaes_pycc_input" "$fwxaes_pycc_enc" "$fwxaes_pycc_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_pycc_dec"

        fwxaes_cpyp_input="$(copy_input "fwxaes_cpyp" "$FWXAES_FILE")"
        fwxaes_cpyp_enc="$(with_suffix "$fwxaes_cpyp_input" ".fwx")"
        fwxaes_cpyp_dec="$WORK_DIR/fwxaes_cpyp/decoded_${FWXAES_FILE}"
        time_cmd "fwxaes_cpp_enc_py_dec" fwxaes_cpp_enc_py_dec "$fwxaes_cpyp_input" "$fwxaes_cpyp_enc" "$fwxaes_cpyp_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_cpyp_dec"

        for method in "${TEXT_NOPASS_METHODS[@]}" "${TEXT_PASS_METHODS[@]}"; do
            py_enc="$OUT_DIR/${method}_py_enc.txt"
            pycc_out="$OUT_DIR/${method}_pycc.txt"
            time_cmd "${method}_py_enc_cpp_dec" text_py_enc_cpp_dec "$method" "$TEXT_ORIG" "$py_enc" "$pycc_out"
            add_verify "$TEXT_ORIG" "$pycc_out"

            cpp_enc="$OUT_DIR/${method}_cpp_enc.txt"
            cpyp_out="$OUT_DIR/${method}_cpyp.txt"
            time_cmd "${method}_cpp_enc_py_dec" text_cpp_enc_py_dec "$method" "$TEXT_ORIG" "$cpp_enc" "$cpyp_out"
            add_verify "$TEXT_ORIG" "$cpyp_out"
        done

        for file_name in "${B512FILE_CASES[@]}"; do
            tag="$(case_tag "$file_name")"
            b512file_pycc_input="$(copy_input "b512file_pycc_${tag}" "$file_name")"
            b512file_pycc_enc="$(with_suffix "$b512file_pycc_input" ".fwx")"
            time_cmd "b512file_py_enc_cpp_dec_${tag}" b512file_py_enc_cpp_dec "$b512file_pycc_input" "$b512file_pycc_enc"
            add_verify "$ORIG_DIR/$file_name" "$b512file_pycc_input"

            b512file_cpyp_input="$(copy_input "b512file_cpyp_${tag}" "$file_name")"
            b512file_cpyp_enc="$(with_suffix "$b512file_cpyp_input" ".fwx")"
            time_cmd "b512file_cpp_enc_py_dec_${tag}" b512file_cpp_enc_py_dec "$b512file_cpyp_input" "$b512file_cpyp_enc"
            add_verify "$ORIG_DIR/$file_name" "$b512file_cpyp_input"
        done

        for file_name in "${PB512FILE_CASES[@]}"; do
            tag="$(case_tag "$file_name")"
            pb512file_pycc_input="$(copy_input "pb512file_pycc_${tag}" "$file_name")"
            pb512file_pycc_enc="$(with_suffix "$pb512file_pycc_input" ".fwx")"
            time_cmd "pb512file_py_enc_cpp_dec_${tag}" pb512file_py_enc_cpp_dec "$pb512file_pycc_input" "$pb512file_pycc_enc"
            add_verify "$ORIG_DIR/$file_name" "$pb512file_pycc_input"

            pb512file_cpyp_input="$(copy_input "pb512file_cpyp_${tag}" "$file_name")"
            pb512file_cpyp_enc="$(with_suffix "$pb512file_cpyp_input" ".fwx")"
            time_cmd "pb512file_cpp_enc_py_dec_${tag}" pb512file_cpp_enc_py_dec "$pb512file_cpyp_input" "$pb512file_cpyp_enc"
            add_verify "$ORIG_DIR/$file_name" "$pb512file_cpyp_input"
        done

        if (( ${#JMG_CASES[@]} > 0 )); then
            for file_name in "${JMG_CASES[@]}"; do
                tag="$(case_tag "$file_name")"
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
            done
        fi
    fi

    if [[ "$RUN_PY_TESTS" == "1" && "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
        # fwxAES cross-compat (Python <-> Java)
        fwxaes_pyj_input="$(copy_input "fwxaes_pyj" "$FWXAES_FILE")"
        fwxaes_pyj_enc="$(with_suffix "$fwxaes_pyj_input" ".fwx")"
        fwxaes_pyj_dec="$WORK_DIR/fwxaes_pyj/decoded_${FWXAES_FILE}"
        time_cmd "fwxaes_py_enc_java_dec" fwxaes_py_enc_java_dec "$fwxaes_pyj_input" "$fwxaes_pyj_enc" "$fwxaes_pyj_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_pyj_dec"

        fwxaes_jp_input="$(copy_input "fwxaes_jp" "$FWXAES_FILE")"
        fwxaes_jp_enc="$(with_suffix "$fwxaes_jp_input" ".fwx")"
        fwxaes_jp_dec="$WORK_DIR/fwxaes_jp/decoded_${FWXAES_FILE}"
        time_cmd "fwxaes_java_enc_py_dec" fwxaes_java_enc_py_dec "$fwxaes_jp_input" "$fwxaes_jp_enc" "$fwxaes_jp_dec"
        add_verify "$ORIG_DIR/$FWXAES_FILE" "$fwxaes_jp_dec"

        for method in "${TEXT_NOPASS_METHODS[@]}" "${TEXT_PASS_METHODS[@]}"; do
            py_enc="$OUT_DIR/${method}_py_enc_java.txt"
            pyj_out="$OUT_DIR/${method}_pyj.txt"
            time_cmd "${method}_py_enc_java_dec" text_py_enc_java_dec "$method" "$TEXT_ORIG" "$py_enc" "$pyj_out"
            add_verify "$TEXT_ORIG" "$pyj_out"

            java_enc="$OUT_DIR/${method}_java_enc.txt"
            jp_out="$OUT_DIR/${method}_javapy.txt"
            time_cmd "${method}_java_enc_py_dec" text_java_enc_py_dec "$method" "$TEXT_ORIG" "$java_enc" "$jp_out"
            add_verify "$TEXT_ORIG" "$jp_out"
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

phase "PHASE4: benchmark timings"
STEP_INDEX=0
STEP_TOTAL=0
BENCH_TEXT="$TEXT_ORIG"
BENCH_BYTES_FILE=""
if [[ "$TEST_MODE" == "default" && -f "$ORIG_DIR/large_36m.bin" ]]; then
    BENCH_BYTES_FILE="$ORIG_DIR/large_36m.bin"
elif [[ -f "$ORIG_DIR/sample_payload.bin" ]]; then
    BENCH_BYTES_FILE="$ORIG_DIR/sample_payload.bin"
else
    BENCH_BYTES_FILE="$ORIG_DIR/$FWXAES_FILE"
fi

if [[ -z "${BENCH_WARMUP_LIGHT:-}" || -z "${BENCH_WARMUP_HEAVY:-}" ]]; then
    if [[ "$TEST_MODE" == "quickest" ]]; then
        BENCH_WARMUP_LIGHT="${BENCH_WARMUP_LIGHT:-3}"
        BENCH_WARMUP_HEAVY="${BENCH_WARMUP_HEAVY:-5}"
        BENCH_WARMUP_FILE="${BENCH_WARMUP_FILE:-0}"
    elif [[ "$TEST_MODE" == "fast" ]]; then
        BENCH_WARMUP_LIGHT="${BENCH_WARMUP_LIGHT:-5}"
        BENCH_WARMUP_HEAVY="${BENCH_WARMUP_HEAVY:-10}"
        BENCH_WARMUP_FILE="${BENCH_WARMUP_FILE:-1}"
    else
        BENCH_WARMUP_LIGHT="${BENCH_WARMUP_LIGHT:-10}"
        BENCH_WARMUP_HEAVY="${BENCH_WARMUP_HEAVY:-20}"
        BENCH_WARMUP_FILE="${BENCH_WARMUP_FILE:-1}"
    fi
fi

JAVA_BENCH_FLAGS="${JAVA_BENCH_FLAGS:--Xms2g -Xmx2g -XX:+AlwaysPreTouch -XX:+TieredCompilation -XX:CompileThreshold=100 -XX:TieredStopAtLevel=4 -XX:+UnlockExperimentalVMOptions -XX:+UseZGC}"
read -r -a JAVA_BENCH_FLAGS_ARR <<<"$JAVA_BENCH_FLAGS"

BENCH_TEXT_METHODS=("b256" "b512" "pb512" "b64" "a512")
BENCH_HASH_METHODS=("hash512" "uhash513" "bi512" "b1024")

BENCH_LANGS=()
if [[ "$RUN_PY_TESTS" == "1" ]]; then
    BENCH_LANGS+=("py")
fi
if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
    BENCH_LANGS+=("pypy")
fi
if [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
    BENCH_LANGS+=("cpp")
fi
if [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
    BENCH_LANGS+=("java")
fi

for idx in "${!BENCH_LANGS[@]}"; do
    lang="${BENCH_LANGS[$idx]}"
    case "$lang" in
        py)
            time_cmd_bench "fwxaes_py_correct" env BASEFWX_BENCH_WARMUP=0 \
                "$PYTHON_BIN" "$PY_HELPER" bench-fwxaes "$BENCH_BYTES_FILE" "$PW"
            for method in "${BENCH_TEXT_METHODS[@]}"; do
                time_cmd_bench "${method}_py_correct" env BASEFWX_BENCH_WARMUP=0 \
                    "$PYTHON_BIN" "$PY_HELPER" bench-text "$method" "$BENCH_TEXT" "$PW"
            done
            for method in "${BENCH_HASH_METHODS[@]}"; do
                time_cmd_bench "${method}_py_correct" env BASEFWX_BENCH_WARMUP=0 \
                    "$PYTHON_BIN" "$PY_HELPER" bench-hash "$method" "$BENCH_TEXT"
            done
            time_cmd_bench "b512file_py_total" env BASEFWX_BENCH_WARMUP=0 \
                "$PYTHON_BIN" "$PY_HELPER" bench-b512file "$BENCH_BYTES_FILE" "$PW"
            time_cmd_bench "pb512file_py_total" env BASEFWX_BENCH_WARMUP=0 \
                "$PYTHON_BIN" "$PY_HELPER" bench-pb512file "$BENCH_BYTES_FILE" "$PW"
            ;;
        pypy)
            time_cmd_bench "fwxaes_pypy_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_HEAVY" \
                "$PYPY_BIN" "$PY_HELPER" bench-fwxaes "$BENCH_BYTES_FILE" "$PW"
            for method in "${BENCH_TEXT_METHODS[@]}"; do
                time_cmd_bench "${method}_pypy_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_LIGHT" \
                    "$PYPY_BIN" "$PY_HELPER" bench-text "$method" "$BENCH_TEXT" "$PW"
            done
            for method in "${BENCH_HASH_METHODS[@]}"; do
                time_cmd_bench "${method}_pypy_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_LIGHT" \
                    "$PYPY_BIN" "$PY_HELPER" bench-hash "$method" "$BENCH_TEXT"
            done
            time_cmd_bench "b512file_pypy_total" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_FILE" \
                "$PYPY_BIN" "$PY_HELPER" bench-b512file "$BENCH_BYTES_FILE" "$PW"
            time_cmd_bench "pb512file_pypy_total" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_FILE" \
                "$PYPY_BIN" "$PY_HELPER" bench-pb512file "$BENCH_BYTES_FILE" "$PW"
            ;;
        cpp)
            time_cmd_bench "fwxaes_cpp_correct" "$CPP_BIN" bench-fwxaes "$BENCH_BYTES_FILE" "$PW" --no-master
            for method in "${BENCH_TEXT_METHODS[@]}"; do
                if [[ "$method" == "b512" || "$method" == "pb512" ]]; then
                    time_cmd_bench "${method}_cpp_correct" "$CPP_BIN" bench-text "$method" "$BENCH_TEXT" -p "$PW" --no-master
                else
                    time_cmd_bench "${method}_cpp_correct" "$CPP_BIN" bench-text "$method" "$BENCH_TEXT"
                fi
            done
            for method in "${BENCH_HASH_METHODS[@]}"; do
                time_cmd_bench "${method}_cpp_correct" "$CPP_BIN" bench-hash "$method" "$BENCH_TEXT"
            done
            time_cmd_bench "b512file_cpp_total" "$CPP_BIN" bench-b512file "$BENCH_BYTES_FILE" "$PW" --no-master
            time_cmd_bench "pb512file_cpp_total" "$CPP_BIN" bench-pb512file "$BENCH_BYTES_FILE" "$PW" --no-master
            ;;
        java)
            time_cmd_bench "fwxaes_java_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_HEAVY" \
                "$JAVA_BIN" "${JAVA_BENCH_FLAGS_ARR[@]}" -jar "$JAVA_JAR" bench-fwxaes "$BENCH_BYTES_FILE" "$PW" --no-master
            for method in "${BENCH_TEXT_METHODS[@]}"; do
                time_cmd_bench "${method}_java_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_LIGHT" \
                    "$JAVA_BIN" "${JAVA_BENCH_FLAGS_ARR[@]}" -jar "$JAVA_JAR" bench-text "$method" "$BENCH_TEXT" "$PW" --no-master
            done
            for method in "${BENCH_HASH_METHODS[@]}"; do
                time_cmd_bench "${method}_java_correct" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_LIGHT" \
                    "$JAVA_BIN" "${JAVA_BENCH_FLAGS_ARR[@]}" -jar "$JAVA_JAR" bench-hash "$method" "$BENCH_TEXT"
            done
            time_cmd_bench "b512file_java_total" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_FILE" \
                "$JAVA_BIN" "${JAVA_BENCH_FLAGS_ARR[@]}" -jar "$JAVA_JAR" bench-b512file "$BENCH_BYTES_FILE" "$PW" --no-master
            time_cmd_bench "pb512file_java_total" env BASEFWX_BENCH_WARMUP="$BENCH_WARMUP_FILE" \
                "$JAVA_BIN" "${JAVA_BENCH_FLAGS_ARR[@]}" -jar "$JAVA_JAR" bench-pb512file "$BENCH_BYTES_FILE" "$PW" --no-master
            ;;
    esac
    if (( idx < ${#BENCH_LANGS[@]} - 1 )); then
        lang_cooldown "benchmark ${lang}"
    fi
done

phase "PHASE5: cleanup and summary"
if [[ "${BASEFWX_KEEP_TMP:-0}" != "1" ]]; then
    rm -rf "$TMP_DIR"
fi

format_ns() {
    awk -v ns="$1" 'BEGIN { printf "%.3f", ns / 1000000000 }'
}

format_delta() {
    local base_ns="$1"
    local other_ns="$2"
    if [[ -z "$base_ns" || -z "$other_ns" || "$base_ns" -le 0 ]]; then
        printf "n/a"
        return
    fi
    local abs_diff
    abs_diff=$(awk -v base="$base_ns" -v other="$other_ns" 'BEGIN { v=other-base; if (v<0) v=-v; printf "%.0f", v }')
    if (( abs_diff < 1000000 )); then
        printf "%s🔵 0.00%%%s" "$BLUE" "$RESET"
        return
    fi
    local base_for_pct="$base_ns"
    if (( base_for_pct < 10000000 )); then
        base_for_pct=10000000
    fi
    local pct abs_pct is_faster
    pct=$(awk -v base="$base_for_pct" -v other="$other_ns" 'BEGIN { printf "%.6f", (other-base)/base*100 }')
    abs_pct=$(awk -v p="$pct" 'BEGIN { v=p; if (v<0) v=-v; printf "%.6f", v }')
    is_faster=$(awk -v p="$pct" 'BEGIN { print (p < 0) ? 1 : 0 }')
    if (( is_faster == 1 )); then
        local gain
        gain=$(awk -v base="$base_for_pct" -v other="$other_ns" 'BEGIN { v=(base-other)/base*100; if (v<0) v=-v; if (v>999.99) v=999.99; printf "%.2f", v }')
        printf "%s%s +%s%%%s" "$GREEN" "$EMOJI_FAST" "$gain" "$RESET"
    else
        local loss
        loss=$(awk -v base="$base_for_pct" -v other="$other_ns" 'BEGIN { v=(other-base)/base*100; if (v<0) v=-v; if (v>999.99) v=999.99; printf "%.2f", v }')
        printf "%s%s -%s%%%s" "$RED" "$EMOJI_SLOW" "$loss" "$RESET"
    fi
}

print_lang_line() {
    local tag="$1"
    local time_s="$2"
    local delta="$3"
    local version="$4"
    if [[ -z "$time_s" ]]; then
        printf "%s n/a %s\n" "$tag" "$version"
        return
    fi
    if [[ -n "$delta" ]]; then
        printf "%s %ss %s %s\n" "$tag" "$time_s" "$delta" "$version"
    else
        printf "%s %ss %s\n" "$tag" "$time_s" "$version"
    fi
}

compare_speed_block() {
    local label="$1"
    local py_key="$2"
    local pypy_key="$3"
    local cpp_key="$4"
    local java_key="$5"
    local py_ns="${TIMES[$py_key]:-}"
    local pypy_ns=""
    local cpp_ns=""
    local java_ns=""
    if [[ -n "$pypy_key" ]]; then
        pypy_ns="${TIMES[$pypy_key]:-}"
    fi
    if [[ -n "$cpp_key" ]]; then
        cpp_ns="${TIMES[$cpp_key]:-}"
    fi
    if [[ -n "$java_key" ]]; then
        java_ns="${TIMES[$java_key]:-}"
    fi
    if [[ -z "$py_ns" && -z "$pypy_ns" && -z "$cpp_ns" && -z "$java_ns" ]]; then
        printf "%s: %s missing timing data%s\n" "$label" "$YELLOW$EMOJI_WARN" "$RESET"
        return
    fi
    local base_key=""
    local base_label="$BASELINE_LANG"
    case "$BASELINE_LANG" in
        py)
            base_key="$py_key"
            ;;
        pypy)
            base_key="$pypy_key"
            ;;
        cpp)
            base_key="$cpp_key"
            ;;
        java)
            base_key="$java_key"
            ;;
    esac
    local base_ns=""
    if [[ -n "$base_key" ]]; then
        base_ns="${TIMES[$base_key]:-}"
    fi
    if [[ -z "$base_ns" || "$base_ns" -le 0 ]]; then
        if [[ -n "$py_ns" ]]; then
            base_ns="$py_ns"
            base_label="py"
        elif [[ -n "$pypy_ns" ]]; then
            base_ns="$pypy_ns"
            base_label="pypy"
        elif [[ -n "$cpp_ns" ]]; then
            base_ns="$cpp_ns"
            base_label="cpp"
        else
            base_ns="$java_ns"
            base_label="java"
        fi
    fi
    local py_s="" pypy_s="" cpp_s="" java_s=""
    if [[ -n "$py_ns" ]]; then
        py_s=$(format_ns "$py_ns")
    fi
    if [[ -n "$pypy_ns" ]]; then
        pypy_s=$(format_ns "$pypy_ns")
    fi
    if [[ -n "$cpp_ns" ]]; then
        cpp_s=$(format_ns "$cpp_ns")
    fi
    if [[ -n "$java_ns" ]]; then
        java_s=$(format_ns "$java_ns")
    fi
    printf "%s:\n" "$label"
    local py_tag="${PY_VERSION_TAG:-py}"
    local pypy_tag="${PYPY_VERSION_TAG:-pypy}"
    local cpp_tag="${CPP_VERSION_TAG:-cpp}"
    local java_tag="${JAVA_VERSION_TAG:-java}"
    local py_delta=""
    if [[ "$base_label" == "py" ]]; then
        print_lang_line "🐍 Python" "$py_s" "" "$py_tag (baseline)"
    else
        if [[ -n "$py_ns" ]]; then
            py_delta="$(format_delta "$base_ns" "$py_ns")"
        fi
        print_lang_line "🐍 Python" "$py_s" "$py_delta" "$py_tag"
    fi
    if [[ -n "$pypy_ns" ]]; then
        local pypy_delta=""
        if [[ "$base_label" == "pypy" ]]; then
            print_lang_line "🥭 PyPy" "$pypy_s" "" "$pypy_tag (baseline)"
        else
            pypy_delta="$(format_delta "$base_ns" "$pypy_ns")"
            print_lang_line "🥭 PyPy" "$pypy_s" "$pypy_delta" "$pypy_tag"
        fi
    fi
    if [[ -n "$cpp_ns" ]]; then
        printf "%s\n" "-----------------------------"
        local cpp_delta=""
        if [[ "$base_label" == "cpp" ]]; then
            print_lang_line "⚙️ C++" "$cpp_s" "" "$cpp_tag (baseline)"
        else
            cpp_delta="$(format_delta "$base_ns" "$cpp_ns")"
            print_lang_line "⚙️ C++" "$cpp_s" "$cpp_delta" "$cpp_tag"
        fi
    fi
    if [[ -n "$java_ns" ]]; then
        printf "%s\n" "----------------------------"
        local java_delta=""
        if [[ "$base_label" == "java" ]]; then
            print_lang_line "☕ Java" "$java_s" "" "$java_tag (baseline)"
        else
            java_delta="$(format_delta "$base_ns" "$java_ns")"
            print_lang_line "☕ Java" "$java_s" "$java_delta" "$java_tag"
        fi
    fi
    printf "\n"
}

overall_sum_for_lang() {
    local lang="$1"
    local sum=0
    local count=0
    local entry label py_key pypy_key cpp_key java_key
    for entry in "${OVERALL_METHODS[@]}"; do
        IFS='|' read -r label py_key pypy_key cpp_key java_key <<<"$entry"
        local base_key=""
        case "$BASELINE_LANG" in
            py) base_key="$py_key" ;;
            pypy) base_key="$pypy_key" ;;
            cpp) base_key="$cpp_key" ;;
            java) base_key="$java_key" ;;
        esac
        local lang_key=""
        case "$lang" in
            py) lang_key="$py_key" ;;
            pypy) lang_key="$pypy_key" ;;
            cpp) lang_key="$cpp_key" ;;
            java) lang_key="$java_key" ;;
        esac
        local base_val="${TIMES[$base_key]:-}"
        local lang_val="${TIMES[$lang_key]:-}"
        if [[ -n "$base_val" && "$base_val" -gt 0 && -n "$lang_val" && "$lang_val" -gt 0 ]]; then
            sum=$((sum + lang_val))
            count=$((count + 1))
        fi
    done
    printf "%s|%s" "$sum" "$count"
}

overall_summary() {
    OVERALL_METHODS=(
        "fwxAES|fwxaes_py_correct|fwxaes_pypy_correct|fwxaes_cpp_correct|fwxaes_java_correct"
        "b256|b256_py_correct|b256_pypy_correct|b256_cpp_correct|b256_java_correct"
        "b512|b512_py_correct|b512_pypy_correct|b512_cpp_correct|b512_java_correct"
        "pb512|pb512_py_correct|pb512_pypy_correct|pb512_cpp_correct|pb512_java_correct"
        "b64|b64_py_correct|b64_pypy_correct|b64_cpp_correct|b64_java_correct"
        "a512|a512_py_correct|a512_pypy_correct|a512_cpp_correct|a512_java_correct"
        "hash512|hash512_py_correct|hash512_pypy_correct|hash512_cpp_correct|hash512_java_correct"
        "uhash513|uhash513_py_correct|uhash513_pypy_correct|uhash513_cpp_correct|uhash513_java_correct"
        "bi512|bi512_py_correct|bi512_pypy_correct|bi512_cpp_correct|bi512_java_correct"
        "b1024|b1024_py_correct|b1024_pypy_correct|b1024_cpp_correct|b1024_java_correct"
        "b512file|b512file_py_total|b512file_pypy_total|b512file_cpp_total|b512file_java_total"
        "pb512file|pb512file_py_total|pb512file_pypy_total|pb512file_cpp_total|pb512file_java_total"
    )
    local base_sum base_count
    IFS='|' read -r base_sum base_count <<<"$(overall_sum_for_lang "$BASELINE_LANG")"
    if [[ -z "$base_sum" || "$base_sum" -le 0 || "$base_count" -le 0 ]]; then
        return
    fi
    printf "OVERALL:\n"
    local py_sum py_count pypy_sum pypy_count cpp_sum cpp_count java_sum java_count
    IFS='|' read -r py_sum py_count <<<"$(overall_sum_for_lang py)"
    if [[ "$RUN_PY_TESTS" == "1" && "$py_count" -gt 0 ]]; then
        local py_delta=""
        if [[ "$BASELINE_LANG" != "py" ]]; then
            py_delta="$(format_delta "$base_sum" "$py_sum")"
        fi
        local py_tag="${PY_VERSION_TAG} (${py_count}/${base_count})"
        if [[ "$BASELINE_LANG" == "py" ]]; then
            py_tag="${PY_VERSION_TAG} (baseline, ${py_count}/${base_count})"
        fi
        print_lang_line "🐍 Python" "$(format_ns "$py_sum")" "$py_delta" "$py_tag"
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        IFS='|' read -r pypy_sum pypy_count <<<"$(overall_sum_for_lang pypy)"
        if [[ "$pypy_count" -gt 0 ]]; then
            local pypy_delta=""
            if [[ "$BASELINE_LANG" != "pypy" ]]; then
                pypy_delta="$(format_delta "$base_sum" "$pypy_sum")"
            fi
            local pypy_tag="${PYPY_VERSION_TAG} (${pypy_count}/${base_count})"
            if [[ "$BASELINE_LANG" == "pypy" ]]; then
                pypy_tag="${PYPY_VERSION_TAG} (baseline, ${pypy_count}/${base_count})"
            fi
            print_lang_line "🥭 PyPy" "$(format_ns "$pypy_sum")" "$pypy_delta" "$pypy_tag"
        fi
    fi
    if [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
        IFS='|' read -r cpp_sum cpp_count <<<"$(overall_sum_for_lang cpp)"
        if [[ "$cpp_count" -gt 0 ]]; then
            printf "%s\n" "-----------------------------"
            local cpp_delta=""
            if [[ "$BASELINE_LANG" != "cpp" ]]; then
                cpp_delta="$(format_delta "$base_sum" "$cpp_sum")"
            fi
            local cpp_tag="${CPP_VERSION_TAG} (${cpp_count}/${base_count})"
            if [[ "$BASELINE_LANG" == "cpp" ]]; then
                cpp_tag="${CPP_VERSION_TAG} (baseline, ${cpp_count}/${base_count})"
            fi
            print_lang_line "⚙️ C++" "$(format_ns "$cpp_sum")" "$cpp_delta" "$cpp_tag"
        fi
    fi
    if [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
        IFS='|' read -r java_sum java_count <<<"$(overall_sum_for_lang java)"
        if [[ "$java_count" -gt 0 ]]; then
            printf "%s\n" "----------------------------"
            local java_delta=""
            if [[ "$BASELINE_LANG" != "java" ]]; then
                java_delta="$(format_delta "$base_sum" "$java_sum")"
            fi
            local java_tag="${JAVA_VERSION_TAG} (${java_count}/${base_count})"
            if [[ "$BASELINE_LANG" == "java" ]]; then
                java_tag="${JAVA_VERSION_TAG} (baseline, ${java_count}/${base_count})"
            fi
            print_lang_line "☕ Java" "$(format_ns "$java_sum")" "$java_delta" "$java_tag"
        fi
    fi
    printf "\n"
}

printf "\nTiming summary (native):\n"
compare_speed_block "fwxAES" "fwxaes_py_correct" "fwxaes_pypy_correct" "fwxaes_cpp_correct" "fwxaes_java_correct"
compare_speed_block "b256" "b256_py_correct" "b256_pypy_correct" "b256_cpp_correct" "b256_java_correct"
compare_speed_block "b512" "b512_py_correct" "b512_pypy_correct" "b512_cpp_correct" "b512_java_correct"
compare_speed_block "pb512" "pb512_py_correct" "pb512_pypy_correct" "pb512_cpp_correct" "pb512_java_correct"
compare_speed_block "b64" "b64_py_correct" "b64_pypy_correct" "b64_cpp_correct" "b64_java_correct"
compare_speed_block "a512" "a512_py_correct" "a512_pypy_correct" "a512_cpp_correct" "a512_java_correct"
compare_speed_block "hash512" "hash512_py_correct" "hash512_pypy_correct" "hash512_cpp_correct" "hash512_java_correct"
compare_speed_block "uhash513" "uhash513_py_correct" "uhash513_pypy_correct" "uhash513_cpp_correct" "uhash513_java_correct"
compare_speed_block "bi512" "bi512_py_correct" "bi512_pypy_correct" "bi512_cpp_correct" "bi512_java_correct"
compare_speed_block "b1024" "b1024_py_correct" "b1024_pypy_correct" "b1024_cpp_correct" "b1024_java_correct"
if [[ "$RUN_PY_TESTS" == "1" && -z "${TIMES[b512file_py_total]-}" ]]; then
    TIMES["b512file_py_total"]=$B512FILE_PY_TOTAL
    TIMES["pb512file_py_total"]=$PB512FILE_PY_TOTAL
fi
if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" && -z "${TIMES[b512file_pypy_total]-}" ]]; then
    TIMES["b512file_pypy_total"]=$B512FILE_PYPY_TOTAL
    TIMES["pb512file_pypy_total"]=$PB512FILE_PYPY_TOTAL
fi
if [[ "$RUN_CPP_TESTS" == "1" && -z "${TIMES[b512file_cpp_total]-}" ]]; then
    TIMES["b512file_cpp_total"]=$B512FILE_CPP_TOTAL
    TIMES["pb512file_cpp_total"]=$PB512FILE_CPP_TOTAL
fi
if [[ "$RUN_JAVA_TESTS" == "1" && -z "${TIMES[b512file_java_total]-}" ]]; then
    TIMES["b512file_java_total"]=$B512FILE_JAVA_TOTAL
    TIMES["pb512file_java_total"]=$PB512FILE_JAVA_TOTAL
fi
compare_speed_block "b512file" "b512file_py_total" "b512file_pypy_total" "b512file_cpp_total" "b512file_java_total"
compare_speed_block "pb512file" "pb512file_py_total" "pb512file_pypy_total" "pb512file_cpp_total" "pb512file_java_total"

overall_summary

if (( ${#FAILURES[@]} > 0 )); then
    printf "\n%sFAILURES%s (%d):\n" "$RED$EMOJI_FAIL " "$RESET" "${#FAILURES[@]}"
    for failure in "${FAILURES[@]}"; do
        printf " - %s\n" "$failure"
    done
    printf "See diagnose.log for details.\n"
    printf "\n---- diagnose.log ----\n"
    cat "$LOG"
    exit 1
fi

printf "\n%sAll tests passed.%s See diagnose.log for details.\n" "$GREEN$EMOJI_OK " "$RESET"
exit 0
