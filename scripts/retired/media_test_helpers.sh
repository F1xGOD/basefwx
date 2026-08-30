#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

# Compatibility-only jMG/kFM/kFA helpers sourced by test_all.sh when the
# retired media profile is explicitly enabled. This file is not standalone.

RETIRED_PY_HELPER="$ROOT/python/tests/retired/test_all_helper.py"

retired_media_step_count() {
    local count=0
    local case_count="${#JMG_CASES[@]}"
    if (( case_count == 0 )); then
        printf '0\n'
        return
    fi
    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        count=$((count + case_count))
    fi
    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        count=$((count + case_count))
    fi
    if [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]]; then
        count=$((count + case_count))
    fi
    if [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; then
        count=$((count + case_count))
    fi
    if [[ "$SKIP_CROSS" != "1" ]]; then
        if [[ "$RUN_PY_TESTS" == "1" && "$RUN_CPP_TESTS" == "1" \
            && "$CPP_AVAILABLE" == "1" ]]; then
            count=$((count + 2 * case_count))
        fi
        if [[ "$RUN_PY_TESTS" == "1" && "$RUN_JAVA_TESTS" == "1" \
            && "$JAVA_AVAILABLE" == "1" ]]; then
            count=$((count + 2 * case_count))
        fi
    fi
    printf '%d\n' "$count"
}

create_retired_media_fixtures() {
    local fixture_helper="$ROOT/scripts/retired/create_media_fixtures.py"
    log "CMD[generate_retired_media_fixtures]: $PYTHON_BIN $fixture_helper $ORIG_DIR"
    run_with_heartbeat "generate_retired_media_fixtures" \
        "$PYTHON_BIN" "$fixture_helper" "$ORIG_DIR"
    local fixture_rc=$?
    log "TIME[generate_retired_media_fixtures]: rc=${fixture_rc}"
    if (( fixture_rc != 0 )); then
        FAILURES+=("generate_retired_media_fixtures (rc=${fixture_rc})")
        return "$fixture_rc"
    fi
}

py_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: python jmg-enc $input"
    "$PYTHON_BIN" "$RETIRED_PY_HELPER" jmg-roundtrip "$input" "$enc" "$dec" "$PW"
}

py_jmg_roundtrip_no_archive() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: python jmg-enc(no-archive) $input"
    "$PYTHON_BIN" "$RETIRED_PY_HELPER" jmg-roundtrip-no-archive "$input" "$enc" "$dec" "$PW"
}

py_jmg_roundtrip_gpu_logged() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    local hwlog="$TMP_DIR/jmg_py_gpu_hw_$(basename "$enc").log"
    rm -f "$hwlog"
    log "STEP: python jmg-enc (gpu+hwlog) $input"
    env BASEFWX_HWACCEL=nvenc BASEFWX_HWACCEL_STRICT=1 \
        "$PYTHON_BIN" "$RETIRED_PY_HELPER" jmg-roundtrip "$input" "$enc" "$dec" "$PW" >>"$LOG" 2>"$hwlog" || {
        cat "$hwlog" >>"$LOG"
        return 1
    }
    cat "$hwlog" >>"$LOG"
    if ! grep -q "\\[basefwx.hw\\].*op=jMGe" "$hwlog"; then
        log "Missing hardware routing log for jMGe in GPU path"
        return 1
    fi
    if ! grep -q "\\[basefwx.hw\\].*op=jMGd" "$hwlog"; then
        log "Missing hardware routing log for jMGd in GPU path"
        return 1
    fi
    return 0
}

pypy_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: pypy jmg-enc $input"
    "$PYPY_BIN" "$RETIRED_PY_HELPER" jmg-roundtrip "$input" "$enc" "$dec" "$PW"
}

py_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: python jmg-enc $input"
    "$PYTHON_BIN" "$RETIRED_PY_HELPER" jmg-enc "$input" "$enc" "$PW"
}

pypy_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: pypy jmg-enc $input"
    "$PYPY_BIN" "$RETIRED_PY_HELPER" jmg-enc "$input" "$enc" "$PW"
}

py_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: python jmg-dec $input"
    "$PYTHON_BIN" "$RETIRED_PY_HELPER" jmg-dec "$input" "$dec" "$PW"
}

pypy_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: pypy jmg-dec $input"
    "$PYPY_BIN" "$RETIRED_PY_HELPER" jmg-dec "$input" "$dec" "$PW"
}

cpp_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $CPP_BIN jmge $input --archive"
    "$CPP_BIN" jmge "$input" -p "$PW" --archive --out "$enc" || return $?
    log "STEP: $CPP_BIN jmgd $enc"
    "$CPP_BIN" jmgd "$enc" -p "$PW" --out "$dec"
}

cpp_jmg_roundtrip_no_archive() {
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
    log "STEP: $CPP_BIN jmge $input --archive"
    "$CPP_BIN" jmge "$input" -p "$PW" --archive --out "$enc"
}

cpp_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: $CPP_BIN jmgd $input"
    "$CPP_BIN" jmgd "$input" -p "$PW" --out "$dec"
}

java_jmg_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmge $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmge "$input" "$enc" "$PW" || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmgd $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmgd "$enc" "$dec" "$PW"
}

java_jmg_roundtrip_no_archive() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmge $input --no-archive"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmge "$input" "$enc" "$PW" --no-archive || return $?
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmgd $enc"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmgd "$enc" "$dec" "$PW"
}

java_jmg_enc() {
    local input="$1"
    local enc="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmge $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmge "$input" "$enc" "$PW"
}

java_jmg_dec() {
    local input="$1"
    local dec="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR jmgd $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" jmgd "$input" "$dec" "$PW"
}

py_kfme() {
    local input="$1"
    local out="$2"
    log "STEP: python -m basefwx kFMe $input"
    "$PYTHON_BIN" -m basefwx kFMe "$input" --out "$out"
}

py_kfmd() {
    local input="$1"
    local out="$2"
    log "STEP: python -m basefwx kFMd $input"
    "$PYTHON_BIN" -m basefwx kFMd "$input" --out "$out"
}

py_kfae() {
    local input="$1"
    local out="$2"
    log "STEP: python -m basefwx kFAe $input (legacy PNG mode)"
    "$PYTHON_BIN" -m basefwx kFAe "$input" --out "$out"
}

py_kfad() {
    local input="$1"
    local out="$2"
    log "STEP: python -m basefwx kFAd $input (legacy decode alias)"
    "$PYTHON_BIN" -m basefwx kFAd "$input" --out "$out"
}

pypy_kfme() {
    local input="$1"
    local out="$2"
    log "STEP: pypy -m basefwx kFMe $input"
    "$PYPY_BIN" -m basefwx kFMe "$input" --out "$out"
}

pypy_kfmd() {
    local input="$1"
    local out="$2"
    log "STEP: pypy -m basefwx kFMd $input"
    "$PYPY_BIN" -m basefwx kFMd "$input" --out "$out"
}

pypy_kfae() {
    local input="$1"
    local out="$2"
    log "STEP: pypy -m basefwx kFAe $input (legacy PNG mode)"
    "$PYPY_BIN" -m basefwx kFAe "$input" --out "$out"
}

pypy_kfad() {
    local input="$1"
    local out="$2"
    log "STEP: pypy -m basefwx kFAd $input (legacy decode alias)"
    "$PYPY_BIN" -m basefwx kFAd "$input" --out "$out"
}

cpp_kfme() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN kFMe $input"
    "$CPP_BIN" kFMe "$input" --out "$out"
}

cpp_kfmd() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN kFMd $input"
    "$CPP_BIN" kFMd "$input" --out "$out"
}

cpp_kfae() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN kFAe $input (legacy PNG mode)"
    "$CPP_BIN" kFAe "$input" --out "$out"
}

cpp_kfad() {
    local input="$1"
    local out="$2"
    log "STEP: $CPP_BIN kFAd $input (legacy decode alias)"
    "$CPP_BIN" kFAd "$input" --out "$out"
}

java_kfme() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR kFMe $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" kFMe "$input" --out "$out"
}

java_kfmd() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR kFMd $input"
    "$JAVA_BIN" -jar "$JAVA_JAR" kFMd "$input" --out "$out"
}

java_kfae() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR kFAe $input (legacy PNG mode)"
    "$JAVA_BIN" -jar "$JAVA_JAR" kFAe "$input" --out "$out"
}

java_kfad() {
    local input="$1"
    local out="$2"
    log "STEP: $JAVA_BIN -jar $JAVA_JAR kFAd $input (legacy decode alias)"
    "$JAVA_BIN" -jar "$JAVA_JAR" kFAd "$input" --out "$out"
}

kfme_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfme "$input" "$enc" || return $?
    cpp_kfmd "$enc" "$dec"
}

kfme_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfme "$input" "$enc" || return $?
    py_kfmd "$enc" "$dec"
}

kfae_py_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfae "$input" "$enc" || return $?
    cpp_kfad "$enc" "$dec"
}

kfae_cpp_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfae "$input" "$enc" || return $?
    py_kfad "$enc" "$dec"
}

kfme_py_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfme "$input" "$enc" || return $?
    java_kfmd "$enc" "$dec"
}

kfme_java_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfme "$input" "$enc" || return $?
    py_kfmd "$enc" "$dec"
}

kfae_py_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfae "$input" "$enc" || return $?
    java_kfad "$enc" "$dec"
}

kfae_java_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfae "$input" "$enc" || return $?
    py_kfad "$enc" "$dec"
}

kfme_cpp_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfme "$input" "$enc" || return $?
    java_kfmd "$enc" "$dec"
}

kfme_java_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfme "$input" "$enc" || return $?
    cpp_kfmd "$enc" "$dec"
}

kfae_cpp_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfae "$input" "$enc" || return $?
    java_kfad "$enc" "$dec"
}

kfae_java_enc_cpp_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfae "$input" "$enc" || return $?
    cpp_kfad "$enc" "$dec"
}

kfme_py_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfme "$input" "$enc" || return $?
    py_kfmd "$enc" "$dec"
}

kfme_pypy_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    pypy_kfme "$input" "$enc" || return $?
    pypy_kfmd "$enc" "$dec"
}

kfme_cpp_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfme "$input" "$enc" || return $?
    cpp_kfmd "$enc" "$dec"
}

kfme_java_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfme "$input" "$enc" || return $?
    java_kfmd "$enc" "$dec"
}

kfae_py_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_kfae "$input" "$enc" || return $?
    py_kfad "$enc" "$dec"
}

kfae_pypy_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    pypy_kfae "$input" "$enc" || return $?
    pypy_kfad "$enc" "$dec"
}

kfae_cpp_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    cpp_kfae "$input" "$enc" || return $?
    cpp_kfad "$enc" "$dec"
}

kfae_java_roundtrip() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_kfae "$input" "$enc" || return $?
    java_kfad "$enc" "$dec"
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

jmg_py_enc_java_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    py_jmg_enc "$input" "$enc" || return $?
    java_jmg_dec "$enc" "$dec"
}

jmg_java_enc_py_dec() {
    local input="$1"
    local enc="$2"
    local dec="$3"
    java_jmg_enc "$input" "$enc" || return $?
    py_jmg_dec "$enc" "$dec"
}


run_retired_native_tests_block() {
if (( ${#JMG_CASES[@]} > 0 )) && { [[ "$RUN_PY_TESTS" == "1" ]] || [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]] || [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]] || [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; }; then
    phase "PHASE2.1: jMG media tests (${PHASE2_LABEL:-native})"
    for file_name in "${JMG_CASES[@]}"; do
        tag="$(case_tag "$file_name")"
        if [[ "$RUN_PY_TESTS" == "1" ]]; then
            jmg_py_input="$(copy_input "jmg_py_${tag}" "$file_name")"
            jmg_py_enc="$WORK_DIR/jmg_py_${tag}/enc_${file_name}"
            jmg_py_dec="$WORK_DIR/jmg_py_${tag}/dec_${file_name}"
            time_cmd "jmg_py_${tag}" py_jmg_roundtrip "$jmg_py_input" "$jmg_py_enc" "$jmg_py_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_py_dec"

            jmg_py_noa_input="$(copy_input "jmg_py_noarchive_${tag}" "$file_name")"
            jmg_py_noa_enc="$WORK_DIR/jmg_py_noarchive_${tag}/enc_${file_name}"
            jmg_py_noa_dec="$WORK_DIR/jmg_py_noarchive_${tag}/dec_${file_name}"
            time_cmd "jmg_py_noarchive_${tag}" py_jmg_roundtrip_no_archive "$jmg_py_noa_input" "$jmg_py_noa_enc" "$jmg_py_noa_dec"
            if [[ ! -s "$jmg_py_noa_dec" ]]; then
                FAILURES+=("jmg_py_noarchive_${tag} (decode empty)")
            fi

            if (( NVIDIA_HWACCEL_AVAILABLE == 1 )) && [[ "$file_name" == *.mp4 || "$file_name" == *.mkv || "$file_name" == *.mov ]]; then
                jmg_py_gpu_input="$(copy_input "jmg_py_gpu_${tag}" "$file_name")"
                jmg_py_gpu_enc="$WORK_DIR/jmg_py_gpu_${tag}/enc_${file_name}"
                jmg_py_gpu_dec="$WORK_DIR/jmg_py_gpu_${tag}/dec_${file_name}"
                time_cmd "jmg_py_gpu_${tag}" py_jmg_roundtrip_gpu_logged \
                    "$jmg_py_gpu_input" "$jmg_py_gpu_enc" "$jmg_py_gpu_dec"
                add_verify "$ORIG_DIR/$file_name" "$jmg_py_gpu_dec"
            fi
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

                jmg_cpp_noa_input="$(copy_input "jmg_cpp_noarchive_${tag}" "$file_name")"
                jmg_cpp_noa_enc="$WORK_DIR/jmg_cpp_noarchive_${tag}/enc_${file_name}"
                jmg_cpp_noa_dec="$WORK_DIR/jmg_cpp_noarchive_${tag}/dec_${file_name}"
                time_cmd "jmg_cpp_noarchive_${tag}" cpp_jmg_roundtrip_no_archive \
                    "$jmg_cpp_noa_input" "$jmg_cpp_noa_enc" "$jmg_cpp_noa_dec"
                if [[ ! -s "$jmg_cpp_noa_dec" ]]; then
                    FAILURES+=("jmg_cpp_noarchive_${tag} (decode empty)")
                fi

                if (( NVIDIA_HWACCEL_AVAILABLE == 1 )) && [[ "$file_name" == *.mp4 || "$file_name" == *.mkv || "$file_name" == *.mov ]]; then
                    jmg_cpp_gpu_input="$(copy_input "jmg_cpp_gpu_${tag}" "$file_name")"
                    jmg_cpp_gpu_enc="$WORK_DIR/jmg_cpp_gpu_${tag}/enc_${file_name}"
                    jmg_cpp_gpu_dec="$WORK_DIR/jmg_cpp_gpu_${tag}/dec_${file_name}"
                    time_cmd "jmg_cpp_gpu_${tag}" env BASEFWX_HWACCEL=nvenc cpp_jmg_roundtrip \
                        "$jmg_cpp_gpu_input" "$jmg_cpp_gpu_enc" "$jmg_cpp_gpu_dec"
                    add_verify "$ORIG_DIR/$file_name" "$jmg_cpp_gpu_dec"
                fi
            else
                FAILURES+=("jmg_cpp_${tag} (cpp unavailable)")
            fi
        fi
        if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
            jmg_java_input="$(copy_input "jmg_java_${tag}" "$file_name")"
            jmg_java_enc="$WORK_DIR/jmg_java_${tag}/enc_${file_name}"
            jmg_java_dec="$WORK_DIR/jmg_java_${tag}/dec_${file_name}"
            if (( JAVA_AVAILABLE == 1 )); then
                cooldown "jmg_cpp_to_java_${tag}"
                time_cmd "jmg_java_${tag}" java_jmg_roundtrip "$jmg_java_input" "$jmg_java_enc" "$jmg_java_dec"
                add_verify "$ORIG_DIR/$file_name" "$jmg_java_dec"

                jmg_java_noa_input="$(copy_input "jmg_java_noarchive_${tag}" "$file_name")"
                jmg_java_noa_enc="$WORK_DIR/jmg_java_noarchive_${tag}/enc_${file_name}"
                jmg_java_noa_dec="$WORK_DIR/jmg_java_noarchive_${tag}/dec_${file_name}"
                time_cmd "jmg_java_noarchive_${tag}" java_jmg_roundtrip_no_archive \
                    "$jmg_java_noa_input" "$jmg_java_noa_enc" "$jmg_java_noa_dec"
                if [[ ! -s "$jmg_java_noa_dec" ]]; then
                    FAILURES+=("jmg_java_noarchive_${tag} (decode empty)")
                fi
            else
                FAILURES+=("jmg_java_${tag} (java unavailable)")
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

if (( RETIRED_MEDIA_ENABLED == 1 )) && { \
    [[ "$RUN_PY_TESTS" == "1" ]] \
    || [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]] \
    || [[ "$RUN_CPP_TESTS" == "1" && "$CPP_AVAILABLE" == "1" ]] \
    || [[ "$RUN_JAVA_TESTS" == "1" && "$JAVA_AVAILABLE" == "1" ]]; \
}; then
    phase "PHASE2.15: kFM/kFA carrier tests (${PHASE2_LABEL:-native})"

    if [[ "$RUN_PY_TESTS" == "1" ]]; then
        kfme_py_input="$(copy_input "kfme_py_correct" "$KFM_FILE")"
        kfme_py_enc="$WORK_DIR/kfme_py_correct/carrier.wav"
        kfme_py_dec="$WORK_DIR/kfme_py_correct/decoded_${KFM_FILE}"
        time_cmd "kfme_py_correct" kfme_py_roundtrip "$kfme_py_input" "$kfme_py_enc" "$kfme_py_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_py_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_py_input"

        kfae_py_input="$(copy_input "kfae_py_correct" "$KFM_FILE")"
        kfae_py_enc="$WORK_DIR/kfae_py_correct/carrier.png"
        kfae_py_dec="$WORK_DIR/kfae_py_correct/decoded_${KFM_FILE}"
        time_cmd "kfae_py_correct" kfae_py_roundtrip "$kfae_py_input" "$kfae_py_enc" "$kfae_py_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_py_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_py_input"
    fi

    if [[ "$RUN_PYPY_TESTS" == "1" && "$PYPY_AVAILABLE" == "1" ]]; then
        kfme_pypy_input="$(copy_input "kfme_pypy_correct" "$KFM_FILE")"
        kfme_pypy_enc="$WORK_DIR/kfme_pypy_correct/carrier.wav"
        kfme_pypy_dec="$WORK_DIR/kfme_pypy_correct/decoded_${KFM_FILE}"
        time_cmd "kfme_pypy_correct" kfme_pypy_roundtrip "$kfme_pypy_input" "$kfme_pypy_enc" "$kfme_pypy_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pypy_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pypy_input"

        kfae_pypy_input="$(copy_input "kfae_pypy_correct" "$KFM_FILE")"
        kfae_pypy_enc="$WORK_DIR/kfae_pypy_correct/carrier.png"
        kfae_pypy_dec="$WORK_DIR/kfae_pypy_correct/decoded_${KFM_FILE}"
        time_cmd "kfae_pypy_correct" kfae_pypy_roundtrip "$kfae_pypy_input" "$kfae_pypy_enc" "$kfae_pypy_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pypy_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pypy_input"
    fi

    if [[ "$RUN_CPP_TESTS" == "1" ]]; then
        kfme_cpp_input="$(copy_input "kfme_cpp_correct" "$KFM_FILE")"
        kfme_cpp_enc="$WORK_DIR/kfme_cpp_correct/carrier.wav"
        kfme_cpp_dec="$WORK_DIR/kfme_cpp_correct/decoded_${KFM_FILE}"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "kfme_py_to_cpp_correct"
            time_cmd "kfme_cpp_correct" kfme_cpp_roundtrip "$kfme_cpp_input" "$kfme_cpp_enc" "$kfme_cpp_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cpp_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cpp_input"
        else
            FAILURES+=("kfme_cpp_correct (cpp unavailable)")
        fi

        kfae_cpp_input="$(copy_input "kfae_cpp_correct" "$KFM_FILE")"
        kfae_cpp_enc="$WORK_DIR/kfae_cpp_correct/carrier.png"
        kfae_cpp_dec="$WORK_DIR/kfae_cpp_correct/decoded_${KFM_FILE}"
        if (( CPP_AVAILABLE == 1 )); then
            cooldown "kfae_py_to_cpp_correct"
            time_cmd "kfae_cpp_correct" kfae_cpp_roundtrip "$kfae_cpp_input" "$kfae_cpp_enc" "$kfae_cpp_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cpp_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cpp_input"
        else
            FAILURES+=("kfae_cpp_correct (cpp unavailable)")
        fi
    fi

    if [[ "$RUN_JAVA_TESTS" == "1" ]]; then
        kfme_java_input="$(copy_input "kfme_java_correct" "$KFM_FILE")"
        kfme_java_enc="$WORK_DIR/kfme_java_correct/carrier.wav"
        kfme_java_dec="$WORK_DIR/kfme_java_correct/decoded_${KFM_FILE}"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "kfme_cpp_to_java_correct"
            time_cmd "kfme_java_correct" kfme_java_roundtrip "$kfme_java_input" "$kfme_java_enc" "$kfme_java_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_java_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_java_input"
        else
            FAILURES+=("kfme_java_correct (java unavailable)")
        fi

        kfae_java_input="$(copy_input "kfae_java_correct" "$KFM_FILE")"
        kfae_java_enc="$WORK_DIR/kfae_java_correct/carrier.png"
        kfae_java_dec="$WORK_DIR/kfae_java_correct/decoded_${KFM_FILE}"
        if (( JAVA_AVAILABLE == 1 )); then
            cooldown "kfae_cpp_to_java_correct"
            time_cmd "kfae_java_correct" kfae_java_roundtrip "$kfae_java_input" "$kfae_java_enc" "$kfae_java_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_java_dec"
            add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_java_input"
        else
            FAILURES+=("kfae_java_correct (java unavailable)")
        fi
    fi
else
    phase "PHASE2.15: kFM/kFA carrier tests (${PHASE2_LABEL:-native}, skipped)"
fi
}
configure_retired_media_cases() {
KFM_FILE="kfm_payload.bin"
JMG_CASES=()
JMG_VIDEO_CASES_ENABLED="${BASEFWX_ENABLE_JMG_VIDEO:-0}"
if (( RETIRED_MEDIA_ENABLED == 1 )); then
    for file_name in "jmg_sample.png" "media_sample.m4a"; do
        if [[ -f "$ORIG_DIR/$file_name" ]]; then
            JMG_CASES+=("$file_name")
        fi
    done
    if [[ "$JMG_VIDEO_CASES_ENABLED" == "1" || "$JMG_VIDEO_CASES_ENABLED" == "true" || "$JMG_VIDEO_CASES_ENABLED" == "yes" || "$JMG_VIDEO_CASES_ENABLED" == "on" ]]; then
        if [[ -f "$ORIG_DIR/media_sample.mp4" ]]; then
            JMG_CASES+=("media_sample.mp4")
        fi
    fi
fi
}

configure_retired_media_benchmark_fixture() {
    BENCH_KFM_FILE="$ORIG_DIR/$KFM_FILE"
    if [[ ! -f "$BENCH_KFM_FILE" ]]; then
        BENCH_KFM_FILE="$BENCH_BYTES_FILE"
    fi
    log "BENCH_KFM_FILE: $BENCH_KFM_FILE"
}
run_retired_python_cpp_cross_tests() {
        # Retired kFM/kFA cross-compat (Python <-> C++).
        if (( RETIRED_MEDIA_ENABLED == 1 )); then
        kfme_pycc_input="$(copy_input "kfme_pycc" "$KFM_FILE")"
        kfme_pycc_enc="$WORK_DIR/kfme_pycc/carrier.wav"
        kfme_pycc_dec="$WORK_DIR/kfme_pycc/decoded_${KFM_FILE}"
        time_cmd "kfme_py_enc_cpp_dec" kfme_py_enc_cpp_dec "$kfme_pycc_input" "$kfme_pycc_enc" "$kfme_pycc_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pycc_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pycc_input"

        kfme_cpyp_input="$(copy_input "kfme_cpyp" "$KFM_FILE")"
        kfme_cpyp_enc="$WORK_DIR/kfme_cpyp/carrier.wav"
        kfme_cpyp_dec="$WORK_DIR/kfme_cpyp/decoded_${KFM_FILE}"
        time_cmd "kfme_cpp_enc_py_dec" kfme_cpp_enc_py_dec "$kfme_cpyp_input" "$kfme_cpyp_enc" "$kfme_cpyp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cpyp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cpyp_input"

        kfae_pycc_input="$(copy_input "kfae_pycc" "$KFM_FILE")"
        kfae_pycc_enc="$WORK_DIR/kfae_pycc/carrier.png"
        kfae_pycc_dec="$WORK_DIR/kfae_pycc/decoded_${KFM_FILE}"
        time_cmd "kfae_py_enc_cpp_dec" kfae_py_enc_cpp_dec "$kfae_pycc_input" "$kfae_pycc_enc" "$kfae_pycc_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pycc_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pycc_input"

        kfae_cpyp_input="$(copy_input "kfae_cpyp" "$KFM_FILE")"
        kfae_cpyp_enc="$WORK_DIR/kfae_cpyp/carrier.png"
        kfae_cpyp_dec="$WORK_DIR/kfae_cpyp/decoded_${KFM_FILE}"
        time_cmd "kfae_cpp_enc_py_dec" kfae_cpp_enc_py_dec "$kfae_cpyp_input" "$kfae_cpyp_enc" "$kfae_cpyp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cpyp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cpyp_input"

        for file_name in "${JMG_CASES[@]}"; do
            tag="$(case_tag "$file_name")"
            jmg_pycc_input="$(copy_input "jmg_pycc_${tag}" "$file_name")"
            jmg_pycc_enc="$WORK_DIR/jmg_pycc_${tag}/enc_${file_name}"
            jmg_pycc_dec="$WORK_DIR/jmg_pycc_${tag}/dec_${file_name}"
            time_cmd "jmg_py_enc_cpp_dec_${tag}" jmg_py_enc_cpp_dec \
                "$jmg_pycc_input" "$jmg_pycc_enc" "$jmg_pycc_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_pycc_dec"

            jmg_cpyp_input="$(copy_input "jmg_cpyp_${tag}" "$file_name")"
            jmg_cpyp_enc="$WORK_DIR/jmg_cpyp_${tag}/enc_${file_name}"
            jmg_cpyp_dec="$WORK_DIR/jmg_cpyp_${tag}/dec_${file_name}"
            time_cmd "jmg_cpp_enc_py_dec_${tag}" jmg_cpp_enc_py_dec \
                "$jmg_cpyp_input" "$jmg_cpyp_enc" "$jmg_cpyp_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_cpyp_dec"
        done
        fi
}

run_retired_python_java_cross_tests() {
        # Retired kFM/kFA cross-compat (Python <-> Java).
        if (( RETIRED_MEDIA_ENABLED == 1 )); then
        kfme_pyj_input="$(copy_input "kfme_pyj" "$KFM_FILE")"
        kfme_pyj_enc="$WORK_DIR/kfme_pyj/carrier.wav"
        kfme_pyj_dec="$WORK_DIR/kfme_pyj/decoded_${KFM_FILE}"
        time_cmd "kfme_py_enc_java_dec" kfme_py_enc_java_dec "$kfme_pyj_input" "$kfme_pyj_enc" "$kfme_pyj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pyj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_pyj_input"

        kfme_jp_input="$(copy_input "kfme_jp" "$KFM_FILE")"
        kfme_jp_enc="$WORK_DIR/kfme_jp/carrier.wav"
        kfme_jp_dec="$WORK_DIR/kfme_jp/decoded_${KFM_FILE}"
        time_cmd "kfme_java_enc_py_dec" kfme_java_enc_py_dec "$kfme_jp_input" "$kfme_jp_enc" "$kfme_jp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_jp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_jp_input"

        kfae_pyj_input="$(copy_input "kfae_pyj" "$KFM_FILE")"
        kfae_pyj_enc="$WORK_DIR/kfae_pyj/carrier.png"
        kfae_pyj_dec="$WORK_DIR/kfae_pyj/decoded_${KFM_FILE}"
        time_cmd "kfae_py_enc_java_dec" kfae_py_enc_java_dec "$kfae_pyj_input" "$kfae_pyj_enc" "$kfae_pyj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pyj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_pyj_input"

        kfae_jp_input="$(copy_input "kfae_jp" "$KFM_FILE")"
        kfae_jp_enc="$WORK_DIR/kfae_jp/carrier.png"
        kfae_jp_dec="$WORK_DIR/kfae_jp/decoded_${KFM_FILE}"
        time_cmd "kfae_java_enc_py_dec" kfae_java_enc_py_dec "$kfae_jp_input" "$kfae_jp_enc" "$kfae_jp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_jp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_jp_input"

        for file_name in "${JMG_CASES[@]}"; do
            tag="$(case_tag "$file_name")"
            jmg_pyj_input="$(copy_input "jmg_pyj_${tag}" "$file_name")"
            jmg_pyj_enc="$WORK_DIR/jmg_pyj_${tag}/enc_${file_name}"
            jmg_pyj_dec="$WORK_DIR/jmg_pyj_${tag}/dec_${file_name}"
            time_cmd "jmg_py_enc_java_dec_${tag}" jmg_py_enc_java_dec \
                "$jmg_pyj_input" "$jmg_pyj_enc" "$jmg_pyj_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_pyj_dec"

            jmg_jp_input="$(copy_input "jmg_jp_${tag}" "$file_name")"
            jmg_jp_enc="$WORK_DIR/jmg_jp_${tag}/enc_${file_name}"
            jmg_jp_dec="$WORK_DIR/jmg_jp_${tag}/dec_${file_name}"
            time_cmd "jmg_java_enc_py_dec_${tag}" jmg_java_enc_py_dec \
                "$jmg_jp_input" "$jmg_jp_enc" "$jmg_jp_dec"
            add_verify "$ORIG_DIR/$file_name" "$jmg_jp_dec"
        done
        fi
}

run_retired_cpp_java_cross_tests() {
        # Retired kFM/kFA cross-compat (C++ <-> Java).
        if (( RETIRED_MEDIA_ENABLED == 1 )); then
        kfme_cppj_input="$(copy_input "kfme_cppj" "$KFM_FILE")"
        kfme_cppj_enc="$WORK_DIR/kfme_cppj/carrier.wav"
        kfme_cppj_dec="$WORK_DIR/kfme_cppj/decoded_${KFM_FILE}"
        time_cmd "kfme_cpp_enc_java_dec" kfme_cpp_enc_java_dec "$kfme_cppj_input" "$kfme_cppj_enc" "$kfme_cppj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cppj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_cppj_input"

        kfme_jcpp_input="$(copy_input "kfme_jcpp" "$KFM_FILE")"
        kfme_jcpp_enc="$WORK_DIR/kfme_jcpp/carrier.wav"
        kfme_jcpp_dec="$WORK_DIR/kfme_jcpp/decoded_${KFM_FILE}"
        time_cmd "kfme_java_enc_cpp_dec" kfme_java_enc_cpp_dec "$kfme_jcpp_input" "$kfme_jcpp_enc" "$kfme_jcpp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_jcpp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfme_jcpp_input"

        kfae_cppj_input="$(copy_input "kfae_cppj" "$KFM_FILE")"
        kfae_cppj_enc="$WORK_DIR/kfae_cppj/carrier.png"
        kfae_cppj_dec="$WORK_DIR/kfae_cppj/decoded_${KFM_FILE}"
        time_cmd "kfae_cpp_enc_java_dec" kfae_cpp_enc_java_dec "$kfae_cppj_input" "$kfae_cppj_enc" "$kfae_cppj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cppj_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_cppj_input"

        kfae_jcpp_input="$(copy_input "kfae_jcpp" "$KFM_FILE")"
        kfae_jcpp_enc="$WORK_DIR/kfae_jcpp/carrier.png"
        kfae_jcpp_dec="$WORK_DIR/kfae_jcpp/decoded_${KFM_FILE}"
        time_cmd "kfae_java_enc_cpp_dec" kfae_java_enc_cpp_dec "$kfae_jcpp_input" "$kfae_jcpp_enc" "$kfae_jcpp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_jcpp_dec"
        add_verify "$ORIG_DIR/$KFM_FILE" "$kfae_jcpp_input"
        fi
}


run_retired_cli_policy_smokes() {
# CLI flag smoke checks and jMG video gate checks for C++/Java.
if (( RETIRED_MEDIA_ENABLED == 1 )) && [[ "$TEST_MODE" != "quickest" ]]; then
    if [[ "$CPP_AVAILABLE" == "1" && -x "$CPP_BIN" && -f "$ORIG_DIR/media_sample.m4a" ]]; then
        cpp_smoke_dir="$WORK_DIR/cpp_flag_smoke"
        mkdir -p "$cpp_smoke_dir"
        cpp_no_log_err="$cpp_smoke_dir/no_log.err"
        cpp_no_log_out="$cpp_smoke_dir/no_log.m4a"
        if ! "$CPP_BIN" --no-log jmge "$ORIG_DIR/media_sample.m4a" -p "$PW" --keep-input --out "$cpp_no_log_out" 2>"$cpp_no_log_err"; then
            FAILURES+=("cpp_no_log_smoke (command failed)")
        elif grep -Eq "basefwx\\.hw|Overall|File    |WARN:" "$cpp_no_log_err"; then
            FAILURES+=("cpp_no_log_smoke (unexpected logs)")
        fi
        cpp_verbose_err="$cpp_smoke_dir/verbose.err"
        cpp_verbose_out="$cpp_smoke_dir/verbose.m4a"
        if ! "$CPP_BIN" --verbose jmge "$ORIG_DIR/media_sample.m4a" -p "$PW" --keep-input --out "$cpp_verbose_out" 2>"$cpp_verbose_err"; then
            FAILURES+=("cpp_verbose_smoke (command failed)")
        elif ! grep -q "reason:" "$cpp_verbose_err"; then
            FAILURES+=("cpp_verbose_smoke (missing reason line)")
        fi
    fi
    if [[ "$JAVA_AVAILABLE" == "1" && -f "$JAVA_JAR" && -f "$ORIG_DIR/media_sample.m4a" ]]; then
        java_smoke_dir="$WORK_DIR/java_flag_smoke"
        mkdir -p "$java_smoke_dir"
        java_no_log_err="$java_smoke_dir/no_log.err"
        java_no_log_out="$java_smoke_dir/no_log.m4a"
        if ! "$JAVA_BIN" -jar "$JAVA_JAR" --no-log jmge "$ORIG_DIR/media_sample.m4a" "$java_no_log_out" "$PW" --keep-input 2>"$java_no_log_err"; then
            FAILURES+=("java_no_log_smoke (command failed)")
        elif grep -Eq "basefwx\\.hw|WARN:" "$java_no_log_err"; then
            FAILURES+=("java_no_log_smoke (unexpected logs)")
        fi
        java_verbose_err="$java_smoke_dir/verbose.err"
        java_verbose_out="$java_smoke_dir/verbose.m4a"
        if ! "$JAVA_BIN" -jar "$JAVA_JAR" --verbose jmge "$ORIG_DIR/media_sample.m4a" "$java_verbose_out" "$PW" --keep-input 2>"$java_verbose_err"; then
            FAILURES+=("java_verbose_smoke (command failed)")
        elif ! grep -q "reason:" "$java_verbose_err"; then
            FAILURES+=("java_verbose_smoke (missing reason line)")
        fi
    fi
fi

if (( RETIRED_MEDIA_ENABLED == 1 )) \
    && [[ "$JMG_VIDEO_CASES_ENABLED" != "1" \
        && "$JMG_VIDEO_CASES_ENABLED" != "true" \
        && "$JMG_VIDEO_CASES_ENABLED" != "yes" \
        && "$JMG_VIDEO_CASES_ENABLED" != "on" \
        && -f "$ORIG_DIR/media_sample.mp4" ]]; then
    if [[ "$CPP_AVAILABLE" == "1" && -x "$CPP_BIN" ]]; then
        cpp_gate_dir="$WORK_DIR/cpp_jmg_video_gate"
        mkdir -p "$cpp_gate_dir"
        cpp_gate_err="$cpp_gate_dir/jmge_video.err"
        if "$CPP_BIN" jmge "$ORIG_DIR/media_sample.mp4" -p "$PW" --out "$cpp_gate_dir/out.mp4" >"$cpp_gate_dir/stdout.log" 2>"$cpp_gate_err"; then
            FAILURES+=("cpp_jmg_video_gate (expected failure)")
        elif ! grep -q "jMG video mode is temporarily disabled" "$cpp_gate_err"; then
            FAILURES+=("cpp_jmg_video_gate (missing disable message)")
        fi
    fi
    if [[ "$JAVA_AVAILABLE" == "1" && -f "$JAVA_JAR" ]]; then
        java_gate_dir="$WORK_DIR/java_jmg_video_gate"
        mkdir -p "$java_gate_dir"
        java_gate_err="$java_gate_dir/jmge_video.err"
        if "$JAVA_BIN" -jar "$JAVA_JAR" jmge "$ORIG_DIR/media_sample.mp4" "$java_gate_dir/out.mp4" "$PW" >"$java_gate_dir/stdout.log" 2>"$java_gate_err"; then
            FAILURES+=("java_jmg_video_gate (expected failure)")
        elif ! grep -q "jMG video mode is temporarily disabled" "$java_gate_err"; then
            FAILURES+=("java_jmg_video_gate (missing disable message)")
        fi
    fi
fi
}
