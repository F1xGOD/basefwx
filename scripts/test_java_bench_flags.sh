#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/java_bench_flags.sh
source "$ROOT/scripts/lib/java_bench_flags.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_JAVA="$TMP_DIR/java"
cat >"$FAKE_JAVA" <<'EOF'
#!/usr/bin/env bash
case " $* " in
    *" -XX:InitialRAMPercentage=20 "*|\
    *" -XX:MaxRAMPercentage=75 "*|\
    *" -XX:+UseAESCTRIntrinsics "*)
        exit 1
        ;;
esac
exit 0
EOF
chmod +x "$FAKE_JAVA"

unset BASEFWX_BENCH_MEMORY_LIMIT_BYTES
basefwx_java_select_default_bench_flags "$FAKE_JAVA"
joined=" ${BASEFWX_JAVA_BENCH_FLAGS[*]} "

[[ "$joined" != *" -XX:InitialRAMPercentage=20 "* ]]
[[ "$joined" != *" -XX:MaxRAMPercentage=75 "* ]]
[[ "$joined" != *" -XX:+UseAESCTRIntrinsics "* ]]
[[ "$joined" == *" -XX:InitialRAMFraction=5 "* ]]
[[ "$joined" == *" -XX:MaxRAMFraction=2 "* ]]
[[ "$joined" == *" -XX:+UseAESIntrinsics "* ]]
[[ "$joined" == *" -XX:+UseGHASHIntrinsics "* ]]

BASEFWX_BENCH_MEMORY_LIMIT_BYTES=$((1024 * 1024 * 1024)) \
    basefwx_java_select_default_bench_flags "$FAKE_JAVA"
joined=" ${BASEFWX_JAVA_BENCH_FLAGS[*]} "

[[ "$joined" != *" -XX:InitialRAMPercentage=20 "* ]]
[[ "$joined" != *" -XX:MaxRAMPercentage=75 "* ]]
[[ "$joined" != *" -XX:InitialRAMFraction=5 "* ]]
[[ "$joined" != *" -XX:MaxRAMFraction=2 "* ]]
[[ "$joined" == *" -Xms128m "* ]]
[[ "$joined" == *" -Xmx512m "* ]]
[[ "$joined" == *" -XX:+UseAESIntrinsics "* ]]
[[ "$joined" == *" -XX:+UseGHASHIntrinsics "* ]]

"$FAKE_JAVA" "${BASEFWX_JAVA_BENCH_FLAGS[@]}" -version
printf 'PASS: Java benchmark flags are capability-selected\n'
