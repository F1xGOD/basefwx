#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_PY_TESTS=0 RUN_CPP_TESTS=0 RUN_JAVA_TESTS=1 RUN_PYPY_TESTS=0 ./scripts/test_all.sh "$@"
