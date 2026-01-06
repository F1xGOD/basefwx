---
layout: doc
title: Testing
---

# Testing

## Quick Run

```
./scripts/test_all.sh
```

The script creates a local venv by default and writes logs to `diagnose.log`.
Media tests require `ffmpeg` and `ffprobe`.

## Modes

- `--fast` reduces fixture sizes and skips wrong-password and cross-compat tests.
- `--quickest` uses the smallest fixture sizes and skips extra cases.
- `--huge` enables very large file fixtures (200MB and 1.2GB).
- `--bench` runs only benchmark timings (skips correctness/cross-compat/verify phases).

Examples:

```
./scripts/test_all.sh --fast
./scripts/test_all.sh --quickest
./scripts/test_all.sh --huge
```

## Environment Overrides

Common knobs used by the test script:

- `USE_VENV=0` to skip venv creation.
- `VENV_DIR=/path/to/venv` to override venv location.
- `BIG_FILE_BYTES=37748736` to set the default largest test file size.
- `BENCH_FILE_BYTES=220000000` to set the benchmark file size (defaults to 220MB in default mode).
- `BENCH_TEXT_BYTES=8388608` to set the benchmark text size (defaults to 8MB in default mode).
- `BENCH_TEXT_FILE=/path` to override the benchmark text input file.
- `BENCH_TEXT_MAX_BYTES=60000000` to cap benchmark text size (defaults to 60MB).
- `BENCH_TEXT_SLOW_BYTES=1048576` to cap slow text methods (a512/bi512/b1024) separately (defaults to 1MB).
- `BENCH_ITERS_LIGHT=50` and `BENCH_ITERS_SLOW=10` to tune benchmark iterations for text/hash methods.
- `BENCH_ITERS_HEAVY=5` and `BENCH_ITERS_FILE=3` to tune fwxAES/file benchmark iterations.
- `BENCH_FWXAES_MODE=par` to benchmark fwxAES with full parallelism (`par` or `single`).
- `BASEFWX_BENCH_PARALLEL=1` to run benchmarks across all cores by default (set `0` to force single-core).
- `BASEFWX_BENCH_ALL_CORES=1` to enforce full-core benchmarking (set `0` to allow custom workers).
- `BASEFWX_BENCH_WORKERS=32` to override worker count when full-core enforcement is disabled.

Note: Full-core mode is enforced by default; if you disable it, benchmark results are flagged as invalid.
- `HUGE_200M_BYTES=200000000` and `HUGE_1P2G_BYTES=1200000000` to adjust huge sizes.
- `COOLDOWN_SECONDS=2` to insert a cooldown between timed sections.

Check `scripts/test_all.sh` for the full set of test flags and defaults.
