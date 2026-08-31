# Testing

## Run the main suite

```bash
./scripts/test_all.sh
```

The script creates a local virtual environment by default and writes its log to
`diagnose.log`. It exercises the maintained C++, Python, and Java formats,
cross-runtime compatibility, negative cases, and the configured benchmark
policy. Retired media tests run only in the explicit compatibility profile.

Use a smaller mode while developing:

```bash
./scripts/test_all.sh --fast
./scripts/test_all.sh --quickest
```

`--fast` reduces fixtures and skips some wrong-password and cross-runtime work.
`--quickest` uses the smallest fixtures. Neither is a release qualification
run. `--huge` enables the large-file cases, and `--bench` runs timed work
without the normal correctness phases.

## Benchmark method

Benchmarks run untimed warm-up iterations, then report the median of the timed
iterations. Java gets extra warm-up where the JVM needs it. JVM startup and the
warm-up work are excluded, so the result describes steady-state operation, not
the latency of a first command invocation.

Compare results only when the input, KDF policy, thread count, runtime mode,
host, and thermal conditions match. A benchmark that fails correctness or
changes its security parameters is not a valid speed comparison.

The benchmark job records machine context and flags results when required
full-core policy is disabled. The published dashboard is a view of recorded
results, not a performance guarantee for another machine.

## Useful overrides

- `USE_VENV=0` skips virtual-environment creation.
- `VENV_DIR=/path/to/venv` selects another environment.
- `BIG_FILE_BYTES=<n>` changes the main large fixture.
- `BENCH_FILE_BYTES=<n>` and `BENCH_TEXT_BYTES=<n>` change timed inputs.
- `BENCH_ITERS_LIGHT=<n>`, `BENCH_ITERS_HEAVY=<n>`, and
  `BENCH_ITERS_FILE=<n>` change repetition counts.
- `BASEFWX_MAX_THREADS=<n>` caps internal concurrency.
- `BASEFWX_BENCH_PARALLEL=0` forces single-core benchmark work.
- `COOLDOWN_SECONDS=<n>` changes the pause between timed sections.

The test driver has more specialist knobs. Read `scripts/test_all.sh` before
using them in published evidence, and record every override with the result.

## Focused native checks

For C++ work, build and run the affected CTest targets first:

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build cpp/build --parallel
ctest --test-dir cpp/build --output-on-failure
```

Format or security changes also need the shared known-answer tests and the
cross-runtime suite. Packaging, ABI, sanitizer, leak, or benchmark changes need
their matching workflow before release.
