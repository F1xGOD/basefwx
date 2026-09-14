---
layout: "doc"
title: "Testing"
description: "Focused checks, cross-runtime qualification, benchmark method, and supported overrides."
permalink: "/docs/TESTING/"
generated_from: "docs/TESTING.md"
doc_source: "docs/src/en_US/pages/testing.doc"
lang: "en-US"
doc_locale: "en_US"
---

# Testing

## Run the main suite

{% raw %}
```bash
./scripts/test_all.sh
```
{% endraw %}

The script creates a local virtual environment by default and writes its log to
`diagnose.log`. It exercises the maintained C++, Python, and Java formats,
cross-runtime compatibility, negative cases, and the configured benchmark
policy. Retired media tests run only in the explicit compatibility profile.
Environment creation, pip preparation and editable-source installation must
all succeed before tests begin. Failure stops the suite at the named stage;
the driver does not switch to another interpreter after a requested
environment or interpreter fails. Existing environments are not deleted on
failure.

Use a smaller mode while developing:

{% raw %}
```bash
./scripts/test_all.sh --fast
./scripts/test_all.sh --quickest
```
{% endraw %}

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

{% raw %}
```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build cpp/build --parallel
ctest --test-dir cpp/build --output-on-failure
```
{% endraw %}

`scripts/test_all.sh` uses `scripts/run_cpp_tests.py` for its internal native
gate. The driver discovers every configured CTest except the
`basefwx-packaging` label, then requires a passing JUnit result for every
discovered test. Empty inventories, disabled or skipped tests, missing results,
and configure/build failures fail the gate; an old executable cannot stand in
for a failed build. New runtime tests enter this gate through CMake's
`add_test()` without updating a second name list. The retired-media policy test
enters only when that profile is configured. Packaging/exported-library checks
keep their separate lane and remain included by the unfiltered CTest command
above.

The driver requires Python 3.9+ and CTest 3.21+ for JUnit output. To run only
this gate after building:

{% raw %}
```bash
python3 scripts/run_cpp_tests.py --build-dir cpp/build --output-junit cpp/build/runtime-tests.xml
python3 scripts/test_run_cpp_tests.py
```
{% endraw %}

The second command checks the driver's failure handling with tiny real CTest
fixtures and isolated Python/native setup failures; it does not install
dependencies, build or qualify the library. The main suite retains its
report at `.tmp_basefwx_tests/out/cpp-internal-tests.xml` until the next run.

Format or security changes also need the shared known-answer tests and the
cross-runtime suite. Packaging, ABI, sanitizer, leak, or benchmark changes need
their matching workflow before release.
