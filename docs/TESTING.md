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
- `HUGE_200M_BYTES=200000000` and `HUGE_1P2G_BYTES=1200000000` to adjust huge sizes.
- `COOLDOWN_SECONDS=2` to insert a cooldown between timed sections.

Check `scripts/test_all.sh` for the full set of test flags and defaults.
