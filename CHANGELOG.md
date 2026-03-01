# Changelog

## [Unreleased]

### Changed
- Python live stream (`fwxAES_live_*`) internals were optimized to reduce allocation pressure:
  - Reused AES-GCM contexts for session frame operations.
  - Replaced repeated front-buffer deletion with offset+compact buffering in live decrypt paths.
- C++ live stream internals were optimized for lower-copy operation:
  - Switched data-frame AES-GCM operations to `*Into` APIs where possible.
  - Replaced repeated `vector.erase(begin, ...)` usage with offset+compact buffering.
- Java live stream internals were optimized similarly (slice-based updates and lower-copy decrypt buffering).
- Python `n10` codec hot paths were optimized for large payloads:
  - Cached per-index transform offsets across runs.
  - Reduced conversion/parse overhead in encode/decode loops.
- Python `b1024` hot path was optimized by removing large intermediate `str -> bytes` conversions in codec packing.
- Java kFM PNG carrier paths (`kFAe`/PNG decode) were optimized with byte-raster fast paths to reduce per-pixel overhead.

### Notes
- Benchmarks remain expected to favor compiled runtimes (C++/Java) for very large `n10` workloads, but Python steady-state performance improved.
- Documentation was synchronized across GitHub and website pages for support policy and benchmark interpretation.

## [v3.6.2] - 2026-02-22

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.6.1...v3.6.2>

### Added
- New reversible carrier APIs in all runtimes:
  - `kFMe` / `kFMd` for auto media carrier encode/decode.
  - `kFAe` / `kFAd` legacy audio-image aliases (kept for compatibility).
- Versioned kFM container header (magic/version/mode/checksum) for deterministic detection and safer decode paths.
- New `n10` codec support in Python, C++, and Java (API + CLI + benchmarks).
- Python live packetized AEAD APIs (`fwxAES_live_*`) with stream/chunk helpers and ffmpeg bridge helpers.
- Python jMG no-archive path with key-only trailer support (`JMG1`) plus compatibility fallback behavior.
- Runtime hardware/telemetry logging:
  - Python, C++, Java hardware plan banner.
  - Progress telemetry with CPU/RAM/temp (and GPU when active).
  - CLI global logging controls in C++/Java: `--no-log`, `--verbose`.
- `scripts/test_all.sh --heavy` mode for larger fixtures, longer passwords, and reliability-focused benchmark/test defaults.

### Changed
- Python package refactor from monolithic `main.py` into modular API layout, with `legacy.py` retained for compatibility internals.
- PyPI metadata now reads from the root project README so package description matches the main repository docs.
- jMG defaults in Python shifted toward no-archive behavior for lower output overhead; archive mode remains available.
- Hardware routing policy in Python was hardened:
  - AES work stays on CPU (AES-NI path where available).
  - GPU is used for media stages where beneficial with strict/fallback controls.
- Branch/workflow parity, publish, benchmark, and website-feed automation were tightened for release consistency.

### Fixed
- Multiple cross-runtime compatibility regressions in codec/KDF paths (including PBKDF2-related decode/interop issues).
- Java and C++ parity gaps for kFM/kFA/live paths and CLI handling.
- macOS/Windows/Linux build workflow regressions (arch matrix, dependency handling, static-linking prep).
- ffmpeg media-path handling improvements across Python/Java/C++ (including mp3/m4a intake paths).
- Website release/hash rendering and benchmark ingestion issues.
- CI/test reliability regressions after project restructuring.

### Notes
- jMG video mode is intentionally gated/paused by default in current release tracks for safety/stability; use fwxAES for video unless explicitly re-enabled.
- Java media operations require `ffmpeg` available on `PATH`; missing ffmpeg will fail jMG Java tests/benchmarks.
- Benchmark/website datasets now include newer methods (`n10`, live suites, carrier suites) and are consumed by `website/results/benchmarks-latest.json`.
