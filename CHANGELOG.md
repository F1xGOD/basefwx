# Changelog

## [Unreleased]

## [v3.6.3] - 2026-03-19

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.6.2...v3.6.3>

### Added
- New `AN7` / `DEAN7` reversible stealth anonymization support in C++, Python, and Java.
- Shared repository `VERSION` source with cross-runtime build/version metadata plumbing.
- Release manifest generation and version-sync validation for packaged artifacts.
- C++ CLI completion and stronger version/build reporting for release diagnostics.

### Changed
- Release workflows now enforce full-support artifacts instead of silently accepting degraded Argon2/OQS/LZMA builds.
- Release asset handling was tightened around canonical, architecture-qualified outputs and shared metadata.
- C++, Python, and Java version/capability reporting was aligned around the same repository version and build inputs.
- Documentation, compatibility notes, and website release metadata were synchronized around the new release process.

### Fixed
- Java CLI build regression caused by missing version-command wiring/import coverage.
- Redundant CI/release pre-build work, including unnecessary repeated `liboqs` setup in cached workflow paths.
- Workflow/package inconsistencies that could ship artifacts without the intended full crypto feature set.

### Notes
- `v3.6.3` is a release-hardening and interoperability release: stealth anonymization, stricter packaging, and consistent metadata are the main user-visible changes.
- Python and Java now follow the repository `VERSION` file directly, so version bumps no longer need separate per-runtime edits beyond the shared source.

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
