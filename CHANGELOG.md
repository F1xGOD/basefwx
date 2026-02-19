# Changelog

## [v3.6.1] - Released

Compare: <https://github.com/F1xGOD/basefwx/compare/ed79adb...907833c>

### Added
- Python `kFM`/`kFA` reversible carrier methods:
  - `kFMe`: image/media bytes -> WAV noise carrier
  - `kFMd`: WAV carrier -> original bytes, with non-kFM fallback to static PNG
  - `kFAe`: audio bytes -> PNG noise carrier (RGB or BW static mode)
  - `kFAd`: PNG carrier -> original bytes, with non-kFM fallback to WAV
- C++ `kFM`/`kFA` API + CLI parity with Python:
  - `basefwx::Kfme`, `basefwx::Kfmd`, `basefwx::Kfae`, `basefwx::Kfad`
  - CLI commands: `kFMe`, `kFMd`, `kFAe`, `kFAd`
- Java `kFM`/`kFA` API + CLI parity with Python:
  - `BaseFwx.kFMe`, `BaseFwx.kFMd`, `BaseFwx.kFAe`, `BaseFwx.kFAd`
  - CLI commands: `kFMe`, `kFMd`, `kFAe`, `kFAd`
- Versioned kFM container header with magic/version/mode/checksum for deterministic detection.
- Python CLI commands: `kFMe`, `kFMd`, `kFAe`, `kFAd`.
- Python tests covering kFM/kFA API and CLI roundtrips plus fallback behavior.
- n10 numeric codec support across C++, Java, and Python.
- n10 CLI commands for text and file workflows in all supported runtimes.
- n10 coverage in benchmark export and benchmark summary output.
- Expanded benchmark scenarios for Java and cross-language parity checks.
- Added branch sync workflow.

### Changed
- Python package layout moved under `python/` with workflow and editable-install fixes.
- Repository structure updated with website/docs organization improvements.
- Benchmark pipeline updated to keep website benchmark feeds aligned with runtime changes.

### Fixed
- Java BW-mode PNG carrier serialization now preserves exact bytes (prevents false fallback on `kFAd`).
- `kFMd` now accepts `.mp3`/`.m4a` audio inputs in Python/C++/Java using runtime ffmpeg decode fallback.
- Cross-language compatibility issues in codec/KDF paths (including PBKDF2 interoperability).
- Java build and Gradle compatibility issues.
- Website hash/integrity display issues.
- CI and test workflow regressions after project layout updates.

### Notes
- Benchmarks consumed by the website (`website/results/benchmarks-latest.json`) now include `n10`.
- Existing benchmark pages automatically render new methods from the JSON dataset.
