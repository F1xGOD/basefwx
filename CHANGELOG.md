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

## [v3.6.4] - 2026-05-16

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.6.3...v3.6.4>

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
- **Cross-language KDF hardening** of the password-based key-derivation paths used by fwxAES, b512, pb512, file codecs, AN7, and the master-key wrap:
  - `USER_KDF_ITERATIONS` / `FWXAES_PBKDF2_ITERS`: 200 000 → **600 000** (attacker cost **3.00×**).
  - `SHORT_PBKDF2_ITERATIONS`: 400 000 → **1 000 000** (2.50×).
  - `HEAVY_PBKDF2_ITERATIONS`: 1 000 000 → **2 000 000** (2.00×).
  - Argon2id default `time / memory`: 3 / 2¹⁵ (32 MiB) → **4 / 2¹⁶** (64 MiB) — **2.67×**.
  - `SHORT_ARGON2 t / m`: 4 / 2¹⁶ → **5 / 2¹⁷** (128 MiB) — 2.50×.
  - `HEAVY_ARGON2 t / m`: 5 / 2¹⁷ → **6 / 2¹⁸** (256 MiB) — 2.40×.
  - Net: roughly **+1.4 bits of brute-force resistance** on the default fwxAES path on top of an already strong baseline. Per-blob backwards compatible — PBKDF2 iteration counts and Argon2 params are stored inline in each blob, so 3.6.3-era blobs decrypt at their original cost without user action.
- **Zero-copy AES-GCM via JNI** for the Java backend. `cpp/src/jni/basefwx_jni.cpp` gained `nativeAesGcmEncryptOneShot` / `nativeAesGcmDecryptOneShot` that pin heap `byte[]` arrays with `GetPrimitiveArrayCritical` and run `EVP_CipherInit / Update / Final / GET_TAG` in a single JNI call (no `DirectByteBuffer` allocation, no chunked copy). About **+10–11 %** throughput on 16 MiB fwxAES encrypt locally (i7-11600H, OpenJDK 25) once `-Dbasefwx.useJNI=true` actually routes through it.
- New documentation:
  - `RELEASE-NOTES-3.6.4.md` — full release write-up with the security-normalized perf comparison vs 3.6.3, KDF cost tables, methodology, and upgrade checklist.
  - `SECURITY.md` sections on the **default password-only crypto stance** (AES-256-GCM + Argon2id/PBKDF2 + HKDF-SHA256 — already PQ-resistant on its own) and the **optional ML-KEM-768 master-key wrap** (off by default, opt-in via `useMaster=true`), including a priority-ordered list of master-pubkey sources for self-hosted deployments.
  - `SECURITY.md` "roll-forward" clarification: each release is **frozen at publish time**; maintenance means publishing a new release, not patching an existing one.

### Changed
- Python package refactor from monolithic `main.py` into modular API layout, with `legacy.py` retained for compatibility internals.
- PyPI metadata now reads from the root project README so package description matches the main repository docs.
- jMG defaults in Python shifted toward no-archive behavior for lower output overhead; archive mode remains available.
- Hardware routing policy in Python was hardened:
  - AES work stays on CPU (AES-NI path where available).
  - GPU is used for media stages where beneficial with strict/fallback controls.
- Branch/workflow parity, publish, benchmark, and website-feed automation were tightened for release consistency.
- **Java `Crypto.aesGcm{Encrypt,Decrypt}WithIvInto` now dispatches through `NativeCryptoBackend.aesGcm{Encrypt,Decrypt}OneShot` when the active `CryptoBackend` is native.** Previously the main fwxAES encrypt/decrypt path always used the JCA `Cipher` regardless of which backend the caller selected, which is why "useJNI=true" used to match (or even trail) "useJNI=false" in the dual-backend benchmark. The native backend is now the actual hot path when it's loaded.
- Java (`Constants.java`) and Python (`legacy.py`) default KDF parameters were aligned with the hardened C++ values listed under **Added** so all three runtimes pay the same security cost. The headline "fwxAES looks slower than 3.6.3" comparison previously came from the C++ side already being hardened while Java/Python silently still used the weaker 3.6.3 cost.

### Fixed
- Multiple cross-runtime compatibility regressions in codec/KDF paths (including PBKDF2-related decode/interop issues).
- Java and C++ parity gaps for kFM/kFA/live paths and CLI handling.
- macOS/Windows/Linux build workflow regressions (arch matrix, dependency handling, static-linking prep).
- ffmpeg media-path handling improvements across Python/Java/C++ (including mp3/m4a intake paths).
- Website release/hash rendering and benchmark ingestion issues.
- CI/test reliability regressions after project restructuring.
- **Python `os.replace` EXDEV (Errno 18 "Invalid cross-device link") in the streaming encrypt/decrypt paths** (`_aes_heavy_encode_path_stream`, `_aes_heavy_decode_path_stream`, `_b512_encode_path_stream`). On hosts where `$TMPDIR` resolves to a tmpfs and the output file lives on a different filesystem (common on Linux servers), the final atomic rename failed and the encrypt/decrypt aborted. The scratch directory is now created next to the output (or input, on decode) so `os.replace` always stays within one filesystem.
- **Python `decrypt_media` / `_recover_mask_key_from_blob` unconditionally required `master_pq.sk` when a master_blob was present.** On non-custodian / open-source deployments without the matching master private key, every jmg blob produced under default master-mode was un-decryptable even with the correct password and an intact user_blob. The decrypt path now falls back to the user_blob/password path when the master private key is missing, matching the documented threat model (master-key recovery is opt-in; password is always an independent unlock path).

### Notes
- jMG video mode is intentionally gated/paused by default in current release tracks for safety/stability; use fwxAES for video unless explicitly re-enabled.
- Java media operations require `ffmpeg` available on `PATH`; missing ffmpeg will fail jMG Java tests/benchmarks.
- Benchmark/website datasets now include newer methods (`n10`, live suites, carrier suites) and are consumed by `website/results/benchmarks-latest.json`.
- **Performance at constant security strength.** Once 3.6.3 benchmark numbers are rescaled to the 3.6.4 KDF cost (PBKDF2 × 3.00; Argon2 default × 2.667 where applicable), the overall test suite is **−55 % to −60 % faster** across C++ / Java / Python and the KDF-heavy paths (`fwxAES`, `b512`, `pb512`, `b512file`, `pb512file`, `kFMe`, `kFAe`, `an7`, `dean7`) are **−60 % to −80 % faster**. Non-KDF micros (`b256`, `b64`, `hash512`, `n10`, `bi512`, `uhash513`) are flat within ±2 %. Headline "fwxAES looks slower than 3.6.3" comparisons against the raw numbers are entirely the security-tax effect, not a code regression. Full methodology in `RELEASE-NOTES-3.6.4.md`.
- ML-KEM-768 is **opt-in** via `useMaster=true` / `--with-master`. Default password-only mode does not engage the PQ KEM but is already PQ-resistant via AES-256 (Grover ≈ 128-bit equivalent) + hardened Argon2id/PBKDF2 + HKDF-SHA256.
- Releases are **frozen at publish time**: 3.6.4 will never receive in-place patches. A vulnerability fixed against 3.6.4 ships as 3.6.5 (or 3.7.0, etc.), and the vulnerable 3.6.4 binary is left as published. See `SECURITY.md` → *Maintenance policy* for the full roll-forward model.
