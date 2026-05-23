# Compatibility and System Requirements

## Platform Support

## Runtime Capability Matrix

| Runtime | Argon2id | PQ/OQS | LZMA/XZ | AN7/DEAN7 | Notes |
| :-- | :--: | :--: | :--: | :--: | :-- |
| C++ | ✅ | ✅ | ✅ | ✅ | Reference release runtime for performance and full native feature set. |
| Python | ✅ with `basefwx[argon2]` | ✅ via `pqcrypto` | ✅ | ✅ | Feature-complete scripting/runtime path. |
| Java | ✅ since 3.7.0 (BouncyCastle `Argon2BytesGenerator`; libargon2 JNI optional) | Partial | ❌ | ✅ | Argon2id user-KDF wrap supported. ML-KEM primitives exist via BouncyCastle (`PQ.kemEncrypt` / `PQ.kemDecrypt`), but Java keywrap still lacks the PQ master-blob dispatch path documented below. JNI bridge to libargon2 (`NativeCryptoBackend.argon2idHashRaw`) speeds Argon2 up ~5–10× on systems where the native lib is loadable; falls through to pure-Java BouncyCastle otherwise (byte-identical output, just slower). |

### Argon2 parallelism portability

The Argon2id parallelism parameter is not stored in the wrap header.
As of 3.7.0, **all three runtimes hardcode the default lane count to
`4`** so blobs are portable across hosts regardless of the encrypting
machine's CPU count:

| Runtime | Default | Source |
| :-- | :--: | :-- |
| C++ | 4 | `kArgon2Parallelism` in `cpp/include/basefwx/constants.hpp` |
| Java | 4 | `ARGON2_PARALLELISM` in `Constants.java` (`defaultArgon2Parallelism()` returns 4) |
| Python | 4 | `_DEFAULT_ARGON2_PARALLELISM` in `python/basefwx/legacy.py` |

Pre-3.7.0 each runtime resolved the default from
`std::thread::hardware_concurrency()` /
`Runtime.getRuntime().availableProcessors()` / `os.cpu_count()`, so a
blob encrypted on a 16-core machine could not be decrypted on a 4-core
machine without the caller explicitly pinning
`KdfOptions.argon2Parallelism`. The 3.7.0 fix closes that. Callers who
genuinely want host-tuned parallelism can still set the field on
`KdfOptions` before the encrypt — the **default** just stops varying.

### Heavy-mode KDF parameter divergence in Android Yume

The C++ YUME/BaseFWX heavy-mode defaults are the reference values:
PBKDF2 uses `2_000_000` iterations, and Argon2id uses
`time=6`, `memory=1 << 18` KiB (256 MiB), `parallelism=4`.

The Android transport currently sends lower mobile-tuned values from
`YumeInnerCrypto.kt`: PBKDF2 uses `1_000_000` iterations, and Argon2id
uses `time=3`, `memory=1 << 16` KiB (64 MiB), `parallelism<=4`.
The server honors the client's advertised KDF params, so
Android-initiated heavy sessions are objectively weaker than desktop
heavy sessions.

This is documented as an Android performance trade-off, not parity.
Do not describe Android "heavy" as equivalent to desktop "heavy" until
the constants are reconciled and the resulting auth latency / memory
use is benchmarked on the Android device class being targeted.

### Master-key wrap: Java is EC-only

The C++ and Python runtimes accept two kinds of `master_blob` in a
keywrap header — an EC-magic-prefixed blob (`EC1` + ECIES-wrapped
key) decoded by `basefwx::ec::KemDecrypt`, and a magic-less PQ blob
(raw Kyber/ML-KEM ciphertext) decoded by `basefwx::pq::KemDecrypt`
([cpp/src/keywrap.cpp:186-189](basefwx/cpp/src/keywrap.cpp#L186)).
The Java runtime currently accepts **only the EC variant** —
[KeyWrap.java:99](basefwx/java/src/main/java/com/fixcraft/basefwx/KeyWrap.java#L99)
hard-codes `startsWith(masterBlob, Constants.MASTER_EC_MAGIC)` and
rejects anything else.

Practical impact:

- **Password-only blobs** (no master key) — work everywhere (C++,
  Python, Java).
- **EC-master-wrapped blobs** — work everywhere.
- **PQ-master-wrapped blobs without a usable password** — only
  decode in C++/Python. Java throws "Invalid master key blob
  magic" and there is no fallback because no password was
  configured.
- **PQ-master-wrapped blobs WITH a usable password** — Java's
  catch-handler at
  [KeyWrap.java:105](basefwx/java/src/main/java/com/fixcraft/basefwx/KeyWrap.java#L105)
  falls back to the user-key path and the decode succeeds. Visible
  consequence: the master-key recovery path is silently bypassed on
  Java even though the producer expected it to be available.

This asymmetry is not caused by a missing primitive:
`PQ.kemDecrypt(byte[] privateKeyBytes, byte[] ciphertext)` exists in
the Java runtime. The blocker is `KeyWrap.recoverMaskKey(...)` itself:
it treats every non-empty `masterBlob` as EC-only, hard-codes a
`Constants.MASTER_EC_MAGIC` check, and has no non-EC/PQ branch that
loads the PQ private key and dispatches to `PQ.kemDecrypt`. Tracked for
a future basefwx minor release.

Until then: do not rely on master-key-only blobs round-tripping
through the Java runtime. The Android client (which consumes the
synced Java codec) inherits this limitation. The C++ CLI and the
Python `basefwx` package are unaffected.

Release policy:

- Native release binaries are expected to ship with Argon2, OQS, and LZMA enabled.
- Language runtimes that do not implement a feature must report that explicitly in `version` output and docs.
- Format changes must preserve declared cross-runtime compatibility or bump the format/version contract intentionally.

### Linux
- **Minimum**: Debian 9+, Ubuntu 18.04+, RHEL/CentOS 7+
- **Architecture**: x86_64 (amd64), aarch64 (arm64)
- **Build**: Release binaries target static third-party crypto/compression linkage where the workflow can provide it
- **Optimizations**: Generic CPU (no -march=native for max compatibility)

### Windows
- **Minimum**: Windows 10+
- **Architecture**: x64, x86
- **Build**: Uses vcpkg for dependencies

### macOS
- **Minimum**: macOS 11+ (Big Sur)
- **Architecture**: x86_64, arm64 (Apple Silicon)
- **Dependencies**: Via Homebrew

## Memory Requirements

### Argon2id (Default KDF)
- **Recommended**: 256 MiB+ free RAM
- **Minimum**: 
  - Standard: ~128 MiB for default parameters (memory_cost=2^15 KiB)
  - Short passwords: ~256 MiB for enhanced security (memory_cost=2^16 KiB)
  - Heavy operations: ~512 MiB (memory_cost=2^17 KiB)

**Low Memory Fallback**: If you encounter "Insufficient memory for Argon2id" errors:
```bash
export BASEFWX_USER_KDF=pbkdf2
```

### PBKDF2 (Fallback KDF)
- **Memory**: Minimal (~1 MiB)
- **Security**: Still secure with high iteration count (200,000+ iterations)

## Error Messages

### Expected Errors (User-Friendly)
The application provides clear error messages for known issues:

1. **Insufficient Memory**:
   ```
   RuntimeError: Insufficient memory for Argon2id key derivation.
   Required: ~128 MiB, Consider using PBKDF2 instead (set BASEFWX_USER_KDF=pbkdf2)
   ```

2. **Missing Dependencies**:
   ```
   RuntimeError: Argon2 backend unavailable
   ```

3. **Invalid Input**:
   ```
   ValueError: User key salt must be at least 16 bytes
   ```

### Unexpected Errors
For unexpected errors, you may see full tracebacks. Please report these as bugs.

## Compatibility Features

### Static Linking
- **Third-party crypto/compression**: Release native binaries aim to statically link liboqs, Argon2, LZMA, and OpenSSL where supported by the target build pipeline
- **Benefits**: Reduced runtime dependency drift across target systems

### Dynamic Linking
- **glibc / system runtime**: Still platform-dependent on Linux/macOS/Windows runtime layers where full static linkage is not practical or desirable

### Release Metadata

Each release publishes:

- canonical binaries/JARs only
- detached `.sig` signatures
- `.sha256` and `.md5` checksum files
- `release-manifest.json` with machine-readable asset metadata

### Build Flags
Release builds use:
- `-O3` optimization
- LTO (Link-Time Optimization)
- No CPU-specific optimizations (-march=native disabled)
- Deprecation warnings suppressed for clean output

## Troubleshooting

### Binary Won't Run on Older Linux
1. Check glibc version: `ldd --version`
   - Required: glibc 2.17+ (RHEL 7+) or 2.27+ (Ubuntu 18.04+)
2. Check OpenSSL: `openssl version`
   - Required: OpenSSL 1.1.1+ or 3.0+

### Memory Errors
1. Check available memory: `free -h`
2. Try PBKDF2: `export BASEFWX_USER_KDF=pbkdf2`
3. Reduce memory_cost if using Argon2 directly

### Performance Issues
1. Ensure you're using release builds (not debug)
2. Check CPU usage during operations
3. Consider SSD for file operations

## Environment Variables

### Memory and Performance
- `BASEFWX_USER_KDF`: Set to `pbkdf2` for low-memory systems
- `BASEFWX_PERF`: Enable performance mode for large files
- `BASEFWX_TEST_KDF_ITERS`: Reduce KDF iterations for testing only

### Development
- `BASEFWX_OBFUSCATE`: Enable/disable obfuscation
- `ALLOW_BAKED_PUB`: Allow using baked public key (testing only)
- `BASEFWX_MASTER_PQ_PUB`: Path to master PQ public key

## Architecture Support

### Tested Architectures
- ✅ x86_64 (AMD64)
- ✅ ARM64 (aarch64, Apple Silicon)

### Untested but Should Work
- ARM32 (ARMv7)
- RISC-V (with appropriate compiler)

## File Format Compatibility

All file formats are cross-platform and architecture-independent:
- Encoded files work across all platforms
- Encrypted files are portable
- Archive formats are standardized
