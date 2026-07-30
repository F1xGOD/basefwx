# Compatibility and System Requirements

## Platform Support

## Runtime Capability Matrix

| Runtime | Argon2id | PQ/OQS | LZMA/XZ | AN7/DEAN7 | Notes |
| :-- | :--: | :--: | :--: | :--: | :-- |
| C++ | ✅ | ✅ | ✅ | ✅ | Reference release runtime for performance and full native feature set. |
| Python | ✅ (`argon2-cffi` is a hard dependency; `basefwx[argon2]` remains a no-op extra for old install scripts) | ✅ via `pqcrypto` | ✅ | ✅ | Feature-complete scripting/runtime path. |
| Java | ✅ since 3.7.0 (BouncyCastle `Argon2BytesGenerator`; libargon2 JNI optional) | ✅ keywrap (BouncyCastle ML-KEM-768/1024; EC fallback only when PQ pub not configured) | ❌ | ✅ | Argon2id user-KDF wrap on fwxAES / b512 / pb512file / KeyWrap. Peer `ENC-ARGON2-*` costs fail closed above shared maxima. |

### 3.8.0-dev1 protocol-building API parity

Explicit-salt HKDF, ML-KEM-768 / ML-KEM-1024 selection with
`GenerateKeyPair` / `generate_kem_keypair`, and X25519 helpers are
public on **C++, Java, and Python**. Cross-runtime byte identity is
gated by shared KAT fixtures under `testdata/protocol_kats/` (emitted by
`scripts/gen_protocol_kats.py` from the C++/liboqs reference). Default
master-key generation/default reporting remains **ML-KEM-768**;
`BASEFWX_MASTER_PQ_ALG=ml-kem-1024` (and `BASEFWX_PQ_MAX` /
`BASEFWX_PQ_1024`) opts generation and reporting into 1024 on all three
runtimes after KAT pass. Those variables alone never change an fwxAES /
b512 / pb512 file: the provisioned public key's standardized size selects
the wrap algorithm and authenticated `ENC-KEM` value.

The repository files are fixed interoperability snapshots. Regeneration
creates fresh randomized X25519/ML-KEM keypairs and encapsulations, then
writes the same JSON to the shared root fixture (used by C++/Python) and
Java test resources. Generation refuses to mutate either copy unless
both ML-KEM sections are available, and stages each replacement in its
destination directory. The two replacements are not one filesystem
transaction; use `scripts/gen_protocol_kats.py --check-copies` to detect
drift after an interruption.

### Argon2 parallelism portability

The Argon2id parallelism parameter is not stored in the wrap header.
As of 3.7.0, **all three runtimes hardcode the default lane count to
`4`** so blobs are portable across hosts regardless of the encrypting
machine's CPU count:

| Runtime | Default | Source |
| :-- | :--: | :-- |
| C++ | 4 | `kArgon2Parallelism` in `cpp/include/basefwx/constants.hpp` |
| Java | 4 | `ARGON2_PARALLELISM` in `Constants.java` (`defaultArgon2Parallelism()` returns 4) |
| Python | 4 | `basefwx.ARGON2_PARALLELISM` in `python/basefwx/legacy.py` (added 3.7.0); used by `_kdf.py` |

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

### Peer PBKDF2 cost ceiling

All three BaseFWX runtimes reject peer-controlled PBKDF2 iteration
counts outside `1..4_000_000` before starting the KDF. The rule covers
`ENC-KDF-ITER` in simple and direct-stream file codecs plus the
unsigned iteration fields in raw/streaming fwxAES and live headers.
Metadata parsing is strict: zero, signs, trailing junk, decimal
overflow, integer overflow, and `4_000_001` are invalid; exactly
`4_000_000` remains accepted.

The 4,000,000 ceiling is twice the shared 2,000,000-iteration heavy
writer profile and is aligned with YUME's protocol-side limit. It
does not change writer defaults; it bounds unauthenticated
peer-triggered CPU amplification during decode.

The 4,000,000 value is a decoder safety ceiling, not a claim that
4,000,000 PBKDF2 iterations are cryptographically stronger than
10,000,000. Higher counts increase password-guess cost, but they also
increase attacker-controlled CPU amplification and latency. Writers use
the shared 2,000,000 heavy profile; deployments needing more protection
should prefer Argon2id within the authenticated shared parameter caps
instead of accepting unbounded PBKDF2 work from peers.

Writers also reject configured PBKDF2 costs above 4,000,000 before key
encapsulation, KDF work, or output creation. This is a shared wire and
resource-safety boundary, not a recommendation to replace Argon2id with
the highest permitted PBKDF2 count.

### AES-heavy payload key separation

New non-stripped AES-heavy simple and direct-stream writers in C++,
Java, and Python emit authenticated metadata `ENC-KSEP=v1`. They
transport the same root key used by legacy files, then derive:

| Purpose | Exact HKDF-SHA256 info label |
| :-- | :-- |
| Payload AES-256-GCM | `basefwx.fwxaes.payload.aead.v1` |
| Payload obfuscation | `basefwx.fwxaes.payload.obf.v1` |

All three decoders implement the same rules:

- `ENC-KSEP=v1`: use the two derived subkeys.
- Missing or empty `ENC-KSEP`: decode the legacy raw-root-key format.
- Any other value: fail closed before key recovery or payload crypto.

Stripped-metadata output necessarily omits the marker and therefore
retains the legacy key schedule. This preserves old-file readability
without guessing a key schedule and prevents a new writer from
advertising `v1` while encrypting with the root key.

The repository cross-runtime matrix verifies `ENC-KSEP=v1` and decoded
byte equality for all six C++/Java/Python producer-to-consumer directions
on both the simple codec and a deterministic payload larger than 3 MiB
that forces direct streaming. Every direction runs once with payload
obfuscation enabled and once with it disabled. The producer must emit
`ENC-OBF=yes`/`fast` or `ENC-OBF=no` to match the bytes it actually
encrypted, and the consumer follows that authenticated wire value rather
than its local producer preference. Missing `ENC-OBF` retains the legacy
`yes` behavior; values other than `yes`, `no`, and `fast` fail closed.

### fwxAES plugin tag (new in 3.7.0)

Plugin use is opt-in at encrypt time. When present, byte 4 of the FWX1
header is `0x03` (`FWXAES_ALGO_PLUGIN`) instead of `0x01` / `0x02`.
Immediately after the 16-byte fixed header:

```
plugin_id   16 bytes
position     1 byte  (PRE_AEAD=1, POST_AEAD=2)
config_len   2 bytes big-endian (max 65535; host caps at 64 KiB)
config       config_len bytes
```

Constants are synced across C++ (`constants.hpp`), Java
(`Constants.java`), and Python (`legacy.py`). Decrypt requires the same
`plugin_id` loaded (embedded registry or `--plugin` path). `POS_RAW`
is refused unless the plugin declares `CAP_SAFE_RAW_MODE`.

**Backward compatibility:** blobs encrypted with 3.6.4 (no plugin tag,
`algo=0x01`) decrypt unchanged on 3.7.0. Plugin-tagged blobs do not
decrypt on 3.6.4 peers (unknown algo — fail closed).

### Master-key wrap: cross-runtime parity

All three runtimes accept two kinds of `master_blob` in a keywrap header:

- **Exact EC frame** (`EC1` + u16 length 133 + one uncompressed P-521
  point; 138 bytes total) — decoded by `EcKeys` /
  `basefwx::ec::KemDecrypt` / `_ec_kem_dec`.
- **PQ blob** (raw ML-KEM-768 or ML-KEM-1024 ciphertext, no magic
  prefix) — decoded by `PQ.kemDecrypt` / `basefwx::pq::KemDecrypt` /
  `_pq.kem_decrypt`. The standardized private-key/ciphertext sizes select
  the algorithm; decrypt does not depend on matching process env state.

On encrypt, when `useMaster=true`, every runtime **prefers the PQ public key** (`BASEFWX_MASTER_PQ_PUB`, or an opt-in build-time embed via `-DBASEFWX_MASTER_PQ_PUB_B64` / `-Dbasefwx.master.pq.public.b64` — empty in upstream artifacts) and falls back to EC only when PQ is unavailable and `BASEFWX_PQ_STRICT` / `BASEFWX_PQ_ONLY` is not set.
The exact selected public-key instance is retained for wrapping and
metadata: its standardized size determines `ENC-KEM=ml-kem-768` or
`ml-kem-1024`; EC fallback records `EC`; no effective master records
`none`. `BASEFWX_MASTER_PQ_ALG` affects generation/default reporting,
not a provisioned key's wrap algorithm or metadata.

On decrypt, `KeyWrap.recoverMaskKey` recognizes only the exact 138-byte
`EC1` P-521 frame; all other blobs are dispatched by standardized ML-KEM
key/ciphertext size rather than by a three-byte prefix.
Non-EC blobs use `PQ.loadMasterPrivateKey()`
(`BASEFWX_MASTER_PQ_SK` when explicitly set, otherwise
`~/master_pq.sk`). An explicitly configured private-key path is
authoritative: if it is missing, recovery fails instead of silently
trying the home-directory default. For a dual-wrapped payload, the
independent user blob remains usable with the correct password when
master recovery is disabled or the master key is missing, wrong,
corrupt, or rejected by strict-PQ policy.

**Strict PQ mode:** set `BASEFWX_PQ_STRICT` or `BASEFWX_PQ_ONLY` to a
true spelling (`1`, `true`, `yes`, or `on`, case-insensitive) to refuse
EC master blobs. A master-wrap encryption request fails if no ML-KEM
public key is configured; it does not silently emit an EC- or
password-only payload. Strict policy does not disable a valid,
independent password wrap already present on decrypt.

**Password-only blobs** (no master key) work everywhere. **EC-master** and **PQ-master** blobs round-trip across C++, Java, and Python when the matching master keys are configured.

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
  - Standard: ~64 MiB for default parameters (memory_cost=2^16 KiB = 65536 KiB)
  - Short passwords: ~128 MiB for enhanced security (memory_cost=2^17 KiB)
  - Heavy operations: ~256 MiB (memory_cost=2^18 KiB)

**Low-memory selection**: choose PBKDF2 explicitly before encryption if
the host cannot run the advertised Argon2 profile:
```bash
export BASEFWX_USER_KDF=pbkdf2
```

An Argon2 allocation/runtime failure is terminal. BaseFWX does not
silently switch KDFs after serializing an Argon2 label.

If Python starts without the optional Argon2 module, automatic KDF
selection chooses PBKDF2 before metadata is built and retains the shared
600,000-iteration writer default. It does not use the historical
32,768-iteration compatibility downgrade.

### PBKDF2 (Explicit Alternative)
- **Memory**: Minimal (~1 MiB)
- **Writer defaults**: 600,000 iterations for ordinary user wrapping;
  2,000,000 for AES-heavy file operations
- **Safety ceiling**: 4,000,000 iterations for producers and
  peer-controlled decode parameters

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
- ~~`ALLOW_BAKED_PUB`~~: **Removed in 3.7.0.** Upstream artifacts no
  longer contain a maintainer key. Use `BASEFWX_MASTER_PQ_PUB` at runtime or
  deliberately supply the documented build-time embedding option for a
  deployment-owned key.
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
