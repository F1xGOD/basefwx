# Changelog

## [Unreleased]

### Security
- **Payload key separation (`ENC-KSEP=v1`).** New non-stripped
  AES-heavy simple and direct-stream file payloads from C++, Java, and
  Python derive independent AES-GCM and obfuscation subkeys from the
  transported root with the exact HKDF-SHA256 labels
  `basefwx.fwxaes.payload.aead.v1` and
  `basefwx.fwxaes.payload.obf.v1`. An absent marker retains the legacy
  root-key format; every decoder rejects unknown marker versions before
  key recovery or payload crypto. The cross-runtime matrix now asserts
  the marker, authenticated `ENC-OBF=yes|no` semantics, and byte equality
  in all six C++/Java/Python producer-to-consumer directions for both
  simple payloads and a deterministic payload larger than 3 MiB. The
  resulting 24-lane gate also fixed direct-stream writers/readers that
  previously applied obfuscation despite advertising `ENC-OBF=no`.
  Decoders now follow the authenticated mode independently of local
  writer settings and reject unknown `ENC-OBF` values.
- **Authentication-before-publication.** Generic fwxAES stream/file and
  media-trailer decryptors now authenticate into a private spool before
  replacing or writing caller-visible destinations. Java no longer has
  a 250 KiB in-memory decrypt ceiling. C++ sibling temps use exclusive
  creation and owner-only permissions (including a protected
  current-user DACL on Windows).
- **Pre-auth allocation hardening.** Raw/live fwxAES and JMG trailer
  parsers validate overflow-safe claimed layouts before allocation,
  KDF, key recovery, or output. fwxAES/live/JMG key headers share a
  64 KiB cap across all three runtimes.
- **Peer PBKDF2 cost ceiling (C++/Java/Python).** Peer-controlled
  `ENC-KDF-ITER` metadata and raw/streaming fwxAES/live iteration
  fields now fail closed outside `1..4_000_000`, with strict decimal
  parsing before KDF work. The 4,000,000 ceiling is twice the shared
  2,000,000-iteration heavy writer profile, aligned with YUME, and
  bounds unauthenticated CPU amplification.
- **Peer Argon2 cost caps (C++/Java/Python).** Metadata
  `ENC-ARGON2-TC/MEM/PAR` above shared maxima (16 / \(2^{18}\) KiB /
  16) fail closed on decrypt/derive.
- **Pre-auth metadata/resource caps.** Python uses one strict bounded
  decimal parser for every peer KDF number, caps length-prefixed blobs
  at 64 MiB and metadata at 1 MiB, and validates declared stream lengths
  against the remaining file before allocating or invoking a KDF.
- **Producer KDF ceiling.** C++, Java, and Python raw, stream, live, and
  AES-heavy file writers reject PBKDF2 profiles above 4,000,000 before
  key encapsulation, derivation, header construction, or output.
- **Password minimum length parity.** Java/Python encrypt paths enforce
  the C++ `kMinimumPasswordLength=10` policy (override with
  `BASEFWX_ALLOW_WEAK_PASSWORD=1` / `BASEFWX_MIN_PASSWORD_LEN`).
  Negative/invalid minimum overrides no longer weaken the default, and
  Python stream/live/file entry points enforce the same policy.
- **KEM selection is blob-derived.** Compatibility encrypt/decrypt
  overloads infer ML-KEM-768 versus ML-KEM-1024 from standardized
  key/ciphertext sizes, so recovery no longer depends on matching
  `BASEFWX_MASTER_PQ_ALG` process state.
- **Authenticated selected KEM metadata.** File writers retain the exact
  selected PQ/EC public key; its actual type/size determines
  `ENC-KEM=ml-kem-768`, `ml-kem-1024`, `EC`, or `none`.
- **EC key loading fails closed.** C++/Java/Python cap EC public/private
  files at 4 MiB, treat explicit paths as authoritative, and remove the
  stray native Windows private-key fallback.
- **Python Argon2 failure is terminal.** Allocation/runtime errors no
  longer silently switch to PBKDF2 after Argon2 metadata was chosen.
- **Python missing-Argon fallback retains the full PBKDF2 cost.** When
  the Argon2 module is unavailable before KDF selection, Python chooses
  PBKDF2 at the shared 600,000-iteration writer default; it no longer
  applies the historical 32,768-iteration downgrade.
- **Java PB512 stream permutation parity.** Java now truncates the
  per-chunk HKDF expansion to the protocol-specified 16 bytes before
  selecting its 64-bit permutation seed. Previously it selected the
  seed from the untruncated 32-byte HMAC block, so non-fast Java streams
  authenticated but decoded incompatibly with C++/Python once a chunk
  entered the 4 KiB PCG permutation path.
- **Java secret cleanup.** KEM shared secrets and loaded PQ private keys
  are wiped in `finally` paths even when HKDF or decapsulation fails.
- **Bounded Python master-key loading.** PQ/EC key files, overrides, and
  zlib-decoded material are capped at 4 MiB, matching native/Java loaders
  and rejecting compressed expansion bombs before KEM parsing.
- **Java + Python password resolution parity with C++.** Bare password
  strings are always literal; filesystem read requires an explicit
  `file://` URI; `password://` forces a literal. Removes the silent
  "string names an existing path → read that file" behavior that C++
  already closed in 3.7.0. Unit tests cover the URI schemes on Java
  and Python.
- **Java `b512file` mask-wrap AAD parity.** `B512FileCodec` now uses
  `MASK_AAD_B512FILE` (`"b512file"`) for `KeyWrap` prepare/recover,
  matching C++ `kMaskAadB512File` and Python `aad=b'b512file'`. It
  previously passed `B512_AEAD_INFO` (`"basefwx.b512file.v1"`), which
  broke cross-runtime decrypt of the password wrap. Payload AEAD /
  HKDF still use `B512_AEAD_INFO`.
  Decode alone retries the exact Java-3.7 user-wrap AAD after a canonical
  user-wrap authentication failure; parse/KDF/master/payload failures
  never trigger the compatibility retry.
- **Orig-tar privacy.** Debian orig archives now use Git-known
  tracked/unignored files only and fail closed on private AI/agent/tool
  state or secret-path names at any depth. Frozen qualification snapshots may
  supply the exact NUL-delimited, sorted Git-visible source manifest instead
  of copying repository metadata; unsafe, duplicate, unsorted, missing, and
  secret-named members still fail before archive publication.

### Added
- **ChaCha20-Poly1305 explicit-nonce one-shot (C++ only).**
  `basefwx::crypto::ChaCha20Poly1305EncryptWithIv` and
  `ChaCha20Poly1305DecryptWithIvOwned` add the RFC 8439 AEAD alongside the
  existing AES-GCM helpers, for callers that must keep an established
  ChaCha20-Poly1305 at-rest format. The key is 32 bytes and the nonce
  exactly 12 — unlike AES-GCM this construction has one legal nonce size,
  so a merely non-empty IV is rejected. The encrypted form is
  `ciphertext || 16-byte tag` with no framing; the caller owns nonce
  storage. AAD is explicit and may be empty, which RFC 8439 defines as
  absorbing zero AAD bytes and is therefore byte-identical to a producer
  that never supplies AAD. Plaintext is staged in `SecureBytes` and
  released only after the Poly1305 tag verifies, so a forgery publishes
  nothing and raises `AuthenticationError`; length errors are reported as
  `std::runtime_error` / `std::length_error` before any narrowing to the
  OpenSSL `int` width. Covered by the RFC 8439 §2.8.2 known-answer vector
  plus fixed empty-AAD fixtures in `crypto_api_safety_test`.
  **Java and Python parity is not claimed** — see COMPATIBILITY.md.
- **Phase 0 — protocol KATs.** `scripts/gen_protocol_kats.py` +
  `cpp/tools/protocol_kat_gen.cpp` emit shared repository fixtures under
  `testdata/protocol_kats/` (HKDF, X25519, ML-KEM-768/1024). The
  generator is opt-in (`BASEFWX_BUILD_PROTOCOL_KAT_GEN=ON`) so it does
  not pollute projects that consume BaseFWX through `add_subdirectory`.
  Generation requires both ML-KEM sections before replacing either
  fixture, stages same-directory temporary files, and provides
  `--check-copies` to detect root/Java drift after an interrupted
  two-file update.
- **Phase A — explicit-salt HKDF.** Java
  `Crypto.hkdfSha256(ikm, salt, info, len)` and Python
  `hkdf_sha256(..., salt=)` match the C++ 4-arg overload (KAT-tested).
- **Phase B — X25519.** Java `com.fixcraft.basefwx.X25519` and Python
  `basefwx.x25519`: raw 32-byte keys, wipe helpers, reject
  all-zero shared. Java uses BouncyCastle's lightweight API and remains
  compatible with the module's Java 8 bytecode target. Not wired into
  fwxAES. **Android sync-list note:**
  add `X25519.java` to Yume Android `syncBasefwxJava` when that tree
  is updated (out of this repo).
- **Phase C — ML-KEM alg selection + GenerateKeyPair + 1024.** Java
  `PQ.KemAlgorithm` / `generateKeyPair` / alg-parameterized
  encrypt/decrypt; Python `generate_kem_keypair` /
  `current_kem_algorithm` / `is_supported_kem_algorithm`. Default
  generation/default reporting remains 768;
  `BASEFWX_MASTER_PQ_ALG=ml-kem-1024` opts generation/reporting into 1024
  but never changes a file by itself. Provisioned key size selects the
  actual wrap and authenticated `ENC-KEM` value. BC Kyber
  matches liboqs KATs for both sizes. CLI `version` prints
  `pq=ml-kem-768|1024` instead of misleading `oqs=OFF`.

### Changed
- **Bounded, active-surface benchmark matrix.** Parallel fwxAES timing now
  applies the existing payload-memory worker cap consistently to Python, C++,
  and Java instead of launching one whole-file operation per CPU. Java's
  fwxAES worker failures are propagated to the benchmark process. Retired
  b256 and kFM/kFA/jMG performance rows no longer run by default; set
  `BASEFWX_BENCH_RETIRED=1` for an explicit compatibility-performance run.
  Focused correctness and existing-data compatibility coverage is unchanged.
- **Media codec retirement.** The image-, audio-, and video-specific
  kFM/kFA/jMG codecs remain available in the 3.7.0+ compatibility line,
  including decode support for existing data, but retire from active
  development after this change. Future work is limited to security,
  correctness, and compatibility fixes; no new formats, features, or
  performance work is planned. Active development shifts to mathematically
  grounded, high-performance C++ cryptographic primitives. This is a
  maintenance-status change, not a wire-format or API removal.
- **Native package boundary and ABI policy.** GPL CLI headers and color
  implementation now live under `cpp/src/cli` and link only into the
  executable; `libbasefwx.so.3` and installed headers remain LGPL. CMake
  compatibility is limited to the same minor line, staged pkg-config/CMake
  consumers exercise the 3.8 HKDF/X25519/ML-KEM-1024 API, and Debian shlibs
  metadata requires the 3.8 runtime for binaries built against it.
- **Debian development package.** The source version is
  `3.8.0~dev1-1`, development orig archives use Debian's `~dev` ordering,
  and package builds run the native CTest suite instead of skipping it.
- **Phase D — file/wire parity.** Java pb512file Argon2-heavy +
  streaming/PQ master wrap (prefer PQ via `KeyWrap`/`PQ`); master-wrap
  defaults changed to off only for Python `encryptAES` / `decryptAES`,
  fwxAES raw/stream/live constructors, and Java `FwxAES.Builder` /
  one-argument `LiveCipher.LiveEncryptor`, matching the CLIs/C++
  `basefwx::fwxaes::Options`. Compatibility-sensitive Python
  b512/file/media/JMG, Java one-argument `LiveCipher.LiveDecryptor`,
  and `FwxAESPureJava()` defaults remain unchanged; password
  min-length parity (above).
- **Phase E — docs.** COMPATIBILITY / SECURITY / CLI / CHANGELOG
  advertise multi-lang builders after KAT gates.
- **License policy**: replace the old GPL-3.0 + Additional Terms model
  with a file-level split — LGPL-3.0-or-later for core library/API/runtime
  and plugin ABI/SPI, GPL-3.0-or-later for standalone
  CLI/tools/benchmarks/scripts, and MIT OR Apache-2.0 for example plugin
  templates. Canonical texts live in `LICENCE`, `LICENSES/`, and
  `LICENSING.md`. Remaining tooling without headers was updated to match.
- **Docs truth pass:** CLI password/master-key notes, SECURITY.md current
  status (3.7.0 / 3.8.0-dev1), COMPATIBILITY Argon2/Python wording,
  plugin README loader status, Yume-as-sibling man/EXPLAINED notes,
  crypto helper boundary section in SECURITY.md; fix Java
  ML-KEM/Argon2 CLI/README lies; `--use-master` naming; honest keyed
  plugin host_secret status in SECURITY.md / THREAT_MODEL.md.
- **Private hygiene:** ignore `AGENTS.md` / `CLAUDE.md` / `RULE.md` /
  `.cursorrules` (and nested forms); exclude `.private/**` from branch
  sync and Debian orig tarballs.
- **Master recovery policy parity:** C++/Java/Python dual-wrapped
  payloads use the independent password wrap when master recovery is
  disabled or fails because a key is missing, wrong, corrupt, or
  rejected by strict-PQ policy. Strict PQ mode refuses password-only /
  EC fallback when a master wrap is requested for encryption.
- **Environment boolean parity:** `BASEFWX_PQ_STRICT` /
  `BASEFWX_PQ_ONLY` and the common Java `Constants.envEnabled` / Python
  `_env_enabled` helpers used by the KDF/performance paths touched here
  accept `1`, `true`, `yes`, or `on`, case-insensitively. Legacy flags
  with exact-`1` contracts retain their existing semantics.

## [v3.8.0-dev1] - 2026-07-19

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.7.0...main>

### Added
- **C++ protocol-building primitives.** The public C++ API now provides an
  explicit-salt HKDF-SHA256 overload, move-only self-wiping ephemeral
  ML-KEM keypairs with explicit ML-KEM-768 / ML-KEM-1024 selection, and
  move-only self-wiping X25519 keypairs/shared-secret derivation with
  all-zero shared-secret rejection.

### Notes
- At the initial 3.8.0-dev1 baseline these primitives were C++-only. The
  current `[Unreleased]` tree adds the Java/Python mirrors and shared
  cross-runtime KATs described above. Android remains a separate consumer and
  must update its hard-coded Java source sync list before claiming parity.

## [v3.7.0] - 2026-06-26

Compare: <https://github.com/F1xGOD/basefwx/compare/v3.6.4...v3.7.0>

> **Release status:** `v3.7.0` was tagged on 2026-06-26. The fwxAES/CLI plugin
> loader and wire-format plugin tag shipped in that release.

> The audit-driven hardening that briefly sat under `[v3.6.5]` in working
> trees is rolled into 3.7.0 alongside the new **blackbox plugin** ABI.
> 3.6.5 was never tagged or published.

### Added
- **Java SPI + Python plugin module (Profile A).** `com.fixcraft.basefwx.plugin` (ServiceLoader) and `basefwx.plugin` (pure Python + ctypes for native `.so`) ship with example plugins and `scripts/plugin-smoke.sh`.
- **fwxAES/CLI plugin loader (Profile A).** C++ host loader (`plugin_loader.cpp`): `Registry::Find` → `dlopen` → ABI check → `init` → cached `capabilities()` → PRE/POST AEAD dispatch. Wire-format plugin tag (`algo=0x03`) written at encrypt time; decrypt fails closed without matching plugin. CLI flags: `--plugin <path>`, `--plugin-id <hex>`, `--plugin-pos pre|post`, `--plugin-config <file>`. Java/Python fwxAES raw paths mirror the tag layout. JNI bridge, Profile B Java/Python SPI parity, and `basefwx-plugin-verify` remain 3.7.x follow-ups.
- **Keyed plugin path (`forward_keyed` / `inverse_keyed`).** Plugins can opt into a per-call `tweak` (host-supplied randomness or self-derived from external entropy) and a `host_secret` (host-derived from the user's password) threaded through the transform. This binds the plugin's output to user-secret context, so extracting the plugin `.so` and its static config does not let an attacker reproduce the transform offline. New `BASEFWX_PLUGIN_DEFINE_KEYED(...)` macro in `plugin.hpp` and `Capabilities()` method on the plugin class. Backwards-compatible — v1 plugins (deterministic `forward`/`inverse` only) continue to load and run. See `examples/plugins/aead-wrapped-keyed/` for the canonical shape (HKDF + AES-CTR + HMAC-SHA256 with constant-time tag compare).
- **Plugin raw-mode position (`BASEFWX_PLUGIN_POS_RAW`).** Plugin transforms run without an AEAD layer above or below. The host structurally refuses this position unless the plugin declares `BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE` in `capabilities()`. Intended for client→server protocols where the server holds the secret and rejects tampered blobs (THREAT_MODEL.md TM-4).
- **Plugin capability bits.** `BASEFWX_PLUGIN_CAP_KEYED`, `BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE`, `BASEFWX_PLUGIN_CAP_REQUIRES_TWEAK`, `BASEFWX_PLUGIN_CAP_REQUIRES_HOST_KEY`, `BASEFWX_PLUGIN_CAP_NONDETERMINISTIC`. Plugins self-declare what they need; the host fails calls closed when requirements are unmet (e.g. `tweak_len == 0` when `REQUIRES_TWEAK` is set).
- **Self-derived-tweak example (`time-tweak/`).** Demonstrates how a plugin can produce different output for the same input on every call (using unix-millisecond timestamps as the entropy source) while still being decodable from the wire bytes alone — the tweak is embedded at the head of the plugin's output, the decoder reads it back. Useful template for orgs that want non-deterministic obfuscation without a host-supplied tweak.
- **Plugin static-embed Registry (`cpp/include/basefwx/plugin_static.hpp`).** In-process plugin registry. `basefwx::plugin::Registry::Register(vtable*)` registers a vtable compiled directly into the host binary; `Registry::Find(plugin_id)` resolves it without `dlopen`. The `BASEFWX_PLUGIN_REGISTER_STATIC(...)` macro wraps the at-startup registration. Header-only, thread-safe. The `static-embed/` example demonstrates an end-to-end host binary that registers + round-trips a plugin with no `.so` on disk. Static linking or embedding BaseFWX itself follows LGPL-3.0-or-later requirements for the BaseFWX library files involved.
- **`examples/plugins/THREAT_MODEL.md`** — authoritative documentation of the five threat models the plugin contract addresses (TM-1 passive observer, TM-2 extracted plugin + config, TM-3 oracle attack, TM-4 malicious client forgery, TM-5 live debugger / out of scope), the three plugin profiles, and the rules in one screen.
- **`BASEFWX_PLUGIN_ERR_CAP_MISMATCH` (-6).** Returned when the host invokes a function the plugin did not declare in `capabilities()` (e.g. `forward_keyed` on a v1 plugin that left the slot NULL).
- **Argon2id user-KDF wrap on the Java runtime.** `KeyWrap.deriveUserKeyWithLabel` now routes the `argon2id` / `argon2` labels through BouncyCastle's `Argon2BytesGenerator` (already a runtime dep). `Crypto.argon2idHashRaw` is the new public primitive mirroring `basefwx::crypto::Argon2idHashRaw` byte-for-byte. The `KdfOptions` Java class grows `argon2TimeCost` / `argon2MemoryKib` / `argon2Parallelism` fields with defaults that mirror the C++ constants; **parallelism defaults to 4 across all three runtimes** (see "Argon2id parallelism portability" below). The `❌` row in COMPATIBILITY.md flips to `✅`. The `UnsupportedKdfException` typed exception is retained for truly unsupported labels.
- **`hardenKdfOptions` short-password step-up applies to Argon2 too** (mirrors `kShortArgon2*` from constants.hpp).
- **Resource guards for bench / test runners.** `scripts/lib/resource_guards.sh` ships a shared helper that caps the runner's CPU to `nproc - 1` (leaves one logical core free), pins the parent shell with `taskset`, sets `OMP_NUM_THREADS` / `OPENBLAS_NUM_THREADS` / `MKL_NUM_THREADS` / `BASEFWX_MAX_THREADS`, and bounds virtual memory via `ulimit -v` to 75 % of system RAM by default. `scripts/test_all.sh` and `scripts/plugin-smoke.sh` source it automatically; opt out per-invocation with `--no-guards` or env `BASEFWX_NO_GUARDS=1`, override the caps with `--max-cpu-cores N` / `--mem-cap-pct N`. Closes the laptop-OOM failure mode the bench could fall into when sequenced across many heavy methods in one Python process.
- **Memory-leak detection CI** (`.github/workflows/leak-detect.yml`). Three jobs, each fails the workflow on a leak: Python uses `scripts/leak_detect.py` (tracemalloc snapshots + RSS-slope linear regression, fails above 8 KiB / iter); C++ uses `scripts/leak_detect_cpp.sh` (rebuilds basefwxcpp with `-fsanitize=address,leak` and runs a probe across hashes / base64 / AEAD round-trip / b256, LSan exits non-zero on any leak); Java uses an inline `HeapLeakProbe` that diffs `MemoryMXBean` heap usage after warm-up + 500 iterations + `System.gc()`. Catches code-level leaks (missing free, unfreed JNI globalrefs, unreleased RAII state) — NOT allocator-pool fragmentation, which is a runtime concern handled by the resource guards above.
- **Benchmark heaviness chips on the website.** `website/results/heaviness.json` classifies each benchmark method as `low` / `medium` / `high` / `extreme` based on typical peak working set and CPU time per call, with documented per-method notes. `website/assets/site.js` reads the manifest at page load and decorates each entry on the Detailed Results panel with a colored chip (`heaviness-low` = green, `medium` = amber, `high` = orange, `extreme` = red). Lets users at a glance see which methods can run on a laptop and which need a build box.

### Deprecated
- **`B256Encode` / `b256encode` / `b256Encode`** (C++ / Python / Java). 🫡 **Retired.** b256 was the very first encoding method in BaseFWX — born in V1, back when this was a proof of concept and not a project. It served from day one through every release since. Marked `[[deprecated]]`, `@Deprecated`, `DeprecationWarning` and emits a one-time retirement notice on first call (with 🫡 and ❤️ in the message, because the moment deserves it). Existing b256-encoded blobs still decode; use stdlib base64 or `Hash512` for new code. Internal callers in the already-deprecated `Bi512`/`A512` codecs route through the un-deprecated `codec::B256Encode`/`Decode` helpers so they don't double-warn.
- **`Uhash513` / `uhash513`** (C++ / Python / Java). Non-standard chained hash (`SHA-256 → SHA-1 → SHA-512 → SHA-256` over the concatenation of two intermediate digests). The SHA-1 hop in the middle uses a hash with known collision weaknesses and adds no security to the construction; the overall collision resistance is bounded by the outer SHA-256 anyway. The "513" in the name is marketing — the output is a 256-bit SHA-256 hex string. Use `Hash512` (SHA-512) or SHA3-512 for new code. Existing call sites continue to work.
- **`Bi512Encode` / `bi512encode` / `bi512Encode`** (C++ / Python / Java). Marked `[[deprecated]]`, `@Deprecated`, `DeprecationWarning`. It's SHA-256 with a custom prefilter — the prefilter adds no security beyond SHA-256 itself. Use `Hash512` / `hash512` for new code. Existing blobs continue to encode/decode.
- **`A512Encode` / `A512Decode` / `a512encode` / `a512decode`** (C++ / Python / Java). Reversible obfuscation codec with no security goal (no key, no AEAD), slower than base64 for the same output. Use stdlib base64 for new reversible-encoding needs (b256 is also retiring; see above). Existing blobs continue to encode/decode.

### Security
- **Drop PBKDF2-32k second-chance fallback** in C++ `keywrap.cpp::RecoverMaskKey`. AES-GCM auth failure (and any other thrown exception during decode) is now terminal — no retry with a 20× weaker derivation. Pre-3.x blobs that relied on this fallback are unsupported per SECURITY.md.
- **`ResolvePassword` requires an explicit URI scheme** to load from disk: `file://<path>` reads, `password://<literal>` forces literal, bare strings are always literal. Removes the silent reinterpretation where a password equal to an existing path was read as that file's contents.
- **Remove baked maintainer ML-KEM-768 public key** from upstream artifacts. Deployments that want a baked key now opt in at build time via `-DBASEFWX_MASTER_PQ_PUB_B64=<base64-key>` (C++ CMake option) or `-Dbasefwx.master.pq.public.b64=<base64-key>` (Java sysprop). The `BASEFWX_MASTER_PQ_ALLOW_BAKED` / `ALLOW_BAKED_PUB` env-var gates are gone with the literal.
- **Remove `BASEFWX_MASTER_EC_CREATE_IF_MISSING`** silent EC master-keypair auto-generation in both C++ `keywrap.cpp` and Java `EcKeys.masterEcAutoCreateEnabled`. Callers must provision the EC keypair explicitly.
- **Remove hardcoded Windows `W:\master_pq.sk`** maintainer-machine path in `pq.cpp::LoadMasterPrivateKey`. Configure via the new `BASEFWX_MASTER_PQ_SK` env var, falling back to `~/master_pq.sk`.
- **Gate `BASEFWX_TEST_KDF_ITERS` behind a compile-time flag.** Honored in C++ only when built with `-DBASEFWX_TESTING=ON`; in Java only when run with `-Dbasefwx.testing=true` or `BASEFWX_TESTING=1`. Single `basefwx::env::TestKdfIters()` helper threads through every call site; the Java side adds `Constants.TESTING_BUILD`.
- **Tighten fwxAES parser bounds.** Wrap-mode `header_len_wrap` capped at 64 KiB (was 4 MiB — real wrap headers are 200–500 bytes), PBKDF2-mode `iters` must be ≥ 10 000. A `kdf`-byte flip can no longer reinterpret one field as a plausible value of the other.
- **Cap `format::UnpackLengthPrefixed`** at 64 MiB total / 64 MiB per part on the C++ side (matches the existing Java cap that's been there since 3.4.x). Malformed blobs declaring 4 GiB parts no longer survive to upstream pre-sizing code.
- **Cap `pq::ReadFileBytes`** at 4 MiB. A symlink under `BASEFWX_MASTER_PQ_PUB` pointing at `/dev/zero` no longer OOMs the process.
- **Refuse to wrap the LiveCipher sequence counter.** C++ `LiveEncryptor::Update` / `Finalize` and Java `LiveEncryptor.update` / `finish` now throw when the counter would advance past `2^64-1` / `Long.MAX_VALUE`, preventing AES-GCM nonce reuse under the same key.

### Changed
- **`BaseFwxImage.java` split from `BaseFwx.java`.** The image-carrier public API (`kFMe`, `kFMd`, `kFAe`, `kFAd`, `jmgEncryptFile`, `jmgDecryptFile`) moved verbatim to a new **`BaseFwxImage.java`** class in the same package. The core `BaseFwx` class no longer imports `java.awt.*` / `javax.imageio.ImageIO` — enabling Android Gradle sync of the core class. **Source-level breaking change**: `BaseFwx.kFMe(...)` → `BaseFwxImage.kFMe(...)` (same for the other 5 methods). Wire format unchanged.
- **Monolith decomposition** across C++ (filecodec, imagecipher, kfm, CLI), Java (BaseFwx codecs, CLI, MediaCipher), and Python (`legacy.py` → implementation modules). No wire-format or public API changes beyond the BaseFwxImage move.
- **`fwxaes.cpp` wipes all key locals via `SecretGuard`.** 3.6.4 had zero `SecureClear` calls in this file vs nine in `keywrap.cpp`; every PBKDF2-derived AES key and HKDF mask key was leaked to the free-list. `SecretGuard` is now declared after the secrets it tracks so destruction order is correct (see code comments for the rationale — declaring it first is a use-after-free).
- **Java `LiveEncryptor` and `LiveDecryptor` implement `AutoCloseable`** and zeroize `password`, `key`, `noncePrefix`, and the decrypt buffer on `close()`. The four in-package callers in `fwxAesLive{Encrypt,Decrypt}{Chunks,Stream}` now use try-with-resources.
- **Java `KeyWrap` throws typed `UnsupportedKdfException`** (extends `IllegalArgumentException`, exposes `getKdfLabel()`) for truly unknown KDF labels. Argon2id is now supported; the exception is only raised for unrecognized label strings.
- **Java `KeyWrap` / `FwxAesCodec` secret hygiene.** EC KEM shared secrets and stream/channel AES keys are zeroed via `Arrays.fill` after HKDF use (mirrors C++ `SecureBytes` / `SecureClear`).
- **Python `BASEFWX_TEST_KDF_ITERS` gated** behind `BASEFWX_TESTING=1` (mirrors C++ `TestKdfIters()` / Java `Constants.TESTING_BUILD`).
- **C++ `--allow-embedded-master` / `--master-autogen` CLI flags** no longer set removed env vars; they only opt into `useMaster=true` (with a deprecation notice for `--master-autogen`).

### Removed
- **`b1024` retired in all three runtimes.** It was a one-line alias of `Bi512Encode(A512Encode(input))` — no new security, no new functionality, and a large chunk of the cross-runtime test-suite wall-clock. C++ `B1024Encode`, Java `BaseFwx.b1024Encode`, Python `basefwx.b1024encode`, the `b1024-enc` CLI subcommand (C++ + Java), and the `b1024` hash-bench method are all gone. Callers wanting the same output can chain `bi512(a512(input))` themselves. `scripts/test_all.sh` benchmarks and compare-blocks updated; docs cleaned.
- `BASEFWX_MASTER_PQ_ALLOW_BAKED` env var (C++ + Java).
- `ALLOW_BAKED_PUB` env-var alias (C++ + Java).
- `BASEFWX_MASTER_EC_CREATE_IF_MISSING` env-driven auto-create (C++ + Java). The env-var name constant is retained in `Constants.MASTER_EC_CREATE_IF_MISSING_ENV` so callers still compile.
- Baked `kMasterPqPublicB64` literal in `constants.hpp` and `Constants.MASTER_PQ_PUBLIC_B64` in Java.
- Windows-specific `W:\master_pq.sk` path in `pq.cpp::LoadMasterPrivateKey`.
- PBKDF2-32k second-chance branch in `keywrap.cpp::RecoverMaskKey`.

### Notes
- Wire format byte-identical to 3.6.4 for blobs **without** a plugin tag. Plugin-tagged blobs use `algo=0x03` and require 3.7.0+ with the matching plugin loaded.
- See [RELEASE-NOTES-3.7.0.md](RELEASE-NOTES-3.7.0.md) for the upgrade walkthrough.

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
