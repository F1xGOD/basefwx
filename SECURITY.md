# Security Policy

## Supported Versions

**Versioning note:** Current tree / development line is tracked in
`VERSION` (currently `3.8.0-dev1`). Published releases use
`MAJOR.MINOR.PATCH` (latest tagged release: **3.7.0**).

> [!CAUTION]
> DO NOT USE ANY VERSION BELOW 2.6, you -> WILL <- get compromised!

> [!NOTE]
> BaseFWX follows a **roll-forward, single-version** model. Each
> published release is **frozen** — there are no patch builds against
> a release after it ships. The way to get "maintenance" is to install
> the **next release**, which is itself the fix. This is **not** like a
> Windows-style model where 3.6.4 keeps receiving updates while 3.6.5
> is in development; once 3.6.4 is out, the only place fixes land is
> 3.6.5 (or 3.7.0, etc.).

|  Version  | Status / Notes                                                                                                                    | Supported |
| :-------: | --------------------------------------------------------------------------------------------------------------------------------- | :-------: |
| **Latest release** | 👑 Currently recommended. **Frozen at publish time** — the version you can run today. Any future fix arrives as a *new* release, not as an in-place patch. | ✅ |
| **All older releases** | ❌ Superseded the moment a newer release ships. They are not patched, not backported to, and not republished. The *new* release is the maintenance. | ❌ |

### Current status (3.7.0 / 3.8.0-dev1)

- **3.7.0** — blackbox plugin ABI (C++ host loader + fwxAES `algo=0x03` wire tag), Java Argon2id user-KDF, fixed Argon2 parallelism default of **4** across C++/Java/Python, removal of the upstream baked ML-KEM master public key and `BASEFWX_MASTER_PQ_ALLOW_BAKED` / path-as-password auto-read. See [RELEASE-NOTES-3.7.0.md](RELEASE-NOTES-3.7.0.md) and [COMPATIBILITY.md](COMPATIBILITY.md).
- **3.8.0-dev1** (this tree) — multi-runtime protocol-building primitives
  (explicit-salt HKDF, ML-KEM-768/1024 selection + GenerateKeyPair,
  X25519) with C++/liboqs KATs under `testdata/protocol_kats/`. See
  `CHANGELOG.md` / `COMPATIBILITY.md`.

### Retired media codecs

The image-, audio-, and video-specific kFM/kFA/jMG codecs remain available for
compatibility in the 3.7.0+ line, but are retired from routine feature and
performance maintenance after the current unreleased change. Security,
correctness, and existing-data compatibility issues in the latest release
remain in scope under this policy. Active development targets mathematically
grounded, high-performance C++ cryptographic primitives.

Routine benchmark runs omit those media codecs and retired b256. An explicit
`BASEFWX_BENCH_RETIRED=1` enables their performance rows for a compatibility
investigation. This benchmark policy does not remove their focused security,
correctness, or existing-data compatibility coverage.

### Historical: What's New in 3.6.4

For the full write-up — KDF cost table, security-normalized
performance comparison vs 3.6.3, JNI win, AN7/DEAN7, PQ stance —
read [**RELEASE-NOTES-3.6.4.md**](RELEASE-NOTES-3.6.4.md). The short
version:

* **KDF hardening (cross-language).** PBKDF2 and Argon2id default
  costs raised in all three runtimes. A single password guess is
  **2–3× more expensive** for an attacker than under 3.6.3
  (~+1.4 bits of brute-force resistance on top of an already strong
  baseline). Per-blob backwards-compatible: old blobs still decrypt
  at their original cost; only newly produced blobs use the new
  defaults.
* **Faster at the same security level.** Once 3.6.3 results are
  rescaled to the 3.6.4 KDF cost, the overall bench suite is
  **−55 % to −60 %** faster across C++, Java, and Python. KDF-heavy
  paths (`fwxAES`, `b512`/`pb512`, `*file`, `kFMe`/`kFAe`,
  `an7`/`dean7`) are **−60 % to −80 %** faster. Non-KDF micros are
  flat within ±2 %.
* **Zero-copy AES-GCM via JNI** (opt-in). `Crypto.aesGcm*WithIvInto`
  now dispatches through `nativeAesGcm{Encrypt,Decrypt}OneShot` when
  the native backend is active. About **+10 %** throughput on 16 MiB
  fwxAES encrypt locally.
* **AN7/DEAN7** stealth-anonymization layer available in cpp, python,
  and java.
* **Release & build hygiene.** Unified version source across
  languages, CI rejects partial-crypto builds, master-key opt-in
  tightened in the C++ CLI, several Java packaging regressions fixed.

The remainder of this document is the **security policy** that applies
across all releases: support window, default crypto stance, optional
ML-KEM-768 master-key wrap, and how to report vulnerabilities.

#### Default encryption (no master key, no manual configuration)

When you run a `basefwx` encrypt with **no special flags**, what you
actually get is:

1. **AES-256-GCM** for the data step — already considered
   post-quantum-safe (Grover halves the effective key strength, so
   128-bit equivalent against a quantum adversary; symmetric AEAD with
   a 32-byte key is fine).
2. **Argon2id (where available) or PBKDF2-HMAC-SHA256** for the
   password step, at the hardened 3.6.4 cost
   (see [RELEASE-NOTES-3.6.4 → KDF hardening](RELEASE-NOTES-3.6.4.md#1-kdf-hardening-cross-language)
   for the exact parameter table).
3. **HKDF-SHA256** for all subkey derivation; SHA-256 is also PQ-safe
   for this use.
4. **HMAC-SHA256 + AES-256-GCM tags** for authenticity.

| Runtime | Default password KDF (no env override)                        |
| ------- | ------------------------------------------------------------- |
| C++     | **Argon2id** if libargon2 was linked at build time (the release builds require it), else PBKDF2-HMAC-SHA256. |
| Python  | **Argon2id** when `argon2-cffi` is available. If the module is absent before selection, Python uses the full 600,000-iteration PBKDF2 writer default; allocation/runtime failure after Argon2 selection is terminal. Choose PBKDF2 explicitly before encryption on constrained hosts. |
| Java    | **Argon2id** (via BouncyCastle's `Argon2BytesGenerator`, supported since 3.7.0) or **PBKDF2-HMAC-SHA256** — controlled by `BASEFWX_USER_KDF`. |

`BASEFWX_USER_KDF` overrides the default per process (`argon2id` /
`pbkdf2` / `auto`). As of 3.7.0, all three runtimes support Argon2id
and blobs interop across runtimes — the KDF label is encoded in the
wrap header so blobs produced by any runtime can be decoded by any
other. See `COMPATIBILITY.md` for the capability matrix.

The KDF label is authenticated wire state. A runtime never silently
switches an Argon2-labelled operation to PBKDF2 after allocation or
runtime failure, because doing so would emit an undecryptable blob.

AES-heavy simple and direct-stream files also authenticate the payload
key-schedule marker. New non-stripped writers in C++, Java, and Python
emit `ENC-KSEP=v1`, deriving independent 32-byte AES-GCM and
obfuscation keys with HKDF-SHA256 info labels
`basefwx.fwxaes.payload.aead.v1` and
`basefwx.fwxaes.payload.obf.v1`. A missing marker means the legacy
raw-root-key schedule; unknown values fail closed. Decoders never guess
between schedules. The authenticated `ENC-OBF` value controls whether
the payload is deobfuscated; a local writer preference cannot override
that wire decision during simple or direct-stream decode. Missing
`ENC-OBF` retains legacy obfuscation; unknown values fail closed.

Unauthenticated wire lengths are bounded before allocation or KDF work:
fwxAES, live, and JMG wrap/key headers share a 64 KiB maximum. Streaming
decryptors stage plaintext in private storage, verify the GCM tag, then
publish to the caller destination. A failed tag or hostile length must
leave an existing destination unchanged.

**This password-only default is already post-quantum-resistant.** AES-256
under Grover is ≈ 128-bit-equivalent, the KDF salt is per-blob, and
the hardened iteration counts make offline brute force expensive even
under a quantum speedup of the inner hash. ML-KEM-768 is **not**
mixed in here, because in a password-only setting it would not add
security — every PQ private key would itself have to be unwrapped
from the password, so cracking the password breaks every layer.

#### Optional: ML-KEM master-key wrap

**API defaults:** the C++ CLI / `basefwx::fwxaes::Options`, Python CLI,
and Java CLI default master wrap **off**. Library defaults are also off
for Python `encryptAES` / `decryptAES`, fwxAES raw/stream helpers, and live
constructors, and for Java `FwxAES.Builder` and the one-argument
`LiveCipher.LiveEncryptor` constructor. Pass `true` / `--use-master`
to opt in when a master public key is configured. Compatibility-sensitive
Python b512/file/media/JMG entry points, Java's one-argument
`LiveCipher.LiveDecryptor`, and `FwxAESPureJava()` retain their existing
master-enabled defaults; callers should pass the desired policy explicitly.

When (and only when) the caller opts in
(`useMaster=true` / `--use-master` / equivalent), basefwx adds an
ML-KEM wrap on top of the password wrap. The provisioned public key's
standardized size selects **ML-KEM-768** or **ML-KEM-1024** and the
authenticated `ENC-KEM` value; `BASEFWX_MASTER_PQ_ALG` only changes key
generation/default reporting and cannot change a file by itself. The mask key is
encapsulated to a master public key, and the user blob still holds
the password-encrypted copy — either path can decrypt independently.
**All three runtimes ship post-quantum support out of the box** —
they just use different backing libraries:

| Runtime | ML-KEM implementation             | Build requirement                                                                                  |
| ------- | --------------------------------- | -------------------------------------------------------------------------------------------------- |
| C++     | **liboqs** (Open Quantum Safe)    | Linked at build time; release builds enforce this via `BASEFWX_REQUIRE_OQS=ON` (no silent downgrade). |
| Java    | **BouncyCastle PQC** (ML-KEM-768/1024) | Bundled in the published JAR; no extra system package required.                              |
| Python  | **`pqcrypto.kem.ml_kem_768/1024`** | Pulled in by the `basefwx` Python wheel.                                                          |

Sources for the master public key, in priority order:

1. **Caller-provided** via `BASEFWX_MASTER_PQ_PUB=<path>` —
   this is the recommended path for self-hosted / open-source
   deployments. You generate your own ML-KEM-768 or ML-KEM-1024 keypair, keep the
   private key offline, and configure the public half via env or your
   own key-management tooling.
2. **Operator-controlled build-time embedding** — the upstream maintainer key
   literal and the runtime `BASEFWX_MASTER_PQ_ALLOW_BAKED` /
   `ALLOW_BAKED_PUB` gates were removed in 3.7.0. Upstream artifacts contain
   no key. A deployment may deliberately compile its own key through
   `-DBASEFWX_MASTER_PQ_PUB_B64=...` (C++) or
   `-Dbasefwx.master.pq.public.b64=...` (Java); this is configuration supplied
   by that deployment, not a fallback controlled by BaseFWX.
3. **None** — without either of the above, `useMaster=true` first
   considers a separately provisioned EC master public key. If neither
   master key is available, password-backed encryption can continue
   only outside strict-PQ mode. When strict mode is enabled, a requested
   master wrap fails instead of emitting an EC- or password-only
   downgrade.

For a dual-wrapped payload, a correct password and intact user blob
remain an independent decrypt path when master recovery is disabled or
fails because a private key is missing, wrong, corrupt, or rejected by
strict-PQ policy. A master-only payload still requires its matching
private key. Enabling `useMaster` adds a recovery path; it does not
replace or weaken a password wrap that is present.

Set `BASEFWX_PQ_STRICT` or `BASEFWX_PQ_ONLY` to `1`, `true`, `yes`, or
`on` (case-insensitive) to enable strict mode. The same true spellings
are accepted where the touched KDF/performance paths use Java
`Constants.envEnabled` or Python `_env_enabled`. Legacy flags with
exact-`1` contracts retain their existing semantics.

> [!NOTE]
> `liboqs` is a **C++-only** build dependency. Java and Python do
> **not** need liboqs installed on the host. Releases of the C++ CLI
> and library that lack PQ support are rejected by CI; PQ is not an
> optional feature in published builds — it is simply not engaged
> until a master public key is configured.

### Compatibility policy

* **3.3 vs earlier:** **Not cross‑compatible.** PQE changes keys, formats, and wire expectations. Do not mix nodes or data stores across the boundary.
* **2.9 ↔ 2.8:** **"Maybe compatible"** for basic operations. Advanced features (new cipher modes, headers, or metadata) may break interoperability. Test explicitly.
* **≤ 2.7:** Treat as incompatible and unsupported.
* **< 2.6:** Cryptographically weak — treat historical data as compromised. Assume adversary can recover large portions of plaintext.

### Maintenance policy

* **A released version is final.** Once 3.6.4 (or any version) is
  published, that artifact is **frozen**. We do not ship 3.6.4.1,
  3.6.4-hotfix, or a re-built 3.6.4 with the same version string.
* **"Maintenance" means: install the next release.** When a security
  issue, bug, or compatibility problem is found in 3.6.4, the fix
  lands in 3.6.5 (or 3.7.0, etc.) — *that* is the maintenance event.
  There is no parallel patch track.
* **Older releases are not back-ported to or re-published.** No
  security patches, no bug fixes, no compatibility fixes are issued
  against a release after it has been superseded.
* **No LTS / no multi-version support track.** This is a cryptography
  tool. Always upgrade to the current latest release rather than
  pinning to an older one and waiting for a patch.

### Migration guidance

* Always migrate to the **current latest release** as soon as it is available.
* From **N-1 or older** → **latest**: plan a one-way migration, re-test interoperability, and re-encrypt sensitive archives when format/KDF behavior changed.
* From **< 2.6**: treat as potentially breached; rotate credentials, invalidate legacy ciphertext at rest, and perform a clean re‑ingest under the latest release.

### Plugin security model (3.7.0+)

3.7.0 introduces the blackbox plugin ABI (`cpp/include/basefwx/plugin.h`).
A plugin is an opt-in transform that can sit before, after, or
instead of the AEAD layer. The full threat model is documented in
[examples/plugins/THREAT_MODEL.md](./examples/plugins/THREAT_MODEL.md);
the policy points that matter for security reports:

* **Open-source crypto, keyed plugins.** The crypto core is public.
  An attacker can extract a closed-source `.so` from a host binary
  via debugger, `objdump`, or `strings`. Treat the plugin code as
  public from day one. The security mechanism is **keying** —
  `forward_keyed` / `inverse_keyed` with a host-derived secret — not
  hiding the plugin source. Static embedding raises extraction cost
  but is not a cryptographic primitive.

* **Raw mode is opt-in and gated by capability.** The host refuses
  `BASEFWX_PLUGIN_POS_RAW` for any plugin that does not declare
  `BASEFWX_PLUGIN_CAP_SAFE_RAW_MODE` in `capabilities()`. The
  refusal is structural; there is no flag to disable it. A
  deterministic plugin used in raw mode is a substitution cipher,
  not encryption.

* **`host_secret` / tweak CAP bits (documented contract, host wiring incomplete).**
  The ABI and Profile B examples declare `CAP_REQUIRES_HOST_KEY` /
  `CAP_REQUIRES_TWEAK`, and helper macros can fail closed when those
  lengths are zero. The **production fwxAES/CLI host loader today
  only dispatches unkeyed `forward`/`inverse`** and enforces
  `CAP_SAFE_RAW_MODE` for `POS_RAW`. Until the host threads
  `host_secret` / `tweak` through `TransformForward`/`TransformInverse`,
  do not treat keyed CAP enforcement as a shipped host guarantee —
  see `examples/plugins/THREAT_MODEL.md`.

* **Plugin scope of this document.** Vulnerabilities **in the ABI
  contract** (e.g. host accepts a plugin without checking
  capabilities, plugin can write past `out_cap`, registry can
  resolve a wrong ID) are in scope. Vulnerabilities **in
  third-party plugins** are out of scope — report those to the
  plugin's maintainer. Examples shipped under `examples/plugins/`
  ARE in scope.

* **What we do not promise.** No defense against TM-5 (live
  debugger / memory read on the host process). Use OS-level
  isolation, secure enclaves, or hardware-backed key storage for
  that layer.

### Crypto helper boundaries

One-shot AEAD, HKDF, PBKDF2, Argon2id, HMAC, and random generation
belong in the shared crypto helpers:

* C++: `basefwx::crypto::*` in `cpp/include/basefwx/crypto.hpp`
  (implementation in `cpp/src/crypto/crypto.cpp`).
* Java: `com.fixcraft.basefwx.Crypto` (and the internal
  `CryptoBackend` / `JavaCryptoBackend` / `NativeCryptoBackend`
  dispatch used only by that helper).

**Streaming exception (intentional):** large-file / media pipelines
reuse OpenSSL `EVP_*` (C++) or JCA `Cipher` (Java) directly for
chunked GCM/CTR so they can avoid buffering whole payloads. Those
call sites must still use the same algorithms, nonce/tag lengths,
and AAD labels as the helpers (`kAeadNonceLen` / `AEAD_NONCE_LEN` =
12, `kAeadTagLen` / `AEAD_TAG_LEN` = 16). New one-shot crypto must
not invent a parallel `EVP_*` / `Cipher.getInstance` path outside
the helpers.

**Caller-supplied nonces are the caller's obligation.** The
explicit-nonce forms — `AesGcmEncryptWithIv` and, since 3.8.0-dev1,
`ChaCha20Poly1305EncryptWithIv` — do not and cannot check nonce
uniqueness, because they see one call at a time. Reusing a nonce under
the same key is catastrophic for both constructions, and in both cases
the damage exceeds confidentiality: two messages under one key/nonce
pair leak the XOR of their plaintexts, and the repeated authenticator
input additionally permits recovery of the authentication key —
the Poly1305 one-time key for ChaCha20-Poly1305, and `H` via the
Joux "forbidden attack" for AES-GCM — which yields forgeries. Neither
construction degrades gracefully; treat nonce reuse as a full break of
both secrecy and integrity.

Randomness is not by itself proof of uniqueness. A 12-byte nonce drawn
from `RandomBytes(kAeadNonceLen)` collides with birthday probability
roughly `q^2 / 2^97` after `q` messages under one key, so the usual
ceiling is **2^32 encryptions per key** (NIST SP 800-38D §8.3 imposes
exactly this limit for random GCM IVs; the same arithmetic governs
ChaCha20-Poly1305). A deterministic counter that provably never repeats
for the lifetime of the key is stronger where the caller can persist
one. Either way the obligation is the caller's: budget the number of
messages per key, and rotate the key before the budget is spent rather
than after. Prefer the nonce-generating `AesGcmEncrypt` unless an
established stored format forces the explicit form.

`ChaCha20Poly1305DecryptWithIvOwned` stages decrypted bytes in
`SecureBytes` and returns them only after the Poly1305 tag verifies, so
a failed authentication publishes no attacker-influenced plaintext to
the caller. It is C++ only; see COMPATIBILITY.md for why no Java or
Python parity is claimed.

Password inputs on the Java public API still arrive as `String` in
several entry points (historical). Prefer `byte[]` / `char[]` for
new APIs; wipe `byte[]` password buffers after use. `String`
passwords cannot be wiped — treat that as a known limitation of
the legacy surface, not a reason to add more `String` password APIs.

**Minimum password length:** encryption entry points reject
passwords shorter than 10 UTF-8 bytes
(`kMinimumPasswordLength` / `MINIMUM_PASSWORD_LENGTH` /
`basefwx.MINIMUM_PASSWORD_LENGTH`). The check is enforced by
`RequireStrongPasswordForEncryption` (C++
`cpp/src/formats/basefwx.cpp`), `PasswordPolicy.requireStrongPassword`
(Java), and `_require_strong_password_for_encryption` (Python
`python/basefwx/crypto/_kdf.py`), and applies on **encrypt only** —
decrypt never rejects a short password, so existing blobs stay
readable. Two deliberate carve-outs:

* An **empty** password is exempt. Master-key-only encryption passes
  `""` and is gated separately by the master-key checks; the length
  floor would otherwise make that mode unreachable.
* Testing builds bypass the floor when a test KDF override is active
  (`BASEFWX_TESTING=1` plus `BASEFWX_TEST_KDF_ITERS` in Python/Java, a
  `BASEFWX_TESTING` compile-time build in C++).

Overrides, honored identically in all three runtimes:

* `BASEFWX_ALLOW_WEAK_PASSWORD=1` (also `true` / `yes` / `on`) skips
  the check entirely.
* `BASEFWX_MIN_PASSWORD_LEN=<n>` replaces the floor; `0` disables it.
  Negative and unparseable values are ignored and the 10-byte default
  stands.

Neither override changes anything on the wire — the floor is a local
authoring policy, not a format constraint, so a blob written with a
short password is indistinguishable from any other and decrypts
normally on runtimes that did not set the override.

**Short-password KDF step-up (load-bearing, not on the wire):**
independently of the floor above, passwords shorter than 12 UTF-8
bytes (`kShortPasswordMin` / `SHORT_PASSWORD_MIN`) are hardened at
derivation time: PBKDF2 iterations are raised to at least 1,000,000
and Argon2id costs to at least t=5 / m=128 MiB / p=4. This is a
`max()` against the caller's parameters, never a reduction
(`HardenKdfOptions` in C++ `cpp/src/crypto/keywrap.cpp`,
`FileCodecKdf.hardenArgon2Params` in Java,
`_harden_kdf_params` in Python `python/basefwx/crypto/_kdf.py`).

The stepped-up costs are **not** recorded in metadata. An AES-LIGHT
blob written with a short password carries no `ENC-ARGON2-*` fields
at all; decrypt re-derives the same costs by applying the identical
step-up rule to the password the caller supplied. Round-tripping
therefore depends on encrypt and decrypt agreeing on these constants
by construction rather than by negotiation.

That makes the step-up constants part of the compatibility contract
even though they never appear on the wire:

> Changing `SHORT_PASSWORD_MIN`, `SHORT_PBKDF2_ITERATIONS`, or any
> `SHORT_ARGON2_*` value in **any** runtime silently makes every
> existing short-password blob undecryptable everywhere. The failure
> surfaces as an AEAD tag mismatch — reported as *"incorrect password
> or tampering"* — so it is indistinguishable from a genuinely wrong
> password and will not be recognised as a regression.

Treat these five constants as frozen. A future profile change has to
be negotiated on the wire (a new `ENC-KDF`-style label or an explicit
`ENC-ARGON2-*` record written by the encoder), not applied by editing
the constants.

All three runtimes pin the literal values, so an edit fails a test
rather than shipping quietly:

* Python: `test_short_password_stepup_constants_are_frozen` in
  `python/tests/test_password_policy.py`, alongside two tests that
  capture the mechanism (short-password blobs carry no `ENC-ARGON2-*`)
  and the failure mode (a bumped constant makes an existing blob
  report *"incorrect password"*).
* C++: the profile check in `cpp/tools/peer_kdf_policy_test.cpp`.
* Java: `shortPasswordStepUpProfileIsFrozenAndApplied` in
  `SecurityPolicyTest`.

C++ hardens parallelism against its own `kShortArgon2Parallelism`
rather than `DefaultArgon2Parallelism()`, so retuning the general
`kArgon2Parallelism` default cannot silently drift the short-password
profile away from Java and Python.

**Peer Argon2 costs:** decrypt paths that honor `ENC-ARGON2-TC` /
`ENC-ARGON2-MEM` / `ENC-ARGON2-PAR` from blob metadata fail closed
when values exceed the shared maxima
(`kArgon2TimeCostMax=16`, `kArgon2MemoryCostMax=1<<18` KiB,
`kArgon2ParallelismMax=16` and Java/Python mirrors).

**Peer PBKDF2 costs:** C++, Java, and Python accept peer-controlled
PBKDF2 iteration counts only in the inclusive range `1..4_000_000`.
This applies to `ENC-KDF-ITER` metadata and the unsigned iteration
fields in raw/streaming fwxAES and live headers. Decimal metadata is
parsed strictly: signs, trailing characters, overflow, zero, and
values above the ceiling fail before any KDF work. The ceiling is
twice the shared 2,000,000-iteration heavy writer profile, is aligned
with YUME's protocol-side ceiling, and bounds unauthenticated CPU
amplification without changing the writer default.

### Native image decode bounds

The C++ image paths treat encoded media as untrusted input. The jMG image
decoder rejects encoded inputs above 256 MiB, decoded images above 512 MiB,
or either dimension above 32768 pixels. The kFM PNG carrier path permits its
documented 1 GiB payload ceiling plus framing overhead, but applies the same
checked dimension multiplication before processing pixels. These checks live
outside the vendored `stb_image` source so upstream updates remain auditable.

---

## Reporting a Vulnerability

Please **report privately**. Do **not** open a public issue for security bugs.

### Preferred: GitHub Security Advisory

1. Go to the repository → **Security** → **Report a vulnerability**.
2. Provide:

   * Clear description and **affected versions**.
   * **Impact** (confidentiality/integrity/availability).
   * **Reproduction steps** or a minimal PoC.
   * Any **temporary mitigations** or fix ideas.
3. Attach a minimal private repro (patch/gist/archive). Avoid sensitive data.

### If GH Advisory is unavailable

* Share a private repro link after contacting maintainers via the advisory; a private email/alternate channel will be provided there.

### Triage & Disclosure Policy (SLA)

* **Acknowledgement:** within **48 hours**.
* **Triage & severity rating:** within **5 business days**.
* **Remediation targets — delivered as a *new release*, never as a patch to the affected version:** Critical/High ≤ **14 days**, Medium ≤ **30 days**, Low/Info in the next planned release. The fix ships as 3.6.5 / 3.7.0 / etc.; the vulnerable release stays frozen.
* We follow **coordinated disclosure**: publish details after a fix/mitigation is available **in a new release** and users have a reasonable update window. Researcher credit is opt‑in (anonymous supported).

### Scope

* In scope: crypto/KDF issues, key leakage, integrity/confidentiality breaks, RCE, auth bypass, privilege escalation, significant DoS, secrets exposure.
* Out of scope: typos, cosmetic UI, debug logs without sensitive data.

### Safe Harbor

Good‑faith research under this policy will not be pursued legally by maintainers. Do not exploit beyond what is needed to demonstrate impact and obey applicable laws.
