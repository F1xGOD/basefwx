# Security Policy

## Supported Versions

**Versioning note:** Current releases use `MAJOR.MINOR.PATCH` (e.g., `3.6.4`).

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

### What's New in 3.6.4

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
| Python  | **Argon2id** if `argon2-cffi` is importable **and** the host has ≥ 128 MiB free RAM; otherwise PBKDF2-HMAC-SHA256. |
| Java    | **PBKDF2-HMAC-SHA256** (the Java KeyWrap path intentionally rejects Argon2 — see `KeyWrap.java`). |

`BASEFWX_USER_KDF` overrides the default per process (`argon2id` /
`pbkdf2` / `auto`). When Argon2 is available, blobs interop across
runtimes — the KDF label is encoded in the wrap header so a Python
blob with Argon2 will be decoded by C++/Python and rejected with a
clear error by Java.

**This password-only default is already post-quantum-resistant.** AES-256
under Grover is ≈ 128-bit-equivalent, the KDF salt is per-blob, and
the hardened iteration counts make offline brute force expensive even
under a quantum speedup of the inner hash. ML-KEM-768 is **not**
mixed in here, because in a password-only setting it would not add
security — every PQ private key would itself have to be unwrapped
from the password, so cracking the password breaks every layer.

#### Optional: ML-KEM-768 master-key wrap (off by default)

When (and only when) the caller explicitly opts in
(`useMaster=true` in any API call, `--with-master` on the C++ CLI,
or the Java builder method), basefwx adds an ML-KEM-768 wrap on top
of the password wrap. The mask key is encapsulated to a master
public key, and the user blob still holds the password-encrypted
copy — either path can decrypt independently. **All three runtimes
ship post-quantum support out of the box** — they just use different
backing libraries:

| Runtime | ML-KEM-768 implementation         | Build requirement                                                                                  |
| ------- | --------------------------------- | -------------------------------------------------------------------------------------------------- |
| C++     | **liboqs** (Open Quantum Safe)    | Linked at build time; release builds enforce this via `BASEFWX_REQUIRE_OQS=ON` (no silent downgrade). |
| Java    | **BouncyCastle PQC** (Kyber-768)  | Bundled in the published JAR; no extra system package required.                                    |
| Python  | **`pqcrypto.kem.ml_kem_768`**     | Pulled in by the `basefwx` Python wheel.                                                           |

Sources for the master public key, in priority order:

1. **Caller-provided** via `BASEFWX_MASTER_PQ_PUB=<path-or-base64>` —
   this is the recommended path for self-hosted / open-source
   deployments. You generate your own ML-KEM-768 keypair, keep the
   private key offline, and configure the public half via env or your
   own key-management tooling.
2. **Baked-in fallback** — only used if
   `BASEFWX_MASTER_PQ_ALLOW_BAKED=1` is set explicitly. This points
   to a key whose private half is held by the original maintainers
   (recovery escrow). Off by default precisely so a self-hosted
   deployment never silently encrypts to a third-party key.
3. **None** — without either of the above, `useMaster=true` falls
   back to the password-only path (above) or, if
   `BASEFWX_PQ_STRICT=1` / `BASEFWX_PQ_ONLY=1` is set, fails cleanly
   instead of falling back.

Decryption with master-key blobs always succeeds with the password
alone; the master private key only matters for password-loss
recovery. There is no scenario where enabling `useMaster` makes the
password path weaker — it adds an *additional* path, never a
replacement.

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

* **`host_secret` is mandatory when claimed.** The host fails the
  call closed if a plugin sets `CAP_REQUIRES_HOST_KEY` and the
  host passes `host_secret_len == 0`. Same for `CAP_REQUIRES_TWEAK`.

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
