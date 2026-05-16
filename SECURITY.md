# Security Policy

## Supported Versions

**Versioning note:** Current releases use `MAJOR.MINOR.PATCH` (e.g., `3.6.4`).

> [!CAUTION]
> DO NOT USE ANY VERSION BELOW 2.6, you -> WILL <- get compromised!

> [!NOTE]
> BaseFWX follows a **single-version support policy**:
> only the **latest published version** is maintained.
> When a newer version is released, all older versions immediately become unsupported.

|  Version  | Status / Notes                                                                                                                    | Supported |
| :-------: | --------------------------------------------------------------------------------------------------------------------------------- | :-------: |
| **Latest release only** | 👑 Actively maintained. Receives all fixes: security, bugs, and compatibility. | ✅ |
| **All older releases** | ❌ End-of-life immediately after a newer release ships. No support, no bug fixes, no security patches. | ❌ |

### What's New in 3.6.4

* **KDF Hardening (cross-language):** Default PBKDF2 and Argon2id cost
  parameters were raised in all three runtimes (C++, Java, Python) so a
  single password guess is roughly **2–3× more expensive** for an
  attacker than under 3.6.3. See the [KDF Hardening](#kdf-hardening-364)
  table below for exact numbers and the attacker-cost ratios.
* **AN7/DEAN7 Added:** New reversible stealth anonymization layer is now available in C++, Python, and Java.
* **Release Metadata Unified:** C++, Python, and Java now read the same repository version and expose consistent build metadata.
* **Full Crypto Support Enforced:** Release and CI workflows now fail instead of silently downgrading when Argon2/OQS/LZMA support is missing.
* **CLI Improvements:** C++ CLI now has stricter master-key opt-in, richer version/build reporting, and better release metadata visibility.
* **Release Hygiene Tightened:** Canonical asset naming, manifest generation, version-sync checks, and redundant workflow work were cleaned up.
* **Java Build Fixes:** Java CLI/version packaging regressions were fixed so release and CI builds stay green.
* **Java AES-GCM via JNI:** When `-Dbasefwx.useJNI=true` (or
  `BASEFWX_NATIVE=1`) is set and the `basefwxcrypto` shared library is
  available, fwxAES encrypt/decrypt now dispatches the AEAD step
  through a zero-copy one-shot OpenSSL path instead of JCA. This is a
  pure-performance change (no security impact) and yields roughly
  **+10 %** throughput on 16 MiB fwxAES encrypt in our local
  measurements.

#### KDF Hardening (3.6.4)

The brute-force resistance of a password-based KDF is measured by the
total work an attacker must perform per guess. For PBKDF2 that's the
iteration count; for Argon2id it is `time_cost × memory_cost`.
3.6.4 raises every default tier:

| Parameter                  | 3.6.3            | 3.6.4            | Attacker cost ratio |
| -------------------------- | ---------------- | ---------------- | :-----------------: |
| `USER_KDF_ITERATIONS`      | 200 000          | **600 000**      | **3.00×** (+200 %)  |
| `FWXAES_PBKDF2_ITERS`      | 200 000          | **600 000**      | **3.00×** (+200 %)  |
| `SHORT_PBKDF2_ITERATIONS`  | 400 000          | **1 000 000**    | 2.50× (+150 %)      |
| `HEAVY_PBKDF2_ITERATIONS`  | 1 000 000        | **2 000 000**    | 2.00× (+100 %)      |
| Argon2id default `t / m`   | 3 / 2¹⁵ (32 MiB) | **4 / 2¹⁶** (64 MiB) | **2.67×** (+167 %) |
| `SHORT_ARGON2  t / m`      | 4 / 2¹⁶          | **5 / 2¹⁷** (128 MiB) | 2.50× (+150 %) |
| `HEAVY_ARGON2  t / m`      | 5 / 2¹⁷          | **6 / 2¹⁸** (256 MiB) | 2.40× (+140 %) |

In log₂ terms that is roughly **+1.4 bits of additional brute-force
resistance** on the default fwxAES path (above an already strong
baseline); offline GPU/ASIC password cracking against a 3.6.4 blob
costs 3× as much per guess as against a 3.6.3 blob, and roughly the
same factor against the wrap KDF used by master-key flows.

**Backwards compatibility:** The selected iteration count (PBKDF2) and
Argon2 parameters are encoded inline in every fwxAES / b512 / pb512
blob. Existing 3.6.3-era blobs continue to decrypt at their original
(lower) cost; only newly produced blobs use the hardened defaults.
Re-encrypting sensitive archives under 3.6.4 is recommended but not
required.

**Configuration:** the defaults can be overridden per-process via
`BASEFWX_USER_KDF_ITERS`, `BASEFWX_FWXAES_PBKDF2_ITERS`, and
`BASEFWX_HEAVY_PBKDF2_ITERS`. The `BASEFWX_TEST_KDF_ITERS` knob, used
by the test/bench harness, still bypasses the short-password and
hardening logic so light-mode benchmarks remain comparable.

#### Default encryption (no master key, no manual configuration)

When you run a `basefwx` encrypt with **no special flags**, what you
actually get is:

1. **AES-256-GCM** for the data step — already considered
   post-quantum-safe (Grover halves the effective key strength, so
   128-bit equivalent against a quantum adversary; symmetric AEAD with
   a 32-byte key is fine).
2. **Argon2id (where available) or PBKDF2-HMAC-SHA256** for the
   password step, at the hardened 3.6.4 cost listed above.
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

* **Only the latest release is supported.**
* A new release immediately replaces the previous one for all support/maintenance.
* Older versions receive **no** maintenance:
  * no security patches
  * no bug fixes
  * no compatibility fixes
* This project is a cryptography tool; there is no multi-version/LTS support track.

### Migration guidance

* Always migrate to the **current latest release** as soon as it is available.
* From **N-1 or older** → **latest**: plan a one-way migration, re-test interoperability, and re-encrypt sensitive archives when format/KDF behavior changed.
* From **< 2.6**: treat as potentially breached; rotate credentials, invalidate legacy ciphertext at rest, and perform a clean re‑ingest under the latest release.

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
* **Remediation targets:** Critical/High ≤ **14 days**, Medium ≤ **30 days**, Low/Info in the next planned release.
* We follow **coordinated disclosure**: publish details after a fix/mitigation is available and users have a reasonable update window. Researcher credit is opt‑in (anonymous supported).

### Scope

* In scope: crypto/KDF issues, key leakage, integrity/confidentiality breaks, RCE, auth bypass, privilege escalation, significant DoS, secrets exposure.
* Out of scope: typos, cosmetic UI, debug logs without sensitive data.

### Safe Harbor

Good‑faith research under this policy will not be pursued legally by maintainers. Do not exploit beyond what is needed to demonstrate impact and obey applicable laws.
