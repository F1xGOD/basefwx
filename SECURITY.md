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

#### Post-Quantum (ML-KEM-768)

3.6.4 keeps the Kyber/ML-KEM-768 hybrid wrap that was introduced in
the 3.6 line. **All three runtimes ship post-quantum support out of
the box** — they just use different backing libraries:

| Runtime | ML-KEM-768 implementation         | Build requirement                                                                                  |
| ------- | --------------------------------- | -------------------------------------------------------------------------------------------------- |
| C++     | **liboqs** (Open Quantum Safe)    | Linked at build time; release builds enforce this via `BASEFWX_REQUIRE_OQS=ON` (no silent downgrade). |
| Java    | **BouncyCastle PQC** (Kyber-768)  | Bundled in the published JAR; no extra system package required.                                    |
| Python  | **`pqcrypto.kem.ml_kem_768`**     | Pulled in by the `basefwx` Python wheel.                                                           |

The PQ KEM is invoked whenever a master public key is available
(`BASEFWX_MASTER_PQ_PUB`, or the baked-in key with
`BASEFWX_MASTER_PQ_ALLOW_BAKED=1`) and the caller has opted into the
master-key path (`useMaster=true` / `--with-master`). The KDF output
is then HKDF-mixed with the ML-KEM shared secret so an attacker would
need to break **both** the password KDF and ML-KEM-768 to recover the
plaintext.

Strict-PQ-only mode (`BASEFWX_PQ_STRICT=1` or `BASEFWX_PQ_ONLY=1`)
disables the EC fallback entirely; master-key operations then fail
cleanly if no PQ public key is configured rather than silently
falling back to classical ECDH.

> [!NOTE]
> `liboqs` is a **C++-only** build dependency. Java and Python do
> **not** need liboqs installed on the host. Releases of the C++ CLI
> and library that lack PQ support are rejected by CI; PQ is not an
> optional feature in published builds.

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
