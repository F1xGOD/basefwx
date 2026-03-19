# Security Policy

## Supported Versions

**Versioning note:** Current releases use `MAJOR.MINOR.PATCH` (e.g., `3.6.3`).

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

### What's New in 3.6.3

* **AN7/DEAN7 Added:** New reversible stealth anonymization layer is now available in C++, Python, and Java.
* **Release Metadata Unified:** C++, Python, and Java now read the same repository version and expose consistent build metadata.
* **Full Crypto Support Enforced:** Release and CI workflows now fail instead of silently downgrading when Argon2/OQS/LZMA support is missing.
* **CLI Improvements:** C++ CLI now has stricter master-key opt-in, richer version/build reporting, and better release metadata visibility.
* **Release Hygiene Tightened:** Canonical asset naming, manifest generation, version-sync checks, and redundant workflow work were cleaned up.
* **Java Build Fixes:** Java CLI/version packaging regressions were fixed so release and CI builds stay green.

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
