# Security Policy

## Supported Versions

**Versioning note:** Current releases use `MAJOR.MINOR` (e.g., `3.3`). When patch versions appear (e.g., `3.3.1`), interpret each row as the whole patch line (`3.3.x`).

> [!CAUTION]
> DO NOT USE ANY VERSION BELOW 2.6, you -> WILL <- get compromised!

> [!NOTE]
> please upgrade to the latest version timely, this will keep your data safe.

|  Version  | Status / Notes                                                                                                                    | Supported |
| :-------: | --------------------------------------------------------------------------------------------------------------------------------- | :-------: |
| **3.5.x+** | 👑 **USE IT!** Faster, Optimized, Multi-Thread. **Python ↔ C++ cross‑compatible.** Actively maintained. **Not cross‑compatible with earlier lines.** |     ✅     |
| **3.4.x** | ➖ PQE + AEAD + obfuscation fast‑paths. Security maintenance only. **Not cross‑compatible with earlier lines.**             |     ✅     |
| **3.3.1** | ➖ PQE + AEAD + obfuscation fast‑paths. Actively maintained. **Not cross‑compatible with earlier lines.**              |     ✅     |
|  **3.2**  | ➖ Security maintenance (bug & vuln fixes only). PQE format introduced here. **Not cross‑compatible with older lines.**             |     🧪     |
|  **3.1**  | ❌ CodeQL findings; weak key‑derivation (affects this and below). **Not cross‑compatible with 3.2.**                               |     ❌     |
|  **3.0**  | ❌ Unstable; may crash due to code defects. **Not cross‑compatible with 3.2.**                                                     |     ❌     |
|  **2.9**  | ✅ Stable baseline (LTS for non‑PQE users). Security fixes only. **Partial/"maybe" compatibility with 2.8** depending on features. |     ✅     |
|  **2.8**  | ⚠️ "OK" for legacy use. Critical security fixes only, limited window. **Partial/"maybe" compatibility with 2.9.**                 |     ⚠️    |
|  **2.7**  | ❌ "Kinda bad" (known issues), unsupported.                                                                                        |     ❌     |
| **< 2.6** | 💀 **HELL NO** — known weaknesses; ~**90% open book**. Do not use.                                                                |     ❌     |

### Compatibility policy

* **3.3 vs earlier:** **Not cross‑compatible.** PQE changes keys, formats, and wire expectations. Do not mix nodes or data stores across the boundary.
* **2.9 ↔ 2.8:** **"Maybe compatible"** for basic operations. Advanced features (new cipher modes, headers, or metadata) may break interoperability. Test explicitly.
* **≤ 2.7:** Treat as incompatible and unsupported.
* **< 2.6:** Cryptographically weak — treat historical data as compromised. Assume adversary can recover large portions of plaintext.

### Maintenance policy

* **Active:** `3.5.x` (PQE + AEAD + C++ core/CLI) — features + security.
* **Security maintenance:** `3.4.x` and `3.2`.
* **LTS (security‑only):** `2.9`.
* **Critical fixes (short window):** `2.8`.
* **EOL:** `3.1`, `3.0`, `2.7`, and anything **< 2.6**.

### Migration guidance

* From **≤ 3.4** → **3.5.x**: upgrade ASAP, **re‑generate keys** and **re‑encrypt** all stored data. Do **not** attempt mixed clusters.
* From **2.9/2.8** → **3.5.x**: plan a one‑way migration with fresh keys and a full re‑encrypt. Validate exports before cutover. Roll back only with full 2.x snapshots (no forward replay).
* From **< 2.6**: treat as potentially breached; rotate credentials, invalidate legacy ciphertext at rest, and perform a clean re‑ingest under **3.5.x**.

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
