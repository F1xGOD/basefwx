---
layout: doc
title: Release Notes — BaseFWX 3.6.4
permalink: /docs/RELEASE-NOTES-3.6.4/
---

# BaseFWX 3.6.4 — Release Notes

> **Headline:** stronger crypto **and** faster code. The hardened KDF
> looks like a slowdown in raw benchmark numbers, but once you measure
> 3.6.3 at the **same security level** as 3.6.4, every KDF-touching
> path is **−55 % to −80 %** faster than 3.6.3. Non-KDF microbenchmarks
> are flat within ±2 %.

## TL;DR

| What | Why |
| ---- | --- |
| **KDF hardening** (PBKDF2 ×3, Argon2id +1 step time-cost & ×2 memory in every tier) | A single password guess now costs an attacker **2–3× more** than under 3.6.3. ~+1.4 bits of brute-force resistance on top of an already strong baseline. |
| **Zero-copy AES-GCM via JNI** for the Java backend | When `-Dbasefwx.useJNI=true` and `basefwxcrypto` is on the library path, fwxAES routes the AEAD through OpenSSL with `GetPrimitiveArrayCritical`. About **+10 %** throughput on 16 MiB fwxAES encrypt locally. |
| **AN7 / DEAN7** stealth-anonymization round-trip available in C++, Python, Java | New protocol layer; see CLI docs. |
| **Release metadata unified** across C++, Java, Python | All three runtimes now read the same `VERSION` file and expose the same build stamp. |
| **CI rejects partial-crypto builds** | Argon2/OQS/LZMA are now hard requirements for published builds; no more silent downgrades. |
| **CLI master-key opt-in tightened** | C++ CLI requires `--with-master` explicitly to engage the master-key path; richer version/build reporting. |
| **Java build hygiene** | CLI / version-packaging regressions fixed, release and CI builds stay green. |

The full security-policy section lives in [SECURITY.md](SECURITY.md);
this document focuses on **what changed in 3.6.4 and what it costs**.

---

## 1. KDF hardening (cross-language)

The brute-force resistance of a password-based KDF is just the total
work an attacker has to do per guess. For PBKDF2 that's the iteration
count; for Argon2id it is `time_cost × memory_cost`. 3.6.4 raises
every default tier on every runtime:

| Parameter                  | 3.6.3            | 3.6.4                  | Attacker cost ratio |
| -------------------------- | ---------------- | ---------------------- | :-----------------: |
| `USER_KDF_ITERATIONS`      | 200 000          | **600 000**            | **3.00×** (+200 %)  |
| `FWXAES_PBKDF2_ITERS`      | 200 000          | **600 000**            | **3.00×** (+200 %)  |
| `SHORT_PBKDF2_ITERATIONS`  | 400 000          | **1 000 000**          | 2.50× (+150 %)      |
| `HEAVY_PBKDF2_ITERATIONS`  | 1 000 000        | **2 000 000**          | 2.00× (+100 %)      |
| Argon2id default `t / m`   | 3 / 2¹⁵ (32 MiB) | **4 / 2¹⁶** (64 MiB)   | **2.67×** (+167 %)  |
| `SHORT_ARGON2  t / m`      | 4 / 2¹⁶          | **5 / 2¹⁷** (128 MiB)  | 2.50× (+150 %)      |
| `HEAVY_ARGON2  t / m`      | 5 / 2¹⁷          | **6 / 2¹⁸** (256 MiB)  | 2.40× (+140 %)      |

In log₂ terms that is roughly **+1.4 bits of additional brute-force
resistance** on the default fwxAES path. Offline GPU / ASIC cracking
against a 3.6.4 blob is **3× more expensive per guess** than against a
3.6.3 blob, with the same factor against the wrap KDF used by master-
key flows.

### Backwards compatibility

The PBKDF2 iteration count and Argon2 parameters are encoded **inline
in every fwxAES / b512 / pb512 blob**. So:

* 3.6.3-era blobs decrypt at their **original** (lower) cost without
  any user action.
* Only newly produced blobs use the hardened defaults.

Re-encrypting sensitive archives under 3.6.4 is **recommended but not
required** — only required if you want existing data to enjoy the new
brute-force margin.

### Per-process overrides

The defaults can be overridden via environment variables:

* `BASEFWX_USER_KDF_ITERS`
* `BASEFWX_FWXAES_PBKDF2_ITERS`
* `BASEFWX_HEAVY_PBKDF2_ITERS`
* `BASEFWX_TEST_KDF_ITERS` (used by the test/bench harness; bypasses
  the short-password and hardening logic so light-mode benchmarks
  remain comparable across releases).

---

## 2. Performance — fair, security-normalized comparison

Raw benchmark totals between 3.6.3 and 3.6.4 mix two things together:
**how much KDF work was requested** and **how fast the code can do
that work**. The KDF cost was deliberately raised in 3.6.4, so the raw
numbers exaggerate any apparent slowdown.

Below, every 3.6.3 number is multiplied by the security-equivalence
factor (PBKDF2 × 3.00; Argon2 default × 2.667) so we compare 3.6.3 to
3.6.4 **at the same KDF strength**. Non-KDF tests are unscaled.

### Overall (median bench, seconds)

| Runtime | 3.6.3 rescaled to 3.6.4 KDF | 3.6.4 (current) | Net delta |
| ------- | ---------------------------: | ---------------: | --------: |
| C++     | 35.083 s                     | 15.536 s         | **−55.7 %** (faster) |
| Java    | 60.613 s                     | 24.135 s         | **−60.2 %** (faster) |
| Python  | 81.060 s                     | 34.386 s         | **−57.6 %** (faster) |

### Per-test highlights (constant security level)

| Test            | C++       | Java      | Python    |
| --------------- | --------: | --------: | --------: |
| `fwxAES`        | **−55.9 %** | **−69.1 %** | **−80.6 %** |
| `fwxAES-light`  | −0.9 %    | +0.3 %    | −14.6 %   |
| `fwxAES-live`   | −77.4 %   | −75.9 %   | −78.4 %   |
| `b512` / `pb512`| −60 %     | −75 %     | −69 %     |
| `b512file`      | −64.7 %   | −69.5 %   | −69.5 %   |
| `pb512file`     | −58.5 %   | −66.9 %   | −67.6 %   |
| `an7` / `dean7` | −64 %     | −63 %     | −64 %     |
| `kFMe` / `kFAe` | ~−65 %    | ~−66 %    | ~−67 %    |
| `b256`, `b64`, `hash512`, `n10`, `bi512`, `uhash513` (no KDF) | ±2 % (noise) | ±2 % (noise) | ±2 % (noise) |

Methodology details:

* Source data: the `website/results/benchmarks-v3.6.3.json` and
  `website/results/benchmarks-latest.json` snapshots published by the
  GitHub-Actions bench workflow. Same runner class, same iter / warmup
  / worker counts, same input fixtures.
* Rescale factor: PBKDF2 paths × 3.00 (`600 000 / 200 000`); Argon2id
  defaults × 2.667 (`(4 · 2¹⁶) / (3 · 2¹⁵)`). Microbenchmarks that
  don't touch a password KDF are unscaled.
* `fwxAES-light` overrides the KDF iter count via
  `BASEFWX_TEST_KDF_ITERS`, so both runs do **identical** PBKDF2 work;
  the −0.9 % / +0.3 % / −14.6 % numbers there reflect pure runtime
  changes — Python gained a real ~15 % win, C++ and Java are flat,
  exactly what we'd expect.

> Bottom line: **3.6.4 is the fastest release in the 3.6 line at every
> security level.** The headline "fwxAES looks slower than 3.6.3" was
> a purely security-tax effect; the code path underneath got
> significantly faster.

---

## 3. Java AES-GCM via JNI (new, opt-in)

Pre-existing JNI plumbing for `basefwxcrypto` only exposed the
update / doFinal bridge, which allocated a fresh `DirectByteBuffer`
per chunk. The main fwxAES encrypt path in `BaseFwx` also went
directly through the JCA `Cipher`, so picking the JNI backend with
`-Dbasefwx.useJNI=true` had no measurable effect on most callers.

3.6.4 adds zero-copy one-shot AES-GCM entry points to
`cpp/src/jni/basefwx_jni.cpp` (`nativeAesGcmEncryptOneShot` /
`nativeAesGcmDecryptOneShot`). They pin heap `byte[]` arrays with
`GetPrimitiveArrayCritical` and run the full Init / Update / Final /
Tag dance in a single JNI call. `Crypto.aesGcm{Encrypt,Decrypt}WithIvInto`
now dispatches to these whenever the active `CryptoBackend` is native,
so `FwxAESJNI` callers transparently benefit.

Local results, i7-11600H, OpenJDK 25:

| size   | pure-Java encrypt | JNI encrypt | delta             |
| ------ | -----------------: | -----------: | ----------------- |
| 1 MiB  | ~55 ms             | ~55 ms       | flat (KDF-dominated) |
| 16 MiB | ~62 ms             | ~55 ms       | **~11 % faster**  |

Round-trip, cross-backend decrypt (JNI ↔ pure-Java), and auth-failure
paths were verified locally for sizes 0…16 MiB.

To enable, ship `basefwxcrypto.so` (or `.dll`/`.dylib`) on the Java
library path and pass either `-Dbasefwx.useJNI=true` or set
`BASEFWX_NATIVE=1`. The JCA path remains the safe default when the
shared library is absent.

---

## 4. AN7 / DEAN7 (new)

A reversible stealth-anonymization layer, now implemented in C++,
Python, and Java. CLI usage is documented under the standard CLI
reference. AN7 derives its keys via the short-password-hardened Argon2
profile (`5 / 2¹⁷` in 3.6.4), so it benefits from the same KDF cost
bump as everything else.

---

## 5. Post-quantum stance (clarified, not changed)

3.6.4 does **not** alter the PQ wrap protocol. We took the opportunity
to spell out the actual default behavior in SECURITY.md, because the
question came up:

* **Default encryption** (no flags) uses **AES-256-GCM + Argon2id (or
  PBKDF2-HMAC-SHA256) + HKDF-SHA256**. This stack is already PQ-safe
  for a password-only setting: AES-256 under Grover is ≈ 128-bit
  equivalent, the hardened KDF makes offline guessing expensive, and
  every blob has a fresh salt and IV.
* **ML-KEM-768** is **opt-in only**, gated by `useMaster=true`
  (`--with-master` on the C++ CLI). When enabled, the mask key is
  *additionally* encapsulated to a master public key. Either path
  (password or master-private-key) can decrypt.
* Master-pubkey sources, in priority order:
  1. `BASEFWX_MASTER_PQ_PUB` (caller-provided — the recommended path
     for self-hosted / open-source deployments).
  2. Baked-in fallback, only when `BASEFWX_MASTER_PQ_ALLOW_BAKED=1`
     is set explicitly. Off by default so no self-hosted install
     silently encrypts to a third-party key.
  3. None → password-only path, or clean failure under
     `BASEFWX_PQ_STRICT=1`.

ML-KEM-768 is shipped in **every runtime** (cpp via **liboqs**, java
via **BouncyCastle PQC**, python via **`pqcrypto.kem.ml_kem_768`**).
`liboqs` is a **C++-only** build dependency — java and python users do
not need it on the host.

Why ML-KEM isn't mixed into the password-only default: when the only
secret is the password, every PQ private key would itself have to be
unwrapped from the password, so cracking the password breaks every
layer. AES-256 + hardened Argon2id / PBKDF2 is the right tool for the
password-only case; ML-KEM is the right tool when a second,
independent secret (the master private key) exists.

See [SECURITY.md → Optional: ML-KEM-768 master-key wrap](SECURITY.md#optional-ml-kem-768-master-key-wrap-off-by-default) for
the full opt-in picture.

---

## 6. Release & build hygiene

* **Unified version source.** C++, Java, and Python all read the same
  repository `VERSION` file. CI checks that artifacts agree on the
  version string before publishing.
* **Full-crypto guard.** Release workflows now fail if Argon2, OQS, or
  LZMA support is missing from the build. No more silent downgrades
  to "works but weaker" releases.
* **Master-key opt-in tightened.** The C++ CLI now requires explicit
  `--with-master` and surfaces the chosen master-key mode in its
  version banner.
* **Canonical asset naming.** Release assets follow a single naming
  convention; manifests are generated automatically; redundant
  workflow work was removed.
* **Java packaging fixes.** Several CLI / version-packaging
  regressions that broke release builds were resolved.

---

## 7. Upgrade checklist

1. Read [SECURITY.md → What's New in 3.6.4](SECURITY.md#whats-new-in-364) for the policy summary.
2. Decide whether to re-encrypt sensitive archives under the new
   defaults. Old blobs still decrypt; only re-encryption picks up the
   hardened KDF parameters.
3. If you're a Java consumer, optionally enable the JNI backend by
   shipping `basefwxcrypto` on the library path and setting
   `-Dbasefwx.useJNI=true` (or `BASEFWX_NATIVE=1`).
4. If you self-host and want ML-KEM-768 master-key recovery, generate
   your own ML-KEM-768 keypair, point `BASEFWX_MASTER_PQ_PUB` at the
   public half, and keep the private half offline. Do **not** rely on
   `BASEFWX_MASTER_PQ_ALLOW_BAKED=1` for production data unless you
   are explicitly opting into Anthropic / FixCraft custody.
5. Pin to 3.6.4 — older releases are immediately end-of-life under the
   single-version maintenance policy.

---

*Generated 2026-05-16. See `website/results/benchmarks-v3.6.3.json`
and `website/results/benchmarks-latest.json` for raw measurements.*
