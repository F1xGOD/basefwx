<pre>
ALL RIGHTS RESERVED

 _______ _        ______             ___      
(_______|_)      / _____)           / __)_    
 _____   _ _   _| /       ____ ____| |__| |_  
|  ___) | ( \ / ) |      / ___) _  |  __)  _) 
| |     | |) X (| \_____| |  ( ( | | |  | |__  
|_|     |_(_/ \_)\______)_|   \_||_|_|   \___)

FixCraft® Inc. FWX Encryption ©  
Version - v3.3.1 😎 OCT 12 2025 (10 PM) GMT-8  
By F1xGOD 💀  
Donate Crypto (Monero):  
48BKksKRWEgixzz1Yec3BH54ybDNCkmmWHLGtXRY42NPJqBowaeD5RTELqgABD1GzBT97pqrjW5PJHsNWzVyQ8zuL6tRBcY
</pre>

[![PyPI version](https://img.shields.io/pypi/v/basefwx)](https://pypi.org/project/basefwx/)
[![Build](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/workflow.yml)](https://github.com/F1xGOD/basefwx/actions)
[![GitHub license](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat)](https://www.fixcraft.org/terms-conditions)  
[![GitHub issues](https://img.shields.io/github/issues/F1xGOD/basefwx?label=Issues)](https://www.fixcraft.org/terms-conditions)  
[![GitHub stars](https://img.shields.io/github/stars/F1xGOD/basefwx)](https://www.fixcraft.org/terms-conditions)  
[![GitHub forks](https://img.shields.io/github/forks/F1xGOD/basefwx)](https://www.fixcraft.org/terms-conditions)  
[![Discord](https://img.shields.io/discord/1130897522051788821?color=7289da&label=Discord&logo=discord&logoColor=ffffff)](https://discord.gg/3eRHYkjgk8)  
[![Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3DF1xGOD%26type%3Dpatrons)](https://patreon.com/F1xGOD)

---

# BASEFWX

**Hybrid post-quantum + AEAD file encryption**, with size-preserving obfuscation and metadata stripping.  
Pipeline: **ML-KEM-768 (Kyber) → HKDF → AES-GCM (AEAD)**, default **Argon2id** KDF, optional master-key recovery (opt-in), and fast C-backed paths.

> TL;DR: ciphertext looks like random data; tamper and it dies; master recovery is only possible when you explicitly enable/maintain that layer.

---

## Why BASEFWX

- **Post-quantum key encapsulation**: session secrets are wrapped with ML-KEM-768, so harvested ciphertexts stay safe against the “record now, decrypt later” threat.
- **AEAD everywhere**: AES-GCM authenticates payload and metadata. Any bit flip results in an authentication failure.
- **Password-hardening by default**: Argon2id is the standard path; PBKDF2 is still available when compatibility requires it.
- **Metadata control**: `--strip-meta` drops internal timestamps/method hints inside the payload.
- **Uniform-looking output**: deterministic XOR/reverse/permutation obfuscation keeps the bytes looking like noise before AEAD.
- **Signals, not noise**: NumPy-backed fast paths keep the O(n) obfuscation lightweight without altering file formats.
- **Audit-friendly legacy mode**: Old CBC payloads decrypt only when you deliberately set an env flag.

---

## Features

- **Hybrid key schedule**: ML-KEM-768 → HKDF(SHA-256, context) → AES-GCM(256).
- **User KDF**: Argon2id by default; switch to PBKDF2 via flag or env if you must.
- **Obfuscation layer**: XOR keystream → reverse bytes → deterministic permutation; adds zero length overhead.
- **Master-key recovery**: opt-in by providing a public key path/env. The baked pubkey only loads when `ALLOW_BAKED_PUB=1`.
- **Heavy mode (b512/pb512)**: internal tokens obfuscated, then the entire blob is AEAD-wrapped by default.
- **Metadata stripping**: optional, disables master wrapping automatically to avoid surprises.
- **Fast paths**: NumPy vectorisation for large buffers (XOR + permutation); symmetric and PQ crypto remain in `cryptography`.
- **Legacy quarantine**: AES-CBC decrypt is guarded by `ALLOW_CBC_DECRYPT=1`; expect loud warnings when you toggle it.

---

## Quick Start

```bash
# Encrypt with password only (light mode) while stripping metadata
python -m basefwx cryptin aes-light secret.bin -p "correct horse battery staple" --strip

# Encrypt with master public key + password
export BASEFWX_MASTER_PQ_PUB=/secure/mlkem768.pub
python -m basefwx cryptin aes-heavy payload.bin -p pass123 --strip

# Decrypt (password only)
python -m basefwx cryptin aes-light secret.bin.fwx -p pass123

# Decrypt master-only payload (ensure MASTER_PQ_SK loader can find the private key)
python -m basefwx cryptin aes-light secret.bin.fwx --no-master -p ""
```

- `--strip` (or `--trim`) removes internal metadata and forces password-only mode.
- File-system timestamps live outside the ciphertext; adjust with OS tools if you need fully sanitised artifacts.

---

## CLI Reference

```text
python -m basefwx cryptin <method> <paths...> [flags]

Methods:
  512 | b512 | pb512         Reversible obfuscation flows
  aes | aes-light            Base64 + AES-GCM fast path
  aes-heavy                  pb512 + AES-GCM bundle
```

Common flags:

- `--password <str|yubikey:label>` – password or YubiKey-derived passphrase
- `--no-master` – disable PQ master wrap (password required)
- `--use-master-pub <path>` – ML-KEM-768 public key path to enable master wrap
- `--strip` / `--strip-meta` – remove internal metadata from payload
- `--no-obf` – disable size-preserving obfuscation (default ON)
- `--heavy` – alias for `aes-heavy`
- `--kdf {argon2id|pbkdf2}` – override user KDF default
- `--pad-size <MiB>` – pad ciphertext up to the target size (MiB)
- `--pad-jitter <bytes>` – add random jitter when padding
- `--password-file <path>` – read password from file (one line)

---

## Configuration

| Variable | Purpose |
| --- | --- |
| `BASEFWX_MASTER_PQ_PUB` | Path to master public key (enables master wrap) |
| `ALLOW_BAKED_PUB=1` | Allow the baked-in public key as a last resort |
| `MASTER_PQ_SK` | Path for master private key loader |
| `BASEFWX_USER_KDF` | Switch user KDF (`argon2id` or `pbkdf2`) |
| `BASEFWX_OBFUSCATE=0` | Disable size-preserving obfuscation |
| `BASEFWX_B512_AEAD=0` | Disable AEAD wrap for b512 file mode |
| `ALLOW_CBC_DECRYPT=1` | Enable legacy CBC decrypt path |

---

## Security Model

- **Confidentiality & integrity**: AES-GCM with random 12-byte nonces, metadata (if present) bound as AAD.
- **Key paths**:
  - Passwords: Argon2id (time/memory hard). PBKDF2 remains for legacy compatibility.
  - Master: ML-KEM-768 generates a shared secret; HKDF derives the AES-GCM key. Keep the private key offline/HSM-backed.
- **Metadata**: `--strip-meta` removes internal hints; OS timestamps must be handled separately.
- **Obfuscation**: deterministic, size-neutral, designed to hide obvious plaintext patterns before AEAD. It is not a substitute for encryption.
- **Post-quantum stance**: Kyber protects session key wrapping against PQ adversaries; AES-256 mitigates Grover’s quadratic speed-up.
- **No magic recovery**: unless you configured and retained the master public/private keys, lost passwords remain lost.

---

## Performance

- C-backed obfuscation fast paths for buffers ≥64 KiB (vectorised XOR) and ≥4 KiB (vectorised permutations).
- AES-GCM and HKDF run via the `cryptography` library (OpenSSL backend).
- File formats and compatibility remain unchanged.
- Consider `--pad-size` and `--pad-jitter` to equalise output sizes in batch workflows.

---

## Examples

```bash
# Master-enabled encryption with metadata strip, heavy mode
export BASEFWX_MASTER_PQ_PUB=/secure/mlkem768.pub
python -m basefwx cryptin aes-heavy secret.png -p @pass.txt --strip

# Decrypt with password only
python -m basefwx cryptin aes-heavy secret.png.fwx -p @pass.txt

# Benchmark without obfuscation
BASEFWX_OBFUSCATE=0 python -m basefwx cryptin aes-light data.bin -p pass out.fwx
```

---

## Compatibility / Legacy

- Legacy AES-CBC decrypt is disabled by default; set `ALLOW_CBC_DECRYPT=1` to re-enable. Expect a clear warning and plan to re-encrypt with AEAD.
- b512/pb512 legacy payloads continue to decode; new writes use AEAD by default.

---

## Testing

What we cover:

- AES light/heavy round trips (password-only, master-only, hybrid)
- Tamper tests on metadata and payload (expect AEAD failure)
- Nonce uniqueness smoke tests
- b512 file AEAD round trip + tamper failure
- Obfuscation invertibility (small & fast-path buffers)

Run locally:

```bash
python -m unittest tests.test_cryptography
# or
pytest -q
```

Ensure `argon2-cffi`, `pqcrypto`, and `numpy` are installed for full coverage.

---

## Threat Model Summary

- **Attacker model**: offline adversary with ciphertext access.
- **Defended against**: brute force (Argon2id), ciphertext tampering (AEAD), future PQ attacks on key wrap (Kyber).
- **Out of scope**: compromised endpoints, keyloggers, RAM scraping during decrypt, supply-chain compromise, or operational mistakes.

---

## Overview (Legacy)

**BASEFWX** is a modern encryption engine. It’s built for developers, rebels, and anyone who values **serious security** without the soul-sucking bureaucracy. Reversible, irreversible, file-based, or text—**it locks your data down**.

## 🛡️ DISCLAIMER (aka “Don’t lose your keys and cry later”)

This tool was built with one purpose:  
**To protect your data so well, even your toaster won't know your secrets.**

Keep your own secrets safe. If you deliberately enable the master-key layer and protect the private key, recovery is possible. If you run password-only mode and lose the password, nobody can help you.

---

## 🔐 Privacy First

No tracking. No analytics. No data collection. Lose your keys and they’re gone. There is no reset hotline.

---

## TL;DR 🧠💥

- Use BASEFWX to encrypt like a pro.
- Keep your keys safe. Seriously.
- Don't DM asking to decrypt files you broke.
- If you break it, you bought it.

**Stay encrypted. Stay dangerous.**  
`~ F1`

---

## 💾 Forgot Your Passphrase?

If master-wrap was enabled and you retained the exact ciphertext, the owner who controls the master private key can recover the file. Otherwise, recovery is not possible. No funny business, no exceptions.

---

## Privacy Policy & Terms

- [Privacy Policy](https://www.fixcraft.org/privacy-policy)  
- [Terms & Conditions](https://www.fixcraft.org/terms-conditions)

---

## Contributing

PRs and audits welcome. File an issue with details or open a PR. For sensitive disclosures, reach out privately.

---

## License

See [Terms & Conditions](https://www.fixcraft.org/terms-conditions).

---

Yubikey support as well...
