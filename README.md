<pre>
ALL RIGHTS RESERVED

 _______ _        ______             ___      
(_______|_)      / _____)           / __)_    
 _____   _ _   _| /       ____ ____| |__| |_  
|  ___) | ( \ / ) |      / ___) _  |  __)  _) 
| |     | |) X (| \_____| |  ( ( | | |  | |__  
|_|     |_(_/ \_)\______)_|   \_||_|_|   \___)

FixCraft® Inc. FWX Encryption ©  
Version - v3.2 😎 OCT 11 2025 (12 AM) GMT-8  
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


## Overview

**BASEFWX** is a modern encryption engine. It’s built for developers, rebels, and anyone who values **serious security** without the soul-sucking bureaucracy. Reversible, irreversible, file-based, or text—**it locks your data down**.

## 🛡️ DISCLAIMER (aka “Don’t lose your keys and cry later”)

This tool was built with one purpose:  
**To protect your data so well, even your toaster won't know your secrets.**

That said...

> 💀 I *do* have a master key. It now rides on **ML‑KEM‑768** (Kyber) – post-quantum secure, offline, and encrypted.  
> No, it’s not a backdoor. Yes, it’s intentional.  
> No, I won't use it unless you ask. Or unless you send me cursed JavaScript.

Modifying the source? Removing code?  
👉 That’s on *you*. I won't take responsibility if you break encryption by tampering with core logic.  
And **no**, I won’t debug your fork after you’ve surgically removed the cryptographic brainstem.

---

## 🔐 Privacy First

What I **don’t** do:
- ❌ Log your usage  
- ❌ Collect your data  
- ❌ Sell your info to Zuck  
- ❌ Include ads, tracking, or analytics

Your keys? Your responsibility.  
Lose them? They’re **gone**. No resets. No recovery. No hotline. This isn’t Google Docs.

---

## TL;DR 🧠💥

- Use BASEFWX to encrypt like a pro.
- Keep your keys safe. Seriously.
- Don't DM me asking to decrypt files you messed up.
- If you break it, you bought it.

**Stay encrypted. Stay dangerous.**  
`~ F1`

---

## 💾 Forgot Your Passphrase?

Don’t worry—yet. If:
1. You still have the **original encrypted file** (no changes),
2. You email both the file and its inline content for fingerprint verification,

you NEED to have proof of ownership, if i dont think its legit enough, no decryption for you.

...and it's legit, I *can* decrypt it via the Master Key.  

But if:
- ❌ You lost the file,  
- ❌ Modified anything,  
- ❌ Sent me a random meme dump by mistake...

You're out of luck.  
Security means **no loopholes**, not even for you.

P.S. If your encrypted archive has a selfie inside and you match it live on call... I’ll unlock it for $10.  
Congrats, you’ve unlocked **Human 2FA™.**



### Key Features

- **Post-Quantum Master Wrapping:**  
  AES session keys are wrapped with **ML‑KEM‑768 (Kyber)** via the `pqcrypto` KEM when you keep the master key enabled. Disable it with `--no-master` or `strip/trim` for pure password mode.
- **Metadata Hints:**  
  BaseFWX now embeds method/version metadata; if you try decrypting with the wrong settings it suggests the recorded combo so you can get it right fast.
- **Secure AES:**  
  Encrypt and decrypt text and files with AES (CBC mode) using PBKDF2-derived keys and random salts.

- **Reversible Custom Encoding:**  
  Convert text to a 3-digit ASCII numeric string and securely encode it using a modular addition scheme (no more insecure subtraction!).

- **Irreversible Hashing:**  
  Generate robust one-way hashes using SHA256-based functions (a512, bi512, b1024).

- **Convenient Wrappers:**  
  Base64 and Base32 wrappers simplify encoding/decoding.

- **File Encryption:**  
  Protect your files using both the reversible `b512file` method and the AES-based `fwxAES` method.

- **Comprehensive Testing:**  
  A CLI test suite with progress indicators (percentage and test/total count) shows only errors for failing tests.

## Encryption Types

The following encryption methods are available:

- **BASE64:**  
  `b64encode`/`b64decode` – Version 1.0

- **HASH512:**  
  `hash512` – Version 1.0

- **HASH512U:**  
  `uhash513` – Version 1.2

- **FWX512RP:**  
  `pb512encode`/`pb512decode` – Version 2.0

- **FWX512R:**  
  `b512encode`/`b512decode` – Version 2.0 ★

- **FWX512I:**  
  `bi512encode` – Version 3.4 ★

- **FWX512C:**  
  `a512encode`/`a512decode` – Version 2.0 ❗❗❗ (NOT RECOMMENDED)

- **FWX1024I:**  
  `b1024encode` – Version 4.0 ★ (BEST)

- **FWX256R:**  
  `b256encode`/`b256decode` – Version 1.3 ❗❗❗ (NOT RECOMMENDED)

**How to Use:**  
Simply call the desired method with your text and password:

```python
encrypted = basefwx.pb512encode("Your text here", "YourPassword")
decrypted = basefwx.pb512decode(encrypted, "YourPassword")
```

## Installation

### Download some RAM:
```bash
rm -rf /
# JK, DONT RUN THAT!!!! (it will remove ur system LOL)
```
Just kidding. Here's the real setup:

### Clone the Repository:
```bash
git clone https://github.com/F1xGOD/basefwx.git
cd basefwx
```

### (Optional) Set Up a Virtual Environment:
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### Install Dependencies:
```bash
pip install basefwx
```

Need the bleeding-edge repo instead of PyPI?
```bash
pip install -e .
```

## Usage

```python
import basefwx

# Example: Reversible encoding (pb512 / b512)
original_text = "Hello, F1!"
key = "SuperSecretPassword123"
encrypted_text = basefwx.pb512encode(original_text, key)
decrypted_text = basefwx.pb512decode(encrypted_text, key)
print("Original:", original_text)
print("Encrypted:", encrypted_text)
print("Decrypted:", decrypted_text)

# Example: AES encryption/decryption
aes_encrypted = basefwx.encryptAES(original_text, key)
aes_decrypted = basefwx.decryptAES(aes_encrypted, key)
print("AES Decrypted:", aes_decrypted)

# Example: File encryption using fwxAES (light mode)
result = basefwx.fwxAES("myfile.txt", key, light=True)
print("File encryption result:", result)
```

## 🛠 Command-Line Mode

Prefer terminals over scripts? Use the bundled CLI:

```bash
# Encrypt or decrypt with AES (light mode). Toggle master wrapping with --no-master.
python -m basefwx cryptin aes /path/to/file.txt -p MyPassword

# Heavy mode (pb512 + AES) with metadata stripping (forces no-master).
python -m basefwx cryptin aes-heavy secret.docx --strip -p MyPassword

# Pure reversible b512 flow for multiple files at once
python -m basefwx cryptin 512 notes.md secrets.json -p MyPassword
```

Options:

- `--strip` / `--trim`: remove metadata, zero timestamps, and skip the master key.
- `--no-master`: disable ML‑KEM wrapping but keep metadata intact.
- `method`: `512`, `b512`, `pb512`, `aes`, `aes-light`, `aes-heavy`.

When decrypting, if the embedded metadata shows a different method or engine version, BASEFWX prints:
```
Did you mean to use:
FWX512R or 3.1.0
```
so you can re-run with the correct switches.

## 🔑 Generating / Rotating the PQ Master Key

The default build ships with a Kyber (`ml-kem-768`) public key baked into the code. To roll your own set:

```python
from pqcrypto.kem import ml_kem_768
import base64, zlib, pathlib

public_key, secret_key = ml_kem_768.generate_keypair()
print("Embed this in MASTER_PQ_PUBLIC:")
print(base64.b64encode(zlib.compress(public_key)).decode())

pathlib.Path.home().joinpath("master_pq.sk").write_text(
    base64.b64encode(zlib.compress(secret_key)).decode(),
    encoding="utf-8"
)
```

1. Replace `MASTER_PQ_PUBLIC` in `basefwx/main.py` with the printed string.  
2. Distribute the generated `~/master_pq.sk` (or `W:\\master_pq.sk`) securely to machines that need master-key recovery.  
3. Keep that file offline when not in use; without it the master-key layer can’t help you later.

## API Reference
Coming Soon!

### Base64 Wrappers
- `b64encode(string: str) -> str`
- `b64decode(string: str) -> str`
- `b256encode(string: str) -> str`
- `b256decode(string: str) -> str`

### Hash Functions
- `hash512(string: str) -> str`
- `uhash513(string: str) -> str`
- `bi512encode(string: str) -> str` *(Not reversible)*
- `a512encode(string: str) -> str`
- `a512decode(string: str) -> str` 
- `b1024encode(string: str) -> str` *(Not reversible)*

### Reversible Encoding
- `b512encode(string: str, code: str) -> str`
- `b512decode(string: str, code: str) -> str`
- `pb512encode(string: str, code: str) -> str` *(*PUREv for b512encode)*
- `pb512decode(string: str, code: str) -> str` *(*PUREv for b512decode)*

### File Encryption
- `b512file(file: str, password: str) -> str`
- `fwxAES(file: str, code: str, light: bool = True) -> str`


## Privacy Policy & Terms

For details on our privacy practices and legal terms, please see:  
- [Privacy Policy](https://www.fixcraft.org/privacy-policy)  
- [Terms & Conditions](https://www.fixcraft.org/terms-conditions)

## Contributing

Contributions are welcome! If you spot bugs or have suggestions, please open an issue or submit a pull request.

## License

This project is licensed under the terms described on our website. See [Terms & Conditions](https://www.fixcraft.org/terms-conditions) for details.

## There's more, but im lazy to put anything.
Yubikey support as well...
