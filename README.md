<pre>
ALL RIGHTS RESERVED

 _______ _        ______             ___      
(_______|_)      / _____)           / __)_    
 _____   _ _   _| /       ____ ____| |__| |_  
|  ___) | ( \ / ) |      / ___) _  |  __)  _) 
| |     | |) X (| \_____| |  ( ( | | |  | |__  
|_|     |_(_/ \_)\______)_|   \_||_|_|   \___)

FixCraft® Inc. FWX Encryption ©  
Version - v2.7 😎 MAR 22 2025 (11 PM) PST8  
By F1xGOD 💀  
Donate Crypto (Monero):  
48BKksKRWEgixzz1Yec3BH54ybDNCkmmWHLGtXRY42NPJqBowaeD5RTELqgABD1GzBT97pqrjW5PJHsNWzVyQ8zuL6tRBcY
</pre>
[![GitHub license](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat)](https://www.fixcraft.org/terms-conditions)  
[![GitHub issues](https://img.shields.io/github/issues/F1xGOD/basefwx?label=Issues)](https://www.fixcraft.org/terms-conditions)  
[![GitHub stars](https://img.shields.io/github/stars/F1xGOD/basefwx)](https://www.fixcraft.org/terms-conditions)  
[![GitHub forks](https://img.shields.io/github/forks/F1xGOD/basefwx)](https://www.fixcraft.org/terms-conditions)  
[![Discord](https://img.shields.io/discord/1130897522051788821?color=7289da&label=Discord&logo=discord&logoColor=ffffff)](https://discord.gg/3eRHYkjgk8)  
[![Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3DF1xGOD%26type%3Dpatrons)](https://patreon.com/F1xGOD)

## Overview

**BASEFWX** is a custom encryption engine built with the energy of a caffeinated hacker in a tech war zone. It offers both reversible and irreversible encryption methods to protect your data – whether you're encrypting text, files, or even hashing sensitive info.

### Key Features

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
pip install cryptography colorama
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

## API Reference

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

---

Stay caffeinated, keep coding, and blast those bugs away! 🚀🔥