---
layout: doc
title: Security Model
---

# Security Model

## Overview

BASEFWX is built around authenticated encryption with optional post-quantum master key wrapping.

- Payload protection: AES-256-GCM (12-byte nonce, 16-byte tag)
- Master wrapping: ML-KEM-768 shared secret -> HKDF-SHA256
- Password KDF: Argon2id when available, PBKDF2 fallback

## Key Paths

Two independent unlock paths are supported:

1) Password-based key derivation.
2) Master key recovery (opt-in) using ML-KEM-768 or EC fallback.

If master wrapping is disabled, a password is required. If master wrapping is enabled and a public key is supplied, you can decrypt with the master private key even when the password is empty.

## Metadata

- File metadata inside the payload can be stripped with `--strip`.
- Media metadata (jMG) is removed by default; use `--keep-meta` to preserve and encrypt it.
- OS filesystem timestamps are not altered by default.

## Obfuscation

BASEFWX includes a size-preserving obfuscation layer before AEAD.
It is deterministic and reversible, designed to remove obvious plaintext structure.
It is not a substitute for encryption.

## Legacy CBC

Legacy AES-CBC decrypt is available only when `ALLOW_CBC_DECRYPT=1` is set.
This is intended for migration of old payloads to AEAD formats.

## Operational Notes

- Protect master private keys offline. If the private key is lost, master recovery is impossible.
- For best security, use Argon2id with a strong passphrase.
- If you use `--strip`, master wrapping is disabled to avoid metadata hints.
