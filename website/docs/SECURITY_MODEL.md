---
layout: doc
title: Security Model
permalink: /docs/SECURITY_MODEL/
---

# Security Model

## Overview

BASEFWX is built around authenticated encryption with optional post-quantum master key wrapping.

- Payload protection: AES-256-GCM (12-byte nonce, 16-byte tag)
- Master wrapping: ML-KEM shared secret -> HKDF-SHA256
- Password KDF: Argon2id when available, PBKDF2 fallback

BASEFWX does not implement a nonstandard "AES-512" primitive. The symmetric layer is AES-256-GCM.

## Version Support Policy

BaseFWX uses a strict single-version maintenance model:

- Only the latest published release is supported.
- When a new release is published, all previous releases are immediately end-of-life.
- Older releases receive no maintenance (no security fixes, no bug fixes, no compatibility updates).

For this project, "upgrade to latest" is a security requirement, not a convenience recommendation.

## Key Paths

Two independent unlock paths are supported:

1) Password-based key derivation.
2) Master key recovery (opt-in) using ML-KEM or EC fallback.

If master wrapping is disabled, a password is required. If master wrapping is enabled and a public key is supplied, you can decrypt with the master private key even when the password is empty.

For a post-quantum-only deployment, set `BASEFWX_PQ_STRICT=1` (or `BASEFWX_PQ_ONLY=1`) to disable the EC fallback path and reject EC master blobs during decrypt.
Set `BASEFWX_MASTER_PQ_ALG=ml-kem-1024` (or `BASEFWX_PQ_MAX=1`) to use the larger ML-KEM parameter set in the C++ core when matching keys are provisioned.

## Metadata

- File metadata inside the payload can be stripped with `--strip`.
- Media metadata (jMG) is removed by default; use `--keep-meta` to preserve and encrypt it.
- Python jMG defaults to `archive_original=False`, writing a tiny `JMG1` key trailer only (smaller output, decrypt may require media re-encode, not guaranteed byte-identical).
- Use Python `--archive` or `archive_original=True` for exact-restore archive trailers (`JMG0`).
- New Python no-archive outputs use `JMGK` v2 profile metadata (`max`) and remain backward-compatible with legacy `JMGK` v1 decode.
- OS filesystem timestamps are not altered by default.

## Obfuscation

BASEFWX includes a size-preserving obfuscation layer before AEAD.
It is deterministic and reversible, designed to remove obvious plaintext structure.
It is not a substitute for encryption.
Current AES payloads derive separate subkeys for AEAD and obfuscation.
Current AES-heavy stream payloads derive the stream obfuscator from the wrapped session secret instead of the user password, so master-only decrypt flows remain viable and key reuse is reduced.
Video/audio scrambling masks only low-order bits to preserve playability and will leak structure.
Python no-archive `max` profile increases masking to full byte/sample transforms to reduce residual structure.
Image encryption without trailers is deterministic and reuses keystream material; only enable it with explicit opt-in (BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION=1).

## Live Stream Framing

Python, Java, and C++ provide a packetized live AEAD stream API (`LiveEncryptor`/`LiveDecryptor` and `fwxAES_live_*` wrappers):

- Each frame is authenticated (AES-GCM) with per-frame nonces derived from a nonce prefix + sequence number.
- AAD binds frame type, sequence number, and plaintext length to prevent structural tampering.
- Sequence monotonicity is enforced; replayed or out-of-order frames are rejected.
- Header key transport supports password PBKDF2 mode or master-wrap mode, matching fwxAES key semantics.
- Python additionally exposes ffmpeg bridge helpers (`fwxAES_live_encrypt_ffmpeg` / `fwxAES_live_decrypt_ffmpeg`) for pipe-based media flows.

Limits:

- v1 framing is transport-agnostic bytes (no built-in jitter buffering, retransmission, or clock sync).
- Stream integrity is frame-level; packet loss/corruption causes local auth failure at affected frames.
- For deterministic cross-language interoperability, all implementations must match the v1 frame format exactly.

## Legacy CBC

Legacy AES-CBC decrypt is available only when `ALLOW_CBC_DECRYPT=1` is set.
This is intended for migration of old payloads to AEAD formats.

## Operational Notes

- Protect master private keys offline. If the private key is lost, master recovery is impossible.
- For best security, use Argon2id with a strong passphrase.
- If you use `--strip`, master wrapping is disabled to avoid metadata hints.
