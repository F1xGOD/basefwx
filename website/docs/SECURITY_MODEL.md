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

Current `b512` and `pb512` text writers emit authenticated payload version 3:
one version byte, a four-byte plaintext length, then a 12-byte nonce,
ciphertext, and a 16-byte AES-256-GCM tag. Distinct b512/pb512 HKDF and AAD
domains bind the visible header and prevent cross-codec substitution.

Text payload version 2 had no authentication tag over the message and was
malleable. It is rejected by default. Use
`BASEFWX_ALLOW_LEGACY_TEXT_V2=1` only to recover trusted old data and re-encrypt
it. New output is canonical standard base64; the historical token-map output
adds no security and is opt-in with `BASEFWX_OBFUSCATE_CODECS=1`.

`b512file` writers also always use their outer AES-256-GCM container. The old
unauthenticated writer mode is retired. Raw historical b512file input is
disabled unless `BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1` is set for a trusted
recovery operation; authentication failures in recognized binary containers
never downgrade into raw parsing.

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

For a post-quantum-only deployment, set `BASEFWX_PQ_STRICT` (or
`BASEFWX_PQ_ONLY`) to `1`, `true`, `yes`, or `on` (case-insensitive).
A requested master-wrap encryption then fails unless ML-KEM is
configured, and EC master recovery is rejected. An intact password
wrap on an existing dual-wrapped payload remains an independent
decrypt path when master recovery is disabled, missing, wrong,
corrupt, or rejected by that policy.
Set `BASEFWX_MASTER_PQ_ALG=ml-kem-1024` (or `BASEFWX_PQ_MAX=1`) to make key generation and default capability reporting use the larger parameter set on C++, Java, or Python. These variables alone never change a file: the provisioned public-key size selects 768 versus 1024 for wrapping and authenticated `ENC-KEM` metadata, while private-key/ciphertext sizes select the algorithm during recovery.

## Metadata

- File metadata inside the payload can be stripped with `--strip`.
- OS filesystem timestamps are not altered by default.

## Obfuscation

BASEFWX includes a size-preserving obfuscation layer before AEAD.
It is deterministic and reversible, designed to remove obvious plaintext structure.
It is not a substitute for encryption.
Current AES payloads derive separate subkeys for AEAD and obfuscation.
Current AES-heavy stream payloads derive the stream obfuscator from the wrapped session secret instead of the user password, so master-only decrypt flows remain viable and key reuse is reduced.

## Retired Media Formats (jMG, kFM, kFA)

As of 3.8.0 these formats are retired. Default C++, Java, and Python artifacts
do not contain their code or commands, so nothing below applies to a default
build. The properties are recorded here because they still govern existing
files, and because reading those files requires a compatibility artifact built
with `BASEFWX_ENABLE_RETIRED_MEDIA=1` at the same BaseFWX version.

Treat these as constraints on old data, not as options for new work. Encrypt
new media with `fwxAES` instead, which gives it the same AEAD guarantees as any
other file.

- Media metadata is removed by default; `--keep-meta` preserves and encrypts it.
- Python jMG defaults to `archive_original=False`, writing a small `JMG1` key
  trailer. Output is smaller, but decrypt may need a media re-encode and is not
  guaranteed byte-identical.
- Python `--archive` or `archive_original=True` writes an exact-restore archive
  trailer (`JMG0`).
- Python no-archive output carries `JMGK` v2 profile metadata (`max`) and still
  decodes legacy `JMGK` v1.
- Video and audio scrambling masks only low-order bits so the file stays
  playable, which leaks structure by design. The no-archive `max` profile
  raises this to full byte and sample transforms to cut residual structure.
- Image encryption without trailers is deterministic and reuses keystream
  material. It stays behind an explicit opt-in
  (`BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION=1`) and should not be used for new
  data.

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
