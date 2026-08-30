---
layout: doc
title: Security model
permalink: /docs/SECURITY_MODEL/
---

# Security model

BaseFWX writes authenticated containers. Current file and text formats use
AES-256-GCM, and readers verify authentication before publishing plaintext.
The library does not implement a nonstandard “AES-512” cipher. Historical
`aes512` names select a heavier key-derivation profile around AES-256-GCM.

The canonical release and recovery policy is in
[SECURITY.md](https://github.com/F1xGOD/basefwx/blob/main/SECURITY.md). Exact
cross-runtime formats and limits are in
[COMPATIBILITY.md](https://github.com/F1xGOD/basefwx/blob/main/COMPATIBILITY.md).

## Unlock paths

A container can have a password path, a master-recovery path, or both.

The password path derives a wrapping key with Argon2id or PBKDF2. New
encryption enforces the configured password-length policy. A KDF slows guesses,
but it cannot turn a weak or reused password into a high-entropy secret.

The optional master path wraps the same random content key with ML-KEM-768 or
ML-KEM-1024. It is a recovery path, not another encryption pass over the file.
Keep the matching private key separate from ordinary user data.

When both paths are present, either valid path can recover the content key.
Strict-PQ mode refuses EC fallback for master recovery. It does not invalidate
an independent password wrap that already exists in the container.

Upstream artifacts contain no baked master public key. Provision one through
the documented runtime or build input.

## Authentication and failure

The AEAD tag covers the encrypted payload and the format metadata bound as
additional authenticated data. A wrong password, changed header, truncated
body, or changed tag fails decryption.

A recognized current container with a bad tag never falls back to an older,
unauthenticated parser. Callers should keep authentication failure distinct
from an unknown prefix, an unavailable optional backend, and a disabled legacy
format.

Current `b512` and `pb512` text payloads have separate HKDF and AAD domains.
This prevents one codec's authenticated payload from being silently
reinterpreted as the other. `b512file` also writes an authenticated outer
container.

## Metadata and obfuscation

BaseFWX can strip supported file metadata from a container. It does not change
filesystem timestamps by default, hide the fact that a BaseFWX container
exists, or control copies made by the operating system and calling process.

The size-preserving obfuscation layer runs inside the authenticated container.
It can remove obvious plaintext structure, but it adds no cryptographic
protection. Current AES-heavy writers separate the AEAD and obfuscation keys.

## Live streams

The live API emits authenticated, ordered frames. Each frame binds its type,
sequence number, and plaintext length. Receivers reject replay and out-of-order
input.

The format does not retransmit missing data, reorder packets, smooth playback,
or synchronize clocks. A network protocol or media pipeline must provide those
behaviors.

## Legacy recovery

Unauthenticated text payloads, raw historical file input, AES-CBC, and retired
text or media formats are recovery-only. Their switches default off. The
retired code is absent from default artifacts and must be included while
building a compatibility artifact.

Use recovery modes only on trusted old data, isolate the operation, and write
the recovered plaintext into a maintained authenticated format. Do not enable a
legacy switch after authentication failure in a current container.

## Operational boundary

- Protect master private keys offline and keep password files owner-readable.
- Prefer Argon2id when the deployment can meet its recorded memory cost.
- Keep peer-controlled KDF parameters within the decoder caps.
- Do not log passwords, private keys, plaintext, or generated recovery data.
- Upgrade to the latest published release. Older releases do not receive
  security backports.

Report suspected vulnerabilities through the repository's private GitHub
security-reporting path, not a public issue.
