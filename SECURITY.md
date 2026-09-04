# Security policy

## Supported releases

BaseFWX supports the latest published release only. Releases are immutable. A
security or correctness fix ships in a new release, and older releases do not
receive backports or rebuilt artifacts under the same version.

The current checkout version is stored in [VERSION](VERSION). A development
checkout is not a supported release merely because its version is newer.

Users should upgrade when a new release is published. Data created by an
unsupported version should be tested with the latest release and re-encrypted
when its format, KDF policy, or recovery path changed. Treat data from versions
older than 2.6 as potentially compromised.

## Current cryptographic boundary

Maintained containers use AES-256-GCM for payload confidentiality and
authentication. They use HKDF-SHA256 for subkey derivation and Argon2id or
PBKDF2-HMAC-SHA256 for password-based wrapping.

The effective strength of a password container is normally bounded by the
password and KDF cost. A salt prevents precomputation across blobs, but it does
not add entropy to a weak password.

BaseFWX does not implement an “AES-512” primitive. Historical names containing
`aes512` select a heavier password profile around AES-256-GCM.

Obfuscation is reversible preprocessing inside the authenticated container. It
is not encryption and does not replace the AEAD tag.

## Password policy and KDF work

New encryption rejects passwords shorter than 10 UTF-8 bytes. Decryption still
accepts them so old data remains readable. An empty password is allowed only
for an explicitly configured master-only operation.

`BASEFWX_ALLOW_WEAK_PASSWORD=1` disables the authoring check.
`BASEFWX_MIN_PASSWORD_LEN=<n>` changes it, and `0` disables it. These are local
authoring controls and do not change the format.

Passwords shorter than 12 UTF-8 bytes use a frozen compatibility profile:

- PBKDF2 is raised to at least 1,000,000 iterations.
- Argon2id is raised to at least time cost 5, 128 MiB, and parallelism 4.

These values are not recorded in old light-profile metadata, so changing them
would make existing short-password data fail authentication. All runtimes pin
them with tests. A future change needs an explicit format label.

Untrusted KDF parameters are bounded before work begins. Peer PBKDF2 counts
must be in `1..4,000,000`. Peer Argon2id parameters cannot exceed time cost 16,
256 MiB, or parallelism 16. Parse failures, signs, overflow, zero, and values
above the cap fail before the KDF runs.

If an Argon2-labelled operation cannot allocate or initialize its backend, it
fails. It does not silently write or read the payload as PBKDF2. Low-memory
writers can select PBKDF2 before creating metadata with
`BASEFWX_USER_KDF=pbkdf2`.

`BASEFWX_FWXAES_PBKDF2_ITERS=<n>` overrides the direct-PBKDF2 `fwxAES` and
`LIVE` iteration count for the writer. The count is serialized in each header,
so a reader does not need the same setting. Both the writer and the reader
enforce a floor of 10,000 iterations, so this variable can raise the cost but
cannot drive it below the floor. An embedding application that must not let
its environment influence key derivation should pass the KDF options
explicitly at the call site rather than relying on the defaults.

## Payload authentication

Current `b512` and `pb512` text writers use authenticated payload version 3:

```text
0x03 || uint32_be(plaintext_length) || nonce[12] || ciphertext[N] || tag[16]
```

Separate HKDF and AAD domains bind the codec name, version, and plaintext
length. Text payload version 2 did not authenticate the message and is rejected
by default. `BASEFWX_ALLOW_LEGACY_TEXT_V2=1` is only for recovery of trusted
old data.

`b512file` writers always use their authenticated outer container. Raw
historical input is disabled unless
`BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1` is set for a scoped recovery operation.
Authentication failure in a recognized container never falls through to the
raw parser.

Streaming decryptors stage plaintext privately and publish it only after the
final tag and structure checks pass. Writers use sibling staging files so a
failed or interrupted operation does not partly replace the requested output.
Unauthenticated wrap and key headers are capped at 64 KiB, and stream work
buffers are capped before allocation.

How that staging happens depends on what the caller supplied. A
destination-aware entry point such as `DecryptStreamFile` stages into a
private sibling of the destination and publishes by rename, so plaintext is
written straight through. A caller that hands in its own output stream gets no
staging directory to use, so the plaintext is held in wiped memory and written
only after the tag verifies. That hold is bounded by
`kFwxAesMaxUnstagedPlaintext` (256 MiB) and a larger stream is refused with a
pointer to the destination-aware call. Unverified plaintext is never spooled
to a temporary file, so it is never left unwiped on disk and cannot consume
`TMPDIR`.

## Optional master recovery

Master recovery is opt-in. It wraps the random content key with a provisioned
ML-KEM-768 or ML-KEM-1024 public key. The matching private key is a separate
recovery factor and should be kept away from ordinary user data.

Upstream releases contain no maintainer-owned master public key. Configure a
deployment key with `BASEFWX_MASTER_PQ_PUB` or an explicit build-time embed.
The standardized public-key size selects the ML-KEM parameter set and the
authenticated `ENC-KEM` value.

When a password wrap and master wrap are both present, either intact path can
recover the content key. `BASEFWX_PQ_STRICT` or `BASEFWX_PQ_ONLY` refuses EC
master fallback and makes a requested master-wrap encryption fail when no
ML-KEM public key is available. It does not disable an independent valid
password wrap while reading an existing container.

A requested master wrap never degrades to password-only. If a caller asks for
a master key and no master public key is configured, C++, Java, and Python all
refuse the encryption with "master key requested but no master public key is
configured". Degrading silently would write a file that looks escrowed on the
host that wrote it and is unrecoverable once the password is lost.

The wrap header records the KDF label but not its cost, so every decoder
reconstructs the cost from the defaults. Wrap-mode encryption therefore
refuses a non-default PBKDF2 iteration count or Argon2 cost instead of writing
a blob no host could open. Use the PBKDF2 payload mode when a custom cost is
required. Serializing the cost in the wrap header is a format change that has
to land in C++, Java, and Python together.

## Nonces and explicit-IV helpers

Caller-supplied nonces must never repeat under one key. Reuse breaks both
confidentiality and authentication for AES-GCM and ChaCha20-Poly1305.
Explicit-IV APIs cannot enforce uniqueness because they see only one call.

Prefer the nonce-generating AES-GCM API unless an existing format owns nonce
allocation. When random 96-bit nonces are used, rotate the key well before
`2^32` messages. A persisted counter that cannot repeat is stronger when the
caller can own it reliably.

C++ explicit-IV decryptors keep pre-authentication output in wiping storage and
return it only after the tag verifies. The C++ ChaCha20-Poly1305 helper exists
for an established downstream record and is not a BaseFWX cross-runtime format.

## Plugins

Plugins execute in the host process and can see data at their configured
position. Treat plugin code as public and potentially hostile. Static embedding
does not create a cryptographic secret.

Raw mode is accepted only when the plugin declares the safe-raw capability. A
deterministic raw transform is not encryption. The current production host does
not provide the keyed and tweak inputs described by some optional capability
bits, so those bits are not a shipped confidentiality guarantee.

Plugin ABI validation, bounds, capability checks, and bundled examples are in
scope for BaseFWX security reports. Third-party plugin logic belongs to its own
maintainer. A live debugger or memory reader on the host process is outside the
plugin threat boundary.

## Retired-data recovery

Retired text and media codecs are excluded from default artifacts. They can be
built only in the explicit compatibility profile to recover existing data.
That profile receives security, correctness, and decode-compatibility fixes in
the latest release, but no new writers, features, or performance work.

Legacy AES-CBC decrypt (Python runtime only) is also recovery-only and requires
`ALLOW_CBC_DECRYPT=1`. Re-encrypt recovered plaintext with a maintained AEAD
format.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
GitHub Security tab and choose “Report a vulnerability.” Include affected
versions, impact, reproduction steps or a minimal proof of concept, and any
known mitigation. Do not include real user data or production secrets.

Maintainers aim to acknowledge reports within 48 hours and provide an initial
severity assessment within five business days. A fix is delivered as a new
release. Coordinated disclosure happens after a fix or mitigation is available
and users have had a reasonable update window.

Cryptographic breaks, key or plaintext disclosure, authentication bypass, RCE,
privilege escalation, and significant attacker-controlled resource exhaustion
are in scope. Cosmetic issues and logs without sensitive data are not security
reports.

Good-faith research that follows this policy will not be pursued legally by
the maintainers. Test only as far as needed to show the issue and follow the
law that applies to you.
