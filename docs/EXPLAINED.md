# BaseFWX explained

BaseFWX turns plaintext into an authenticated container that C++, Python, and
Java can read. Its current formats use standard cryptographic primitives and a
versioned envelope. This page gives the working model without duplicating the
CLI or byte-level reference.

## File encryption

The `fwxAES` path has four steps:

```text
plaintext
   |
   | optional compression and reversible obfuscation
   v
random content key + nonce
   |
   | AES-256-GCM, with format metadata in AAD
   v
ciphertext + authentication tag
   |
   | password wrap and optional ML-KEM master wrap
   v
versioned BaseFWX container
```

AES-GCM encrypts the payload and authenticates the metadata bound to it. A
reader verifies the tag before it publishes plaintext. A wrong password,
changed header, truncated body, or changed tag fails decryption.

Obfuscation runs inside the authenticated container. It can change byte
patterns, but it does not add cryptographic protection and should not be used
without AEAD.

## Unlock paths

A container can have a password path, a master-key path, or both.

The password path derives a wrapping key with Argon2id or PBKDF2. The format
stores the KDF choice and its bounded parameters. Current encryption enforces a
minimum password length unless the caller explicitly changes that policy.

The optional master path uses an ML-KEM public key to wrap the same random
content key. It is a recovery mechanism, not a second encryption pass over the
file. The matching private key should be kept separately from ordinary user
data.

When both paths exist, either valid path can recover the content key. Strict-PQ
mode can reject EC fallback for master recovery. It does not remove an intact,
independent password path from an existing dual-wrapped container.

## Text and file codecs

`b512` and `pb512` are Base64-oriented authenticated formats. Current text
writers include a version, plaintext length, nonce, AES-256-GCM ciphertext,
and tag. Separate HKDF and AAD domains prevent a payload from being silently
reinterpreted as the other codec.

File writers use an authenticated outer container. Current authentication
failures never downgrade into the old raw parser. Legacy input is available
only through a recovery switch for trusted old data.

`n10` converts bytes to decimal text and back. It is useful where only digits
can be carried, but it provides no secrecy or authentication.

## Live streams

The live API emits a header followed by authenticated packets. Each packet
binds its type, sequence number, and plaintext length as AAD. Receivers reject
replay and out-of-order input.

This gives frame-level confidentiality and authentication. It does not resend
lost data, reorder packets, synchronize clocks, or smooth playback. A network
protocol or media pipeline must provide those behaviors.

## Cross-runtime compatibility

Shared containers are a contract across C++, Python, and Java. A format or
security change must update the runtimes and shared known-answer tests in the
same change unless the API is explicitly documented as runtime-specific.

The plugin ABI is different. It is a frozen C boundary with its own version and
wire tag. The general C++ library is still pre-stable and can change at a minor
release. See [ABI.md](../ABI.md) and [COMPATIBILITY.md](../COMPATIBILITY.md).

## Retired formats

The default artifacts exclude the old media carriers and retired text codecs.
Their code exists only in a source-built compatibility profile so existing data
can be recovered. That profile does not make the formats suitable for new
data, and it does not restore performance work or new features for them.

After recovery, write the plaintext into `fwxAES`, authenticated `b512`, or
another maintained format. The compatibility page lists the build switch and
the legacy decode switches.

## Failure model

BaseFWX treats these cases differently:

- An unknown prefix is not automatically a corrupted BaseFWX file.
- A recognized container with a bad tag is an authentication failure.
- A missing optional backend is a capability error.
- A disabled legacy format stays disabled until the caller explicitly enables
  its recovery policy.

Callers should preserve those distinctions. Do not catch an authentication
failure and try a looser parser or unauthenticated mode.

## Use in YUME

YUME pins a specific BaseFWX commit and consumes selected C++ primitives and
storage helpers. YUME owns its network wire format, authentication transcript,
ratchet policy, permissions, and C ABI. A BaseFWX version change does not change
those YUME contracts unless YUME makes and tests that change explicitly.

The required BaseFWX revision is recorded in YUME's
`config/dependencies.json`. The repositories keep separate Git histories and
release boundaries.
