# Compatibility and system requirements

The checkout version comes from [VERSION](VERSION). This page describes format
and runtime contracts that must survive a version change. Release history
belongs in [CHANGELOG.md](CHANGELOG.md).

## Runtime capabilities

| Capability | C++ | Python | Java |
| --- | --- | --- | --- |
| AES-256-GCM, HKDF, PBKDF2 | yes | yes | yes |
| Argon2id | release builds require it | `argon2-cffi` | Bouncy Castle, optional JNI |
| ML-KEM-768 and ML-KEM-1024 | liboqs | `pqcrypto` | Bouncy Castle PQC |
| LZMA/XZ | yes | yes | no |
| `fwxAES`, `b512`, `pb512`, live stream, `n10` | yes | yes | yes |
| fwxAES stream variant for unsized input (algo `0x02`) | C++ only | no | no |
| `ENC-P` pack marker (`--compress` output) | reads | reads | refuses |
| Explicit-IV ChaCha20-Poly1305 helper | C++ only | no | no |

Published native builds are expected to include Argon2id and both ML-KEM
parameter sets. A missing required backend is a capability error, not permission
to emit a weaker or differently labelled container.

Two rows above need care.

The C++ writer selects fwxAES algo `0x02` when it cannot learn the input length
up front. That happens in the C++ API `basefwx::fwxaes::EncryptStream` when the
source stream is not seekable, and for any input larger than about 4 GiB.
Python and Java reject `0x02` on every decode path, so a container written
either way is readable by C++ alone. The ordinary `fwxaes-stream-enc` path on a
normal file writes `0x01` and stays portable, and `fwxaes-live-enc` is
unaffected because it writes the separate `LIVE` frame format rather than an
fwxAES container.

Java writes no `ENC-P` and cannot unpack one, so a container carrying that
marker is refused instead of returning the packed archive in place of the
original file. Decode those with the C++ or Python runtime. One combination
still returns the archive silently: `--compress` together with metadata
stripping writes no marker at all, and C++ and Python then recover the pack
mode from the stored `.tgz` or `.txz` extension, which Java does not read.

Java targets Java 8 bytecode. The JDK used to build or test a release may be
newer. Python cryptographic primitives use native-backed packages even though
codec orchestration is Python. Performance varies by runtime and workload and
is not a format contract.

## Maintained format contracts

### Authenticated text payloads

C++, Python, and Java write `b512` and `pb512` payload version 3:

```text
0x03 || uint32_be(plaintext_length) || nonce[12] || ciphertext[N] || tag[16]
```

| Codec | HKDF info | AAD prefix |
| --- | --- | --- |
| `b512` | `basefwx.b512.payload.aead.v1` | `basefwx.b512.payload.v3` |
| `pb512` | `basefwx.pb512.payload.aead.v1` | `basefwx.pb512.payload.v3` |

The AAD prefix is followed by the five-byte version and length header. Writers
use canonical standard Base64. Readers also accept the older URL-safe alphabet
and token-map encoding for migration.

Payload version 2 had no message authentication tag. It is rejected unless
`BASEFWX_ALLOW_LEGACY_TEXT_V2=1` is set while recovering trusted old data.

### File containers and key separation

`b512file` always writes its authenticated outer container. Historical raw
input requires `BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1`. A recognized container
with a bad tag never falls back to raw parsing.

Current non-stripped AES-heavy writers record `ENC-KSEP=v1` and derive separate
payload keys:

| Purpose | HKDF-SHA256 info |
| --- | --- |
| AES-256-GCM | `basefwx.fwxaes.payload.aead.v1` |
| Obfuscation | `basefwx.fwxaes.payload.obf.v1` |

A missing marker selects the legacy root-key schedule. Any unknown marker fails
closed. `ENC-OBF=yes`, `no`, or `fast` controls the authenticated obfuscation
choice. Missing `ENC-OBF` uses the legacy enabled behavior, and any other value
fails.

Stripped output cannot carry `ENC-KSEP`, so it keeps the legacy key schedule.
Readers never guess between schedules.

### Live streams

The live format is shared across the three runtimes. Frames bind their type,
sequence number, and plaintext length as AAD. Sequence numbers must be strictly
ordered. The format provides no retransmission, reordering, jitter buffer, or
clock synchronization.

## KDF compatibility and limits

File-container metadata stores the KDF label. The ordinary b512file user-wrap
blob repeats that label before its salt and wrapped key, while the AES-heavy
pb512file user-wrap blob contains the salt and wrapped key without another
label copy. AES-heavy metadata additionally records the PBKDF2 iteration count
and Argon2id costs, so AES-heavy authoring refuses metadata stripping: without
those values the correct password cannot reproduce the wrapping key. Ordinary
b512file containers do not record costs and rely on the shared defaults (or
matching caller-supplied options where an API exposes them).

This rule is specific to file-container metadata. Direct PBKDF2 `FWX1` and
`LIVE` headers serialize their iteration count in the header itself. Their
wrap-mode variants carry no file metadata and rely on the matching KDF defaults
used by the password-wrap implementation.

The default authoring label is runtime-specific: C++ and Python select
Argon2id when that backend is available, while Java defaults to PBKDF2 unless
`BASEFWX_USER_KDF` selects another supported label. The chosen label and salt
are serialized as described above, so readers do not guess the producer's
default and cross-runtime decode remains interoperable.

Argon2id parallelism defaults to 4 in every runtime. Changing that shared
default would break wrap-mode output that does not record the cost separately.
Set an explicit parallelism only where the producing format records it or when
you control both the writer and reader.

Peer-controlled PBKDF2 counts generally must be in `1..4,000,000`. The C++
direct-PBKDF2 `FWX1` raw and stream decoders retain an additional 10,000
minimum; Java and Python apply the generic lower bound there. Ordinary writers
use 600,000 iterations and the heavy profile uses 2,000,000. The upper bound is
a CPU-amplification limit, not a recommendation to choose the maximum.

Peer Argon2id parameters cannot exceed time cost 16, 256 MiB, or parallelism
16. All runtimes reject invalid decimal syntax, zero, overflow, and values above
the caps before derivation.

Passwords shorter than 12 bytes use the frozen step-up profile recorded in
[SECURITY.md](SECURITY.md). Those constants are part of stored compatibility
even where old metadata omits them.

Local environment overrides are not a shared cross-runtime API. For portable
output, leave them unset or keep PBKDF2 in the peer-safe range. An operator can
make recovery-only local media work unexpectedly expensive with a trusted
override, but ciphertext metadata cannot trigger work above the decoder caps.

There is no second-chance PBKDF2 path. 3.7.0 removed the unauthenticated
fallback, and 3.8.0 removed the `allow_pbkdf2_fallback` field and
`--no-fallback` flag that had survived as documented no-ops. Authentication
failure is terminal.

## Protocol-building APIs

Explicit-salt RFC 5869 HKDF-SHA256, X25519, and ML-KEM key generation and
encapsulation are public in all three runtimes. Shared known-answer fixtures
under `testdata/protocol_kats/` pin interoperability.

RFC HKDF output is limited to 8,160 bytes. Older BaseFWX masks can be larger,
so the runtimes retain a separate compatibility PRF:

```text
PRK  = HMAC-SHA256(32 zero bytes, key_material)
T(i) = HMAC-SHA256(PRK, T(i-1) || info || uint32_be(i))
```

This construction preserves existing bytes. It is not RFC HKDF and must not be
used for a new protocol.

The explicit-IV ChaCha20-Poly1305 helper is C++ only. It exists for a downstream
stored record and is not used by a BaseFWX cross-runtime format. A future second
runtime or shared format would require implementations and shared vectors
before publication.

## Master recovery

The password-only path works in every runtime. A writer that is asked for
master recovery and cannot load a master public key refuses to write rather
than silently producing a password-only file. When master recovery is enabled,
all runtimes prefer a provisioned ML-KEM public key. Its standardized size
selects ML-KEM-768 or ML-KEM-1024 and the `ENC-KEM` value. Upstream artifacts
contain no baked master key.

Readers select ML-KEM by standardized private-key and ciphertext sizes.
Historical EC recovery uses the exact P-521 `EC1` frame. Strict-PQ mode refuses
that EC frame and requires ML-KEM for a new requested master wrap. A valid
independent password wrap remains readable.

## Plugin containers and ABI

Plugin-enabled `FWX1` containers use algorithm byte `0x03`. The fixed header is
followed by:

```text
plugin_id    16 bytes
position      1 byte
config_len    2 bytes, big endian
config        config_len bytes, at most 64 KiB
```

Readers require the matching plugin ID. Raw position requires the plugin's
safe-raw capability. Older readers that do not know algorithm `0x03` fail
closed. The plugin C ABI has its own compatibility policy in [ABI.md](ABI.md).

## Retired-data profile

The old b256, A512, Bi512, Uhash513, kFM, kFA, and jMG surfaces are excluded
from default artifacts. The build-time profile exists for data that already
exists. Its encoders are retained so retired output can be reproduced
byte-for-byte; they are not a supported target for new data:

| Runtime | Select the compatibility profile |
| --- | --- |
| C++ | `-DBASEFWX_ENABLE_RETIRED_MEDIA=ON` |
| Java | `BASEFWX_ENABLE_RETIRED_MEDIA=1` or `-PbasefwxEnableRetiredMedia=true` |
| Python | build from source with `BASEFWX_ENABLE_RETIRED_MEDIA=1` and the `retired-media` extra |

The switch must be active while building. It cannot add missing modules to a
default wheel, JAR, or binary after publication. Recovery preserves released
bytes and APIs, but retired methods have no benchmark or new-feature path.

## Platform and release files

Release assets name their operating system and architecture. The current
release manifest is the source of truth for published targets. Source builds
are expected to work on supported C++ toolchains, Python versions, and JVMs,
but an untested architecture is not a published support claim.

Each release includes canonical artifacts, detached signatures, SHA-256
checksums, and `release-manifest.json`. MD5 files may be present for file
identification and are not a security verification mechanism.

Native release builds avoid `-march=native` so artifacts do not depend on the
builder's CPU. Static third-party crypto and compression linkage is used where
the target workflow supports it, but the operating-system runtime can remain a
dynamic dependency.

If a binary does not start, inspect its architecture and runtime dependencies
with `file`, `ldd`, or the platform equivalent and compare them with the release
manifest. For an Argon2 allocation failure, select PBKDF2 before encryption or
move the operation to a host with enough memory. Never relabel an
Argon2-encoded container after failure.
