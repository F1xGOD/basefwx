# BaseFWX Explained

This document explains what BaseFWX does, how the main container and stream
shapes fit together, and where the C++ library sits when YUME uses it. The
diagrams are plain ASCII so the same content can be reused in a future
`man basefwx` page.

BaseFWX is a cryptographic codec toolkit. It protects files and byte streams.
It is not a transport by itself and it does not provide anonymity by itself.
Applications such as YUME use BaseFWX as an inner crypto and encoding layer.

## Diagram Style

Every diagram uses the same fixed-width box shape. The format is stable in
terminals, Markdown, and man pages.

```text
+--------------------------------+
|  PROCESS                       |
|  detail                        |
+--------------------------------+

--->   normal data movement
===>   encrypted or authenticated BaseFWX data
...>   optional carrier, wrapper, or outer application
```

## Basic Mental Model

Most BaseFWX operations have four visible parts:

```text
+--------------------------------+
|  CALLER                        |
|  CLI / library / YUME          |
+--------------------------------+
        |
        | password, bytes, options
        v
+--------------------------------+
|  BASEFWX CORE                  |
|  KDF, keys, AEAD, metadata     |
+--------------------------------+
        |
        | encrypted container
        v
+--------------------------------+
|  OUTPUT FORMAT                 |
|  file, packet, media carrier   |
+--------------------------------+
        |
        | stored or transported
        v
+--------------------------------+
|  DECODER                       |
|  verifies before release       |
+--------------------------------+
```

The caller gives BaseFWX plaintext bytes and a password or key context.
BaseFWX derives or unwraps encryption keys, encrypts and authenticates the
payload, then writes a format that another BaseFWX implementation can parse.

On decode, BaseFWX reads the format metadata, derives or unwraps the same
keys, verifies the authenticated data, then returns plaintext only after the
checks pass.

## What BaseFWX Provides

BaseFWX includes several related codec families:

- `fwxAES`: AES-GCM file encryption with metadata and optional wrappers.
- `pb512` / `b512`: authenticated AES-256-GCM text payloads with password or
  optional master-key wrapping, plus related file modes.
- `livecipher`: packetized stream encryption for pipe and transport use.
- `keywrap`: password and master-key wrapping helpers.
- `pq`: ML-KEM-768/1024 key encapsulation when liboqs support is enabled.
- `n10`, `b512`: maintained reversible text and binary encodings.

b256/A512/Bi512/Uhash513 and the kFM/kFA/jMG media codecs are not in this list,
because a default build does not contain retired methods. See
[Retired compatibility formats](#retired-compatibility-formats).

The C++ package exports the shared library as `libbasefwx.so.4`, headers
under `basefwx/`, a CMake package named `basefwx`, and a `basefwx.pc`
pkg-config file.

## File Encryption Flow

The normal file path is a container pipeline:

```text
+--------------------------------+
|  PLAINTEXT FILE                |
|  bytes from disk or stdin      |
+--------------------------------+
        |
        v
+--------------------------------+
|  KDF AND KEY SETUP             |
|  Argon2id or PBKDF2            |
+--------------------------------+
        |
        v
+--------------------------------+
|  AEAD ENCRYPTION               |
|  AES-256-GCM + metadata        |
+--------------------------------+
        |
        | ===>
        v
+--------------------------------+
|  BASEFWX CONTAINER             |
|  FWX1 / heavy / encoded form   |
+--------------------------------+
```

`fwxAES` is the direct encrypted-file mode. Heavy modes increase KDF cost
and use compatible BaseFWX wrappers for stronger password-hardening choices.
Metadata is authenticated with the payload, so tampering is detected during
decode.

## Key Setup

BaseFWX separates password hardening, optional post-quantum wrapping, and
payload encryption:

```text
+--------------------------------+
|  USER SECRET                   |
|  password or passphrase        |
+--------------------------------+
        |
        | KDF
        v
+--------------------------------+
|  USER KEY                      |
|  Argon2id / PBKDF2 output      |
+--------------------------------+
        |
        | optional master wrap
        v
+--------------------------------+
|  PAYLOAD KEY                   |
|  used by AES-GCM               |
+--------------------------------+
        |
        | ===>
        v
+--------------------------------+
|  AUTHENTICATED PAYLOAD         |
|  ciphertext + tag              |
+--------------------------------+
```

When ML-KEM support is enabled, BaseFWX can use post-quantum encapsulation
for master-key handling. Builds that do not have liboqs still keep the
non-PQ formats available, but they cannot produce or consume PQ-required
containers.

## Container Shape

At a high level, encrypted file containers carry authenticated metadata and
encrypted payload bytes:

```text
+----------------------------------------------------------------------+
|  BASEFWX ENCRYPTED CONTAINER                                         |
|                                                                      |
|  magic/version | KDF parameters | wrap data | metadata | ciphertext  |
|                                                                      |
|  metadata is authenticated; payload releases after verification      |
+----------------------------------------------------------------------+
```

Exact byte layout depends on the selected codec family. Stable public APIs
should be used to read and write containers instead of hand-parsing fields.

## Live Stream Flow

Live mode is for pipes and real-time transports:

```text
+--------------------------------+
|  PRODUCER                      |
|  file, ffmpeg, app bytes       |
+--------------------------------+
        |
        v
+--------------------------------+
|  LIVE ENCRYPTOR                |
|  start, update, finalize       |
+--------------------------------+
        |
        | ===>
        v
+--------------------------------+
|  LIVE PACKETS                  |
|  ordered AES-GCM frames        |
+--------------------------------+
        |
        v
+--------------------------------+
|  LIVE DECRYPTOR                |
|  verifies packet sequence      |
+--------------------------------+
```

The live API emits packetized `LIVE` frames. This keeps memory bounded and
lets an outer program move encrypted chunks through a pipe, socket, or
transport. The receiver must process the stream in order and finalize it
before treating the stream as complete.

## Retired Compatibility Formats

b256, A512, Bi512, Uhash513, and the kFM/kFA/jMG media codecs are retired. A
default build does not compile or package their code, commands, tests, or
benchmarks, so none of this section describes a default artifact.

They live in a compatibility build, configured with
`-DBASEFWX_ENABLE_RETIRED_MEDIA=ON` for C++ and the matching
`BASEFWX_ENABLE_RETIRED_MEDIA=1` for Java and Python. The historical switch
name remains for build-script compatibility. That profile has one job: reading
retired data you already have. It preserves the historical APIs, formats, and
bytes unchanged, and receives security, correctness, and existing-data
compatibility fixes only.

Because the switch selects what gets compiled, it cannot re-enable these
formats in an artifact built without them. Use a compatibility artifact of the
same BaseFWX version that wrote the file.

For new media, use `fwxAES`. A media file is bytes, and `fwxAES` gives those
bytes the same AEAD guarantees it gives any other file.

The two shapes below are recorded so existing files stay readable and
diagnosable.

### kFM and kFA carriers

Carrier modes are wrappers around protected data. They are not security by
themselves; the encryption comes from the BaseFWX container inside the carrier.

```text
+--------------------------------+
|  INPUT DATA                    |
|  file, audio, image            |
+--------------------------------+
        |
        v
+--------------------------------+
|  BASEFWX PAYLOAD               |
|  encrypted or encoded bytes    |
+--------------------------------+
        |
        | ...>
        v
+--------------------------------+
|  CARRIER FORMAT                |
|  PNG / WAV / media output      |
+--------------------------------+
        |
        v
+--------------------------------+
|  STRICT DECODER                |
|  accepts BaseFWX carriers      |
+--------------------------------+
```

`kFMe` picks a carrier shape from the input type and writes BaseFWX carrier
files. `kFMd` decodes them strictly and rejects ordinary media that BaseFWX did
not produce. `kFAe` and `kFAd` are deprecated aliases for the PNG-only path.

### jMG media cipher

```text
+--------------------------------+
|  MEDIA INPUT                   |
|  image, audio, video path      |
+--------------------------------+
        |
        v
+--------------------------------+
|  TRANSCODE OR COPY PATH        |
|  optional ffmpeg/hw accel      |
+--------------------------------+
        |
        v
+--------------------------------+
|  JMG TRAILER                   |
|  key-only or archive payload   |
+--------------------------------+
        |
        | ===>
        v
+--------------------------------+
|  MEDIA OUTPUT                  |
|  smaller or exact restore      |
+--------------------------------+
```

The key-only path keeps output small. The archive path appends the encrypted
original so decode can restore it exactly. Video support was gated by build and
runtime flags on top of the compatibility profile.

🫡 b256 has been retired since BaseFWX 3.7.0. It was the first BaseFWX
encoding method, born in V1 back when this was a proof of concept and not yet a
project. Existing data still decodes through the compatibility profile, but
for new work, it's time to go. ❤️

## YUME Integration

YUME is a **separate sibling project** (not shipped in this repository).
It uses the C++ BaseFWX library for inner crypto, not the BaseFWX CLI:

```text
+--------------------------------+
|  YUME STREAM                   |
|  logical app connection        |
+--------------------------------+
        |
        v
+--------------------------------+
|  BASEFWX INNER CRYPTO          |
|  AES / Argon2id / ML-KEM       |
+--------------------------------+
        |
        | ===>
        v
+--------------------------------+
|  YUME CARRIER                  |
|  TLS 1.3 + YUME frames         |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUMED SERVER                  |
|  unwraps inner stream data     |
+--------------------------------+
```

For Debian-style YUME builds, `yume` should link against a packaged
`libbasefwx4` runtime through `libbasefwx-dev`. This avoids using the
bundled BaseFWX tree or vendored dependency directories inside the YUME
source package. The development package exposes the LGPL library headers,
not the private GPL command-line headers. `ABI.md` defines the stable plugin
C ABI and the narrower same-minor compatibility contract for the general
C++ library.

## Debian Package Shape

The intended package split is:

```text
+--------------------------------+
|  basefwx                       |
|  command-line frontend         |
+--------------------------------+
        |
        v
+--------------------------------+
|  libbasefwx4                   |
|  runtime shared library        |
+--------------------------------+
        ^
        |
+--------------------------------+
|  libbasefwx-dev                |
|  headers and build metadata    |
+--------------------------------+
        ^
        |
+--------------------------------+
|  yume                          |
|  links to libbasefwx.so.4      |
+--------------------------------+
```

Local development builds may use a prepared vendor liboqs staging directory
to keep ML-KEM-768/1024 available. Debian archive builds should use a normal
packaged `liboqs-dev` dependency instead of embedding or copying liboqs into
BaseFWX.

The Debian packaging in this tree ships the C++ CLI, shared library, and
development files as separate binary packages from one source package. It
does not install the Python or Java modules; those can remain separate
packages if they are needed later.

## Failure Model

BaseFWX should fail closed:

- Wrong password: authentication fails and plaintext is not released.
- Changed ciphertext: authentication fails.
- Missing PQ support: PQ-required operations fail instead of silently
  downgrading.
- Truncated live stream: finalization fails or reports an incomplete stream.
- Non-carrier media, in a compatibility build: strict carrier decoders reject
  it.

Callers should treat decode errors as integrity failures unless they have a
format-specific reason to do otherwise.

## Man Page Reuse

This file is intentionally written in short sections with fixed-width
diagrams. The `basefwx(7)` overview page reuses the same diagram style inside
roff `.nf` / `.fi` blocks without changing box widths.
