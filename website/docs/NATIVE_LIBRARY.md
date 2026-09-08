---
layout: "doc"
title: "BaseFWX library manual"
description: "C++ cryptographic codec library and container family"
permalink: "/docs/NATIVE_LIBRARY/"
generated_from: "docs/NATIVE_LIBRARY.md"
doc_source: "docs/src/en_US/man/basefwx_7.doc"
lang: "en-US"
doc_locale: "en_US"
---

# BaseFWX library manual

C++ cryptographic codec library and container family

## SYNOPSIS

{% raw %}
```text
#include <basefwx/basefwx.hpp>

pkg-config --cflags --libs basefwx

find_package(basefwx 3.8 CONFIG REQUIRED)
target_link_libraries(app PRIVATE basefwx::basefwxcpp)
```
{% endraw %}

## DESCRIPTION

BaseFWX is a cryptographic codec toolkit. It protects files and byte streams.
It is not a network transport by itself and it does not provide anonymity by
itself.

Applications such as YUME use BaseFWX as an inner cryptographic and encoding
layer. The C++ library provides authenticated encryption, password hardening,
post-quantum key encapsulation when built with liboqs support, and live stream
framing.

The Debian packaging in this source tree ships the C++ CLI, shared library, and
development files as separate binary packages from one source package. It does
not install the Python or Java modules.

## BASIC FLOW

<!-- yume-diagram: basic_flow -->
{% raw %}
```text
+----------------------------+
|  CALLER                    |
|  CLI / library / YUME      |
+--------------+-------------+
                \
                 \
                  v password, bytes, options
   +--------------+-------------+
   |  BASEFWX CORE              |
   |  KDF, keys, AEAD, metadata |
   +--------------+-------------+
                   \
                    \
                     v encrypted container
      +--------------+-------------+
      |  OUTPUT FORMAT             |
      |  file or packet            |
      +--------------+-------------+
                      \
                       \
                        v stored or transported
         +--------------+-------------+
         |  DECODER                   |
         |  verifies before release   |
         +----------------------------+
```
{% endraw %}
<!-- /yume-diagram -->

The caller supplies plaintext bytes and a password or key context. BaseFWX
derives or unwraps encryption keys, encrypts and authenticates the payload, and
writes a format another BaseFWX implementation can parse.

On decode, BaseFWX reads and validates format metadata, derives or unwraps the
same keys, verifies integrity, and releases plaintext only after verification
passes.

## CODEC FAMILIES

- **fwxAES**

  AES-GCM file encryption with metadata and optional wrappers.

- **pb512 / b512**

  Authenticated AES-256-GCM text payloads with password or optional master-key
  wrapping, plus related file modes. Current writers emit payload version 3;
  version 2 decode requires **BASEFWX_ALLOW_LEGACY_TEXT_V2=1** for
  trusted-data recovery.

- **livecipher**

  Packetized stream encryption for pipes and transport use.

- **keywrap / pq**

  Password and master-key wrapping helpers, including ML-KEM-768/1024 when
  liboqs support is enabled.

- **n10 / b512**

  Maintained reversible text and binary encodings.

## RETIRED COMPATIBILITY FORMATS

b256, A512, Bi512, Uhash513, the kFM/kFA carrier codecs, and the jMG media
cipher are retired. A default build compiles and installs none of them: their
implementations, CLI commands, tests, and benchmarks are all absent, and
**BASEFWX_HAS_RETIRED_MEDIA** is 0 in the installed CMake and pkg-config
metadata.

Configuring with **-DBASEFWX_ENABLE_RETIRED_MEDIA=ON** produces a compatibility
library that carries them. The historical switch name is retained for
build-script compatibility. That profile exists to read retired data that
already exists. It preserves the historical APIs, formats, and bytes unchanged,
and receives security, correctness, and existing-data compatibility fixes only;
no new retired formats or features are planned.

The switch decides what gets compiled, so it cannot re-enable these formats in
a library that was built without them. Link against a compatibility build of
the same BaseFWX version that wrote the file. Protect new media with **fwxAES**
instead, which gives it the same AEAD guarantees as any other file.

## FILE CONTAINERS

<!-- yume-diagram: file_containers -->
{% raw %}
```text
+------------------------------+
|  PLAINTEXT FILE              |
|  bytes from disk or stdin    |
+---------------+--------------+
                 \
                  \
                   v
   +---------------+--------------+
   |  KDF AND KEY SETUP           |
   |  Argon2id or PBKDF2          |
   +---------------+--------------+
                    \
                     \
                      v
      +---------------+--------------+
      |  AEAD ENCRYPTION             |
      |  AES-256-GCM payload         |
      +---------------+--------------+
                       \
                        \
                         v
         +---------------+--------------+
         |  BASEFWX CONTAINER           |
         |  FWX1 / heavy / encoded form |
         +------------------------------+
```
{% endraw %}
<!-- /yume-diagram -->

At a high level, encrypted file containers carry bounded format and key headers
followed by an authenticated encrypted payload:

{% raw %}
```text
+----------------------------------------------------------------------+
|  BASEFWX ENCRYPTED CONTAINER                                         |
|                                                                      |
|  magic/version | KDF parameters | wrap data | metadata | ciphertext  |
|                                                                      |
|  headers are bounded; payload releases after tag verification        |
+----------------------------------------------------------------------+
```
{% endraw %}

Exact byte layout depends on the selected codec family. Use the public API to
read and write containers instead of hand-parsing container fields.

## LIVE STREAMS

<!-- yume-diagram: live_streams -->
{% raw %}
```text
+---------------------------+
|  PRODUCER                 |
|  file, ffmpeg, app bytes  |
+-------------+-------------+
               \
                \
                 v
   +-------------+-------------+
   |  LIVE ENCRYPTOR           |
   |  start, update, finalize  |
   +-------------+-------------+
                  \
                   \
                    v
      +-------------+-------------+
      |  LIVE PACKETS             |
      |  ordered AES-GCM frames   |
      +-------------+-------------+
                     \
                      \
                       v
         +-------------+-------------+
         |  LIVE DECRYPTOR           |
         |  verifies packet sequence |
         +---------------------------+
```
{% endraw %}
<!-- /yume-diagram -->

Live mode emits packetized frames, keeping memory bounded for pipes, sockets,
and transport integrations. Receivers must process frames in order and finalize
before treating the stream as complete.

## YUME INTEGRATION

<!-- yume-diagram: yume_integration -->
{% raw %}
```text
+----------------------------+
|  YUME STREAM               |
|  logical app connection    |
+--------------+-------------+
                \
                 \
                  v
   +--------------+-------------+
   |  BASEFWX INNER CRYPTO      |
   |  AES / Argon2id / ML-KEM   |
   +--------------+-------------+
                   \
                    \
                     v
      +--------------+-------------+
      |  YUME CARRIER              |
      |  TLS 1.3 + YUME frames     |
      +--------------+-------------+
                      \
                       \
                        v
         +--------------+-------------+
         |  YUMED SERVER              |
         |  unwraps inner stream data |
         +----------------------------+
```
{% endraw %}
<!-- /yume-diagram -->

For packaged YUME builds, the yume binary links against libbasefwx.so.4 through
the libbasefwx-dev build package and the libbasefwx4 runtime package.

## PACKAGE LAYOUT

{% raw %}
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
{% endraw %}

Local development builds may use a prepared vendor liboqs staging directory to
keep ML-KEM-768/1024 available. Debian archive builds should use a normal
packaged liboqs-dev dependency instead of embedding liboqs into BaseFWX.

## FAILURE MODEL

BaseFWX fails closed. A wrong password, changed ciphertext, missing PQ support
for a PQ-required container, or a truncated live stream fails instead of
releasing unauthenticated plaintext. A compatibility build applies the same
rule to retired carrier input that is not a BaseFWX carrier.

## FILES

- */usr/include/basefwx/*

  C++ public headers.

- */usr/lib/<multiarch>/libbasefwx.so.4*

  BaseFWX runtime shared library.

- */usr/lib/<multiarch>/cmake/basefwx/*

  CMake package files.

- */usr/lib/<multiarch>/pkgconfig/basefwx.pc*

  pkg-config metadata.

- */usr/share/doc/libbasefwx4/EXPLAINED.md.gz*

  Extended overview with reusable diagrams.

## SEE ALSO

`basefwx(1)`

YUME is a separate sibling project that can link against **libbasefwx**; its
manual pages (if installed) are `yume(1)` and `yumed(8)`. Those binaries
and man pages are **not** part of this BaseFWX source tree.
