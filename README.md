<h1 align="center">
<img src="https://raw.githubusercontent.com/f1xgod/basefwx/main/src/ui/basefwx.svg" width="300">
</h1><br>

[![PyPI](https://img.shields.io/pypi/v/basefwx?style=flat&logo=pypi&logoColor=white&label=PyPI)](https://pypi.org/project/basefwx/)
[![Downloads](https://img.shields.io/pypi/dm/basefwx?style=flat&logo=pypi&logoColor=white&label=downloads)](https://pypi.org/project/basefwx/)
[![Python](https://img.shields.io/pypi/pyversions/basefwx?style=flat&logo=python&logoColor=white)](https://pypi.org/project/basefwx/)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat)](https://github.com/F1xGOD/basefwx/releases/latest)

[![CI](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/ci.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI)](https://github.com/F1xGOD/basefwx/actions/workflows/ci.yml)
[![Memleak](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/leak-detect.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=Memleak)](https://github.com/F1xGOD/basefwx/actions/workflows/leak-detect.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/codeql.yml?branch=main&style=flat&logo=github&logoColor=white&label=CodeQL)](https://github.com/F1xGOD/basefwx/actions/workflows/codeql.yml)

[![Latest release](https://img.shields.io/github/v/release/F1xGOD/basefwx?style=flat&logo=github&logoColor=white&label=Release)](https://github.com/F1xGOD/basefwx/releases/latest)
[![License](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat&label=License)](https://github.com/F1xGOD/basefwx/blob/main/LICENCE)

BaseFWX is a cross-runtime post-quantum + AEAD encryption toolkit. Active
development now centers on mathematically grounded, high-performance C++
cryptographic primitives. Python and Java remain part of the compatibility
surface, and the three implementations share the same established on-disk and
on-wire formats.

The b256/A512/Bi512/Uhash513 text codecs and the image-, audio-, and
video-specific kFM/kFA/jMG codecs are retired. Default C++, Java, and Python
artifacts do not compile or package their implementations, commands, tests, or
benchmarks. Existing callers and data can use an explicitly enabled
compatibility artifact; that profile preserves the established APIs and bytes,
but receives only security, correctness, and existing-data compatibility fixes.
No new retired formats, features, performance work, or benchmark rows are
planned.

The version in this checkout is recorded in [`VERSION`](VERSION). This
revision is the unreleased `3.8.0-dev1` development line; the latest tagged
release is `v3.7.0`. See [CHANGELOG.md](CHANGELOG.md) for development changes
and [SECURITY.md](SECURITY.md) for the supported-version policy. Native
consumers should also read [ABI.md](ABI.md): the plugin C ABI and general C++
library have intentionally different compatibility contracts.

Repository policy:

- `main` is the canonical development/release line; `DEV` is its integration
  mirror.
- It stays a monorepo. There are no language-specific long-lived branches.
- Shared format and security changes have to keep Python / C++ / Java parity in one PR.

- Website: https://basefwx.fixcraft.jp
- Documentation: https://basefwx.fixcraft.jp/docs/CLI
- Source code: https://github.com/F1xGOD/basefwx
- Contributing: https://basefwx.fixcraft.jp/docs/CONTRIBUTING
- Bug reports: https://github.com/F1xGOD/basefwx/issues
- Report a security vulnerability: https://basefwx.fixcraft.jp/docs/SECURITY_MODEL

What's in the box:

- AES-256-GCM payloads with optional ML-KEM-768/1024 master-key wrapping
- Password-based encryption via Argon2id (recommended) or PBKDF2
- fwxAES file format with an optional normalize wrapper that hides bytes in zero-width Unicode markers
- A packetized live-stream API so fwxAES works inside ffmpeg/SIP/transport pipes
- b512 / pb512 authenticated text encodings (v3 AES-256-GCM) and file modes
- Optional retired-data compatibility artifacts for b256/A512/Bi512/Uhash513,
  kFM/kFA carriers, and jMG
- C++ and Java libraries + CLIs that read and write the same formats as the Python module

Quick Start
-----------

```bash
pip install basefwx
python -m basefwx cryptin aes-light file.bin -p "correct-horse-battery" --strip
python -m basefwx cryptin aes-light file.bin.fwx -p "correct-horse-battery"
python -m basefwx n10-enc "hello"
python -m basefwx n10-dec "<digits>"
```

Notes:
- Encryption requires a password of at least 10 UTF-8 bytes. This is enforced
  on encrypt only — existing blobs with shorter passwords still decrypt.
  Override with `BASEFWX_ALLOW_WEAK_PASSWORD=1`, or set a different floor with
  `BASEFWX_MIN_PASSWORD_LEN=<n>` (`0` disables it). Passwords under 12 bytes
  additionally get a more expensive KDF profile. See
  [SECURITY.md](SECURITY.md#crypto-helper-boundaries) for both rules.
- `--strip` is rejected when b512/AES-heavy file encoding selects the
  streaming container. Streaming decode needs the public `ENC-MODE=STREAM`
  marker for safe format dispatch; omitting it would create an unreadable
  ciphertext rather than a metadata-free stream.
- Default artifacts exclude b256/A512/Bi512/Uhash513, jMG/kFM/kFA, and Pillow.
  To read existing retired data, build and run a compatibility profile as shown
  below. The historical switch remains named `BASEFWX_ENABLE_RETIRED_MEDIA` so
  existing build automation keeps working.
- New b512/pb512 text output is authenticated payload v3 and canonical
  standard base64. Version 2 text payloads were malleable and are rejected by
  default; `BASEFWX_ALLOW_LEGACY_TEXT_V2=1` is a trusted-data recovery switch,
  not a normal compatibility setting. Cosmetic token-map output is opt-in
  with `BASEFWX_OBFUSCATE_CODECS=1`.
- b512file writers always use the outer AES-256-GCM container. The old
  unauthenticated writer mode is retired; raw historical files require
  `BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1` only while recovering trusted data.
- Benchmarks exercise only maintained methods. Compatibility mode restores
  exact-byte and decode qualification for retired methods, but does not restore
  their benchmark rows.
- Release support policy is single-version: only the latest release is maintained; all older releases are immediately unsupported.
- CLI progress now includes live system telemetry (CPU/GPU/RAM/I/O/TEMP when available).
  Disable with `BASEFWX_PROGRESS_TELEMETRY=0`.
- Python `n10` was optimized for large payloads, but compiled runtimes (C++/Java) are still expected to benchmark faster for very large text workloads.
- C++/Java CLI global flags: `--no-log` (suppress non-essential logs) and `--verbose` (show hardware routing reasons).
- Canonical release assets are architecture-qualified only; alias artifacts without arch suffixes are intentionally not published.
- Every GitHub release includes detached signatures, checksum files, and `release-manifest.json`.

Python API quick refs:

```python
from basefwx import n10encode, n10decode, n10encode_bytes, n10decode_bytes
from basefwx import LiveEncryptor, LiveDecryptor

digits = n10encode("hello")
text = n10decode(digits)
blob_digits = n10encode_bytes(b"\x00\x01\x02")
blob = n10decode_bytes(blob_digits)

# Live packetized stream encryption/decryption
enc = LiveEncryptor("correct-horse-battery", use_master=False)
dec = LiveDecryptor("correct-horse-battery", use_master=False)
wire = [enc.start(), enc.update(b"chunk-1"), enc.update(b"chunk-2"), enc.finalize()]
plain_chunks = []
for packet in wire:
    plain_chunks.extend(dec.update(packet))
dec.finalize()

# ffmpeg pipe helpers for live media transport
from basefwx import fwxAES_live_encrypt_ffmpeg, fwxAES_live_decrypt_ffmpeg
fwxAES_live_encrypt_ffmpeg(
    ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", "input.m4a", "-f", "matroska", "-c", "copy", "-"],
    "stream.live.fwx",
    "correct-horse-battery",
    use_master=False,
)
fwxAES_live_decrypt_ffmpeg(
    "stream.live.fwx",
    ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "matroska", "-i", "-", "-c", "copy", "restored.mkv"],
    "correct-horse-battery",
    use_master=False,
)
```

Retired-media compatibility is source-build-only and must be selected before
Python imports BaseFWX. A default wheel does not contain these modules, so an
environment variable cannot turn them back on afterward:

```bash
BASEFWX_ENABLE_RETIRED_MEDIA=1 \
  python -m pip install './python[retired-media]'
BASEFWX_ENABLE_RETIRED_MEDIA=1 \
  python -m basefwx kFMd existing-carrier.wav -o restored.bin
```

Compatibility-only details:

- `kFMd` refuses plain WAV/PNG/MP3/M4A files; it decodes BaseFWX carriers only.
- `kFAe` / `kFAd` remain deprecated aliases to `kFMe` / `kFMd`.
- `BASEFWX_KFM_ACCEL=auto|cuda|cpu` selects kFM acceleration.
- `BASEFWX_HWACCEL=auto|nvenc|qsv|vaapi|off` selects jMG acceleration.
- jMG video additionally requires `BASEFWX_ENABLE_JMG_VIDEO=1`.

Optional extras:

```bash
pip install basefwx[argon2]
```

The `argon2` extra is a compatibility no-op; Argon2 is already a required
dependency. The `retired-media` extra installs Pillow but does not by itself
add retired code to a default wheel.

Documentation
-------------

- [Docs home (HTML)](https://basefwx.fixcraft.jp)
- [BaseFWX explained](docs/EXPLAINED.md)
- [BaseFWX CLI manual page](docs/man/basefwx.1)
- [BaseFWX library overview manual page](docs/man/basefwx.7)
- [CLI and usage](https://basefwx.fixcraft.jp/docs/CLI)
- [Security model](https://basefwx.fixcraft.jp/docs/SECURITY_MODEL)
- [Testing and benchmarks](https://basefwx.fixcraft.jp/docs/TESTING)
- [Contributing and code of conduct](https://basefwx.fixcraft.jp/docs/CONTRIBUTING)
- [Java module](https://basefwx.fixcraft.jp/docs/CLI#java-cli)
- [Compatibility matrix](https://github.com/F1xGOD/basefwx/blob/main/COMPATIBILITY.md)

License
-------

BaseFWX uses a split license: core library/API/runtime and plugin ABI/SPI
surfaces are LGPL-3.0-or-later, standalone CLI/tools/benchmarks/scripts are
GPL-3.0-or-later, and example plugin templates are MIT OR Apache-2.0.
The root [LICENCE](LICENCE) file contains the canonical LGPL-3.0 text for
GitHub/license-scanner detection; see [LICENSING.md](LICENSING.md) for the
full split policy and [LICENSES/](LICENSES/) for the other canonical texts.
