<h1 align="center">
<img src="https://raw.githubusercontent.com/f1xgod/basefwx/main/src/ui/basefwx.svg" width="300">
</h1><br>

[![PyPI version](https://img.shields.io/pypi/v/basefwx)](https://pypi.org/project/basefwx/)
[![PyPI downloads](https://img.shields.io/pypi/dm/basefwx.svg?label=PyPI%20downloads)](https://pypi.org/project/basefwx/)
[![CI](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/ci.yml?label=CI)](https://github.com/F1xGOD/basefwx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/publish.yml?label=Release)](https://github.com/F1xGOD/basefwx/actions/workflows/publish.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/codeql.yml?label=CodeQL)](https://github.com/F1xGOD/basefwx/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat)](https://github.com/F1xGOD/basefwx/blob/main/LICENCE)
[![Discord](https://img.shields.io/discord/1130897522051788821?color=7289da&label=Discord&logo=discord&logoColor=ffffff)](https://discord.gg/6d3QxXnzbV)

BASEFWX is a hybrid post-quantum + AEAD encryption toolkit for files and media, with cross-compatible Python, C++, and Java implementations.

- Website: https://basefwx.fixcraft.jp
- Documentation: https://basefwx.fixcraft.jp/docs/CLI
- Source code: https://github.com/F1xGOD/basefwx
- Contributing: https://basefwx.fixcraft.jp/docs/CONTRIBUTING
- Bug reports: https://github.com/F1xGOD/basefwx/issues
- Report a security vulnerability: https://basefwx.fixcraft.jp/docs/SECURITY_MODEL

It provides:

- ML-KEM-768 master key wrapping (optional) and AES-GCM payload protection
- Password-based encryption with Argon2id or PBKDF2
- fwxAES file encryption with optional normalize wrapper
- Packetized live fwxAES stream API for transport-agnostic real-time pipelines
- b512/pb512 reversible encodings and file modes
- kFM carrier codecs (auto media/audio encode + strict carrier decode)
- jMG media cipher for images/audio with metadata control (`archive_original` toggle). Video path is temporarily disabled by default in Python/C++/Java unless `BASEFWX_ENABLE_JMG_VIDEO=1`.
- C++ library and CLI with Python/C++/Java format parity
- Java (JVM) library and CLI for cross-compatible fwxAES/b512/pb512/b256/jMG/kFM

Quick Start
-----------

```bash
pip install basefwx
python -m basefwx cryptin aes-light file.bin -p "password" --strip
python -m basefwx cryptin aes-light file.bin.fwx -p "password"
python -m basefwx n10-enc "hello"
python -m basefwx n10-dec "<digits>"
python -m basefwx kFMe photo.png -o photo.wav            # image/media -> audio carrier
python -m basefwx kFMe track.mp3 -o track.png --bw       # audio -> image carrier
python -m basefwx kFMd photo.wav -o photo-restored.png   # strict decode
python -m basefwx kFMd track.png -o track-restored.mp3
python -m basefwx cryptin fwxaes video.mp4 -p "password"            # Python default: no-archive
python -m basefwx cryptin fwxaes video.mp4 -p "password" --archive  # exact-restore trailer
```

Notes:
- `kFMd` only decodes BaseFWX carriers; it refuses plain WAV/PNG/MP3/M4A files.
- `kFAe` / `kFAd` remain available as deprecated aliases to `kFMe` / `kFMd`.
- Optional kFM/kFA acceleration:
  - `BASEFWX_KFM_ACCEL=auto|cuda|cpu` (default `auto`)
  - `BASEFWX_KFM_ACCEL_MIN_BYTES=<bytes>` (default `1048576`, auto mode threshold)
- CLI progress now includes live system telemetry (CPU/GPU/RAM/I/O/TEMP when available).
  Disable with `BASEFWX_PROGRESS_TELEMETRY=0`.
- C++/Java CLI global flags: `--no-log` (suppress non-essential logs) and `--verbose` (show hardware routing reasons).
- jMG video is disabled by default in Python/C++/Java; set `BASEFWX_ENABLE_JMG_VIDEO=1` to re-enable temporarily.

Python API quick refs:

```python
from basefwx import n10encode, n10decode, n10encode_bytes, n10decode_bytes
from basefwx import kFMe, kFMd
from basefwx import LiveEncryptor, LiveDecryptor, jMGe, jMGd

digits = n10encode("hello")
text = n10decode(digits)
blob_digits = n10encode_bytes(b"\x00\x01\x02")
blob = n10decode_bytes(blob_digits)

carrier = kFMe("input.mp3", output="input.png", bw_mode=True)
restored = kFMd("input.png", output="restored.mp3")

# jMG Python default is no-archive (smaller, non-byte-identical restore)
jMGe("clip.m4a", "password", output="clip.small.m4a")
jMGe("cover.png", "password", output="cover.exact.png", archive_original=True)
jMGd("clip.small.m4a", "password", output="clip.out.m4a")

# Live packetized stream encryption/decryption
enc = LiveEncryptor("password", use_master=False)
dec = LiveDecryptor("password", use_master=False)
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
    "password",
    use_master=False,
)
fwxAES_live_decrypt_ffmpeg(
    "stream.live.fwx",
    ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "matroska", "-i", "-", "-c", "copy", "restored.mkv"],
    "password",
    use_master=False,
)
```

Hardware acceleration (Python jMG):
- `BASEFWX_HWACCEL=auto` (default), `nvenc`, `qsv`, `vaapi`, or `off`
- `BASEFWX_HWACCEL_STRICT=1` to fail instead of CPU fallback when requested accel is unavailable

Optional extras:

```bash
pip install basefwx[argon2]
```

Documentation
-------------

- [Docs home (HTML)](https://basefwx.fixcraft.jp)
- [CLI and usage](https://basefwx.fixcraft.jp/docs/CLI)
- [Security model](https://basefwx.fixcraft.jp/docs/SECURITY_MODEL)
- [Testing and benchmarks](https://basefwx.fixcraft.jp/docs/TESTING)
- [Contributing and code of conduct](https://basefwx.fixcraft.jp/docs/CONTRIBUTING)
- [Java module](https://basefwx.fixcraft.jp/docs/CLI#java-cli)

License
-------

See https://basefwx.fixcraft.jp/LICENCE.
