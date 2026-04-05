# BaseFWX C++

This C++ implementation is wire-compatible with BaseFWX 3.6.4 and covers the
current CLI/library surface used in release builds, including fwxAES, jMG, kFM,
and the shared codec families.

## Build

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
```

If you want to build without Argon2 or ML-KEM support (not cross-compatible with those modes):

```bash
cmake -S cpp -B cpp/build -DBASEFWX_REQUIRE_ARGON2=OFF -DBASEFWX_REQUIRE_OQS=OFF
cmake --build cpp/build
```

## CLI (current)

```bash
./cpp/build/basefwx [global flags] <command> ...
# global flags: --verbose|-v --no-log --no-color
./cpp/build/basefwx info <file.fwx>
./cpp/build/basefwx b256-enc "hello"
./cpp/build/basefwx b256-dec "<payload>"
./cpp/build/basefwx n10-enc "hello"
./cpp/build/basefwx n10-dec "<digits>"
./cpp/build/basefwx n10file-enc secret.bin secret.n10
./cpp/build/basefwx n10file-dec secret.n10 secret.bin
./cpp/build/basefwx kFMe input.bin --out input.wav
./cpp/build/basefwx kFMe input.mp3 --out input.png --bw
./cpp/build/basefwx kFMd input.wav --out restored.bin
./cpp/build/basefwx kFMd input.png --out restored.mp3
./cpp/build/basefwx b512-enc "hello" -p "pw"
./cpp/build/basefwx b512-dec "<payload>" -p "pw"
./cpp/build/basefwx pb512-enc "hello" -p "pw"
./cpp/build/basefwx pb512-dec "<payload>" -p "pw"
./cpp/build/basefwx b512file-enc secret.bin -p "pw"
./cpp/build/basefwx b512file-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx pb512file-enc secret.bin -p "pw"
./cpp/build/basefwx pb512file-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx fwxaes-enc secret.bin -p "pw" --normalize
./cpp/build/basefwx fwxaes-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx fwxaes-enc secret.bin -p "pw" --heavy
./cpp/build/basefwx fwxaes-dec secret.bin.fwx -p "pw" --heavy
./cpp/build/basefwx fwxaes-heavy-enc secret.bin -p "pw"
./cpp/build/basefwx fwxaes-heavy-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx fwxaes-live-enc secret.bin -p "pw" --out secret.live.fwx
./cpp/build/basefwx fwxaes-live-dec secret.live.fwx -p "pw" --out secret.bin
ffmpeg -hide_banner -loglevel error -i input.m4a -vn -ac 1 -ar 16000 -f wav pipe:1 \
  | ./cpp/build/basefwx fwxaes-live-enc - -p "pw" --no-master --out - \
  | ./cpp/build/basefwx fwxaes-live-dec - -p "pw" --no-master --out - > restored.wav
./cpp/build/basefwx jmge input.mp4 -p "pw" --out out-small.mp4
./cpp/build/basefwx jmge input.mp4 -p "pw" --archive --out out-exact.mp4
```

`info`, `identify`, and `probe` recognize:

- BaseFWX length-prefixed containers
- `FWX1` fwxAES headers
- kFM PNG/WAV carriers, including legacy `kFAe` output

If a file is not recognized as a BaseFWX container, the CLI falls back to a
heuristic report. High-entropy files are reported as unidentified random-like
data instead of being mislabeled as a corrupted BaseFWX container.

## Compatibility notes

- The AEAD blob format is: 4-byte len + user blob, 4-byte len + master blob,
  4-byte len + payload blob.
- The AES payload starts with 4-byte metadata length, followed by base64-encoded
  JSON metadata, followed by ciphertext.
- The b512 AEAD payload is fully encrypted, so metadata cannot be parsed without
  decryption.
- kFM carriers are byte-reversible across Python/C++/Java for BaseFWX-made files.
- New kFM carriers are block-coded into PNG/WAV media at near full carrier capacity; they are no longer stored as raw carrier bytes copied straight into pixel/sample buffers.
- Legacy raw-byte kFM carriers still decode for backward compatibility.
- New encrypt operations reject passwords shorter than 10 characters unless `BASEFWX_ALLOW_WEAK_PASSWORD=1` is set.
- Default user KDF targets are hardened to `PBKDF2=600000` / `Argon2id=4 x 64 MiB`, and heavy mode advertises `PBKDF2=2000000` / `Argon2id=6 x 256 MiB`.
- `kFMe` auto-detects source type:
  - audio input -> PNG carrier
  - non-audio input -> WAV carrier
- `kFMe` only emits `.png` or `.wav` carrier files; explicit mismatched output extensions are rejected.
- `kFMd` strictly decodes BaseFWX carriers and refuses non-carrier files.
- `kFAe` / `kFAd` are kept as compatibility aliases but are deprecated.
- The fwxaes raw format uses the FWX1 header and PBKDF2 + AES-256-GCM, with an
  optional normalize wrapper that hides bytes in zero-width Unicode markers.
- Live streaming uses packetized `LIVE` v1 AES-GCM frames and is cross-compatible
  with Python/Java `fwxAES_live_*` APIs.
- `fwxaes-live-enc` / `fwxaes-live-dec` accept `-` for stdin/stdout so they can be
  used in piping workflows (for example with `ffmpeg` audio/video streams).
- jMG media transcode can use optional FFmpeg hardware acceleration:
  set `BASEFWX_HWACCEL=nvenc` for NVIDIA (auto-detected fallback to CPU when unavailable).
- `jmge` now defaults to a key-only `JMG1` trailer in the CLI (smaller output, concealment-first, decode may not be byte-identical).
- Use `jmge --archive` when you explicitly want the encrypted original payload appended for exact restore.
- `--no-log` suppresses telemetry/progress/warnings while preserving primary outputs/errors.
- `--verbose` adds a hardware routing reason line.
- jMG video is temporarily disabled by default unless `BASEFWX_ENABLE_JMG_VIDEO=1`.
- Current C++ codec support covers b256/b512/pb512 plus b512file/pb512file
  (AES-heavy) and fwxaes. Argon2id + ML-KEM-768 support is enabled when the
  dependencies are installed.
- `fwxaes --heavy` and `fwxaes-heavy-*` use the same AES-heavy container
  as `pb512file-*` for consistent heavy-mode behavior across APIs.

## Dependencies

- OpenSSL (crypto) for HKDF, PBKDF2, AES-GCM.
- libargon2 for Argon2id KDF parity with Python defaults.
- liboqs for ML-KEM-768 master-key wrapping.
- zlib for baked key decoding.
- liblzma (xz) for tar.xz packing in `--compress` mode.

Quick install hints:

- Ubuntu/Debian: `sudo apt install libssl-dev libargon2-dev liboqs-dev zlib1g-dev liblzma-dev`
- Arch: `sudo pacman -S openssl argon2 liboqs zlib xz`
- macOS (brew): `brew install openssl@3 argon2 liboqs zlib xz`

## Library API quick refs

```cpp
#include "basefwx/basefwx.hpp"

// n10 API
std::string digits = basefwx::N10Encode("hello");
std::string text = basefwx::N10Decode(digits);

// kFM API (auto media/audio encode + strict decode)
std::string carrier = basefwx::Kfme("input.mp3", "input.png", true);
std::string restored = basefwx::Kfmd("input.png", "restored.mp3");

// jMG API
std::string media = basefwx::Jmge("input.mp4", "password", "out.mp4", false, false, true);
std::string media_small = basefwx::Jmge("input.mp4", "password", "out-small.mp4", false, false, false);

// Live stream API
std::ifstream src("input.bin", std::ios::binary);
std::ofstream live("out.live", std::ios::binary);
basefwx::FwxAesLiveEncryptStream(src, live, "password", false);
```
