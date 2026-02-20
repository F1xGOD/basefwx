# basefwx C++ port (WIP)

This folder is the start of a C++ rewrite intended to stay wire-compatible with
BaseFWX 3.6.2. The initial focus is shared codecs (b256/b512/pb512) and
file-format parsing so we can inspect payloads and validate blob structure before
porting the full AES file pipeline.

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
./cpp/build/basefwx_cpp info <file.fwx>
./cpp/build/basefwx_cpp b256-enc "hello"
./cpp/build/basefwx_cpp b256-dec "<payload>"
./cpp/build/basefwx_cpp n10-enc "hello"
./cpp/build/basefwx_cpp n10-dec "<digits>"
./cpp/build/basefwx_cpp n10file-enc secret.bin secret.n10
./cpp/build/basefwx_cpp n10file-dec secret.n10 secret.bin
./cpp/build/basefwx_cpp kFMe input.bin --out input.wav
./cpp/build/basefwx_cpp kFMe input.mp3 --out input.png --bw
./cpp/build/basefwx_cpp kFMd input.wav --out restored.bin
./cpp/build/basefwx_cpp kFMd input.png --out restored.mp3
./cpp/build/basefwx_cpp kFAe input.mp3 --out input.png --bw   # deprecated alias
./cpp/build/basefwx_cpp kFAd input.png --out restored.mp3     # deprecated alias
./cpp/build/basefwx_cpp b512-enc "hello" -p "pw"
./cpp/build/basefwx_cpp b512-dec "<payload>" -p "pw"
./cpp/build/basefwx_cpp pb512-enc "hello" -p "pw"
./cpp/build/basefwx_cpp pb512-dec "<payload>" -p "pw"
./cpp/build/basefwx_cpp b512file-enc secret.bin -p "pw"
./cpp/build/basefwx_cpp b512file-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx_cpp pb512file-enc secret.bin -p "pw"
./cpp/build/basefwx_cpp pb512file-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx_cpp fwxaes-enc secret.bin -p "pw" --normalize
./cpp/build/basefwx_cpp fwxaes-dec secret.bin.fwx -p "pw"
./cpp/build/basefwx_cpp fwxaes-live-enc secret.bin -p "pw" --out secret.live.fwx
./cpp/build/basefwx_cpp fwxaes-live-dec secret.live.fwx -p "pw" --out secret.bin
ffmpeg -hide_banner -loglevel error -i input.m4a -vn -ac 1 -ar 16000 -f wav pipe:1 \
  | ./cpp/build/basefwx_cpp fwxaes-live-enc - -p "pw" --no-master --out - \
  | ./cpp/build/basefwx_cpp fwxaes-live-dec - -p "pw" --no-master --out - > restored.wav
./cpp/build/basefwx_cpp jmge input.mp4 -p "pw" --no-archive --out out-small.mp4
```

This prints the length-prefixed sections and attempts to decode metadata if the
payload matches the AES file format.

## Compatibility notes

- The AEAD blob format is: 4-byte len + user blob, 4-byte len + master blob,
  4-byte len + payload blob.
- The AES payload starts with 4-byte metadata length, followed by base64-encoded
  JSON metadata, followed by ciphertext.
- The b512 AEAD payload is fully encrypted, so metadata cannot be parsed without
  decryption.
- kFM carriers are byte-reversible across Python/C++/Java for BaseFWX-made files.
- `kFMe` auto-detects source type:
  - audio input -> PNG carrier
  - non-audio input -> WAV carrier
- `kFMd` strictly decodes BaseFWX carriers and refuses non-carrier files.
- `kFAe` / `kFAd` are kept as compatibility aliases but are deprecated.
- The fwxaes raw format uses the FWX1 header and PBKDF2 + AES-256-GCM, with an
  optional normalize wrapper that hides bytes in zero-width Unicode markers.
- Live streaming uses packetized `LIVE` v1 AES-GCM frames and is cross-compatible
  with Python/Java `fwxAES_live_*` APIs.
- `fwxaes-live-enc` / `fwxaes-live-dec` accept `-` for stdin/stdout so they can be
  used in piping workflows (for example with `ffmpeg` audio/video streams).
- `jmge --no-archive` stores a key-only `JMG1` trailer (smaller output, but decode
  may not be byte-identical to the source media).
- Current C++ codec support covers b256/b512/pb512 plus b512file/pb512file
  (AES-heavy) and fwxaes. Argon2id + ML-KEM-768 support is enabled when the
  dependencies are installed.

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

## Next steps

- Expand CLI flags for argon2 tuning and streaming thresholds if needed.

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
