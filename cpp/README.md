# BaseFWX C++

This C++ implementation is wire-compatible with BaseFWX 3.6.4 and provides the
current core CLI/library surface used in release builds. Active development
targets mathematically grounded, high-performance cryptographic primitives.

b256, A512, Bi512, Uhash513, jMG, kFM, and kFA are retired compatibility
codecs. Their implementations and commands are excluded from default builds
and live under `src/retired`. An explicit compatibility build restores the
established APIs and bytes; only security, correctness, and existing-data
compatibility fixes are planned.

## Build

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
```

To build a compatibility artifact for existing retired callers or data:

```bash
cmake -S cpp -B cpp/build-retired \
  -DBASEFWX_ENABLE_RETIRED_MEDIA=ON
cmake --build cpp/build-retired
./cpp/build-retired/basefwx version  # retired_media=ON
```

The default is `BASEFWX_ENABLE_RETIRED_MEDIA=OFF`; its archive and CLI contain
no retired symbols or command strings. `BASEFWX_HAS_RETIRED_MEDIA` is
published through both the CMake target and installed `pkg-config` metadata so
consumers can guard compatibility-only includes and calls.

Argon2 is required by default. liboqs is optional by default, so a plain build
silently omits ML-KEM if it is absent; release and Debian builds pass
`-DBASEFWX_REQUIRE_OQS=ON` to make that a configure error.

To permit a reduced-capability build when Argon2 or liboqs is unavailable (not
cross-compatible with those modes):

```bash
cmake -S cpp -B cpp/build -DBASEFWX_REQUIRE_ARGON2=OFF -DBASEFWX_REQUIRE_OQS=OFF
cmake --build cpp/build
```

These switches relax missing-backend errors; they do not disable a backend that
CMake finds. Use the generated capability macros to inspect the resulting
build.

## CLI (current)

```bash
./cpp/build/basefwx [global flags] <command> ...
# global flags: --verbose|-v --no-log --no-color
./cpp/build/basefwx info <file.fwx>
./cpp/build/basefwx n10-enc "hello"
./cpp/build/basefwx n10-dec "<digits>"
./cpp/build/basefwx n10file-enc secret.bin secret.n10
./cpp/build/basefwx n10file-dec secret.n10 secret.bin
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
```

Compatibility-build-only commands:

```bash
./cpp/build-retired/basefwx kFMe input.mp3 --out input.png --bw
./cpp/build-retired/basefwx kFMd input.png --out restored.mp3
./cpp/build-retired/basefwx jmge input.mp4 -p "pw" --out out-small.mp4
./cpp/build-retired/basefwx jmge input.mp4 -p "pw" --archive --out out-exact.mp4
```

`info`, `identify`, and `probe` recognize:

- BaseFWX length-prefixed containers
- `FWX1` fwxAES headers
- kFM PNG/WAV carriers, including legacy `kFAe` output, when the CLI was built
  with retired-media compatibility

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
- b512/pb512 text writers emit authenticated payload v3 with AES-256-GCM and
  canonical standard base64. Their distinct HKDF/AAD domains bind the visible
  version/length header. Unauthenticated v2 text payloads require the explicit
  trusted-recovery switch `BASEFWX_ALLOW_LEGACY_TEXT_V2=1`; token-map output is
  cosmetic and opt-in with `BASEFWX_OBFUSCATE_CODECS=1`.
- b512file writers require the outer AES-256-GCM container. The old
  `--no-aead` writer option is gone; raw historical input requires
  `BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1` for trusted recovery.
- Compatibility kFM carriers are byte-reversible across Python/C++/Java for
  BaseFWX-made files, including legacy raw-byte carriers.
- New encrypt operations reject passwords shorter than 10 UTF-8 bytes unless
  `BASEFWX_ALLOW_WEAK_PASSWORD=1` is set. `BASEFWX_MIN_PASSWORD_LEN=<n>`
  overrides the threshold, and `0` disables the check.
- Default user KDF targets are hardened to `PBKDF2=600000` / `Argon2id=4 x 64 MiB`, and heavy mode advertises `PBKDF2=2000000` / `Argon2id=6 x 256 MiB`.
- In compatibility builds, `kFMe` auto-detects source type:
  - audio input -> PNG carrier
  - non-audio input -> WAV carrier
- `kFMe` only emits `.png` or `.wav` carrier files; explicit mismatched output extensions are rejected.
- `kFMd` strictly decodes BaseFWX carriers and refuses non-carrier files.
- `kFAe` / `kFAd` are kept as compatibility aliases but are deprecated.
- The fwxaes raw format uses the FWX1 header with an AES-256-GCM payload. The
  content key is wrapped under Argon2id by default, or PBKDF2 when the Argon2
  backend is absent; `--legacy-pbkdf2` selects the historical direct-PBKDF2
  header. An optional normalize wrapper hides bytes in zero-width Unicode
  markers.
- Live streaming uses packetized `LIVE` v1 AES-GCM frames and is cross-compatible
  with Python/Java `fwxAES_live_*` APIs.
- `fwxaes-live-enc` / `fwxaes-live-dec` accept `-` for stdin/stdout so they can be
  used in piping workflows (for example with `ffmpeg` audio/video streams).
- Compatibility jMG media transcode can use optional FFmpeg hardware acceleration:
  set `BASEFWX_HWACCEL=nvenc` for NVIDIA (auto-detected fallback to CPU when unavailable).
- `jmge` now defaults to a key-only `JMG1` trailer in the CLI (smaller output, concealment-first, decode may not be byte-identical).
- Use `jmge --archive` when you explicitly want the encrypted original payload appended for exact restore.
- `--no-log` suppresses telemetry/progress/warnings while preserving primary outputs/errors.
- `--verbose` adds a hardware routing reason line.
- jMG video remains disabled by default;
  `BASEFWX_ENABLE_JMG_VIDEO=1` exists for compatibility use.
- Current C++ codec support covers b512/pb512 plus b512file/pb512file
  (AES-heavy) and fwxaes. Argon2id plus ML-KEM-768/1024 support is enabled
  only when the selected dependencies provide both ML-KEM parameter sets.
- `fwxaes --heavy` and `fwxaes-heavy-*` use the same AES-heavy container
  as `pb512file-*` for consistent heavy-mode behavior across APIs.

## Dependencies

- OpenSSL (crypto) for HKDF, PBKDF2, AES-GCM.
- libargon2 for Argon2id KDF parity with Python defaults.
- liboqs with ML-KEM-768 and ML-KEM-1024 enabled for master-key wrapping.
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

// Live stream API
std::ifstream src("input.bin", std::ios::binary);
std::ofstream live("out.live", std::ios::binary);
basefwx::FwxAesLiveEncryptStream(src, live, "password", false);
```

Compatibility-only APIs are declared when `BASEFWX_HAS_RETIRED_MEDIA` is true:

```cpp
#include "basefwx/basefwx.hpp"

#if BASEFWX_HAS_RETIRED_MEDIA
std::string historical = basefwx::B256Decode("<payload>");
std::string carrier = basefwx::Kfme("input.mp3", "input.png", true);
std::string restored = basefwx::Kfmd("input.png", "restored.mp3");
std::string media = basefwx::Jmge(
    "input.mp4", "password", "out.mp4", false, false, true);
#endif
```
