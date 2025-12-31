# basefwx C++ port (WIP)

This folder is the start of a C++ rewrite intended to stay wire-compatible with
BaseFWX 3.4.1. The initial focus is shared codecs (b256/b512/pb512) and
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
- The fwxaes raw format uses the FWX1 header and PBKDF2 + AES-256-GCM, with an
  optional normalize wrapper that hides bytes in zero-width Unicode markers.
- Current C++ codec support covers b256/b512/pb512 plus b512file/pb512file
  (AES-heavy) and fwxaes. Argon2id + ML-KEM-768 support is enabled when the
  dependencies are installed.

## Dependencies

- OpenSSL (crypto) for HKDF, PBKDF2, AES-GCM.
- libargon2 for Argon2id KDF parity with Python defaults.
- liboqs for ML-KEM-768 master-key wrapping.
- zlib for baked key decoding.

Quick install hints:

- Ubuntu/Debian: `sudo apt install libssl-dev libargon2-dev liboqs-dev zlib1g-dev`
- Arch: `sudo pacman -S openssl argon2 liboqs zlib`
- macOS (brew): `brew install openssl@3 argon2 liboqs zlib`

## Next steps

- Expand CLI flags for argon2 tuning and streaming thresholds if needed.
