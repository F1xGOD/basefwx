# BaseFWX

BaseFWX is an authenticated-encryption library and command-line tool for C++,
Python, and Java. The maintained runtimes share the same file, text, and live
stream formats.

The version of this checkout is stored in [VERSION](VERSION). A development
checkout may be newer than the latest published release. Only the latest
release receives security and bug fixes.

- Website and downloads: <https://basefwx.fixcraft.jp>
- Source: <https://github.com/F1xGOD/basefwx>
- Issues: <https://github.com/F1xGOD/basefwx/issues>
- Security reports: [SECURITY.md](SECURITY.md)

## Maintained formats

- `fwxAES` encrypts files and byte streams with AES-256-GCM.
- `b512` and `pb512` write authenticated text and file containers.
- The live stream API authenticates ordered packets for use inside a transport
  or media pipe.
- `n10` is a reversible numeric encoding. It is not encryption.

BaseFWX can derive password keys with Argon2id or PBKDF2. An optional master
recovery path wraps a random content key with ML-KEM-768 or ML-KEM-1024.
Password and master recovery are independent unlock paths when both are
present.

BaseFWX does not implement an “AES-512” cipher. Historical `aes512` names are
aliases for a heavier KDF profile around AES-256-GCM.

The size-preserving obfuscation step can remove obvious plaintext structure,
but it is not a substitute for encryption. The AEAD tag is what authenticates
the payload and its bound metadata.

## Install and try the Python CLI

```bash
python -m pip install basefwx
python -m basefwx cryptin aes-light file.bin -p "correct-horse-battery"
python -m basefwx cryptin aes-light file.bin.fwx -p "correct-horse-battery"
```

For unattended use, load the password from an owner-readable file instead of
putting it in the process arguments:

```bash
python -m basefwx cryptin fwxaes file.bin \
  -p file://$HOME/.config/basefwx/password
```

New encryption rejects passwords shorter than the configured minimum. An
environment switch can lower that check for controlled compatibility work, but
it should not be a deployment default. See [SECURITY.md](SECURITY.md).

## Python streaming example

```python
from basefwx import fwxAES_encrypt_stream, fwxAES_decrypt_stream

with open("input.bin", "rb") as source, open("output.fwx", "wb") as target:
    fwxAES_encrypt_stream(source, target, "correct-horse-battery")

with open("output.fwx", "rb") as source, open("restored.bin", "wb") as target:
    fwxAES_decrypt_stream(source, target, "correct-horse-battery")
```

Use `LiveEncryptor` and `LiveDecryptor` when the caller needs authenticated,
ordered packets instead of a complete file. The live format does not provide
retransmission, jitter buffering, or clock synchronization. Those belong to
the transport around it.

## C++ and Java

The C++ library and CLI build with CMake:

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --parallel
ctest --test-dir cpp/build --output-on-failure
```

The Java module builds with Gradle:

```bash
cd java
gradle test
gradle jar
```

The [CLI reference](https://basefwx.fixcraft.jp/docs/CLI/) has C++, Python,
and Java commands and API examples. [COMPATIBILITY.md](COMPATIBILITY.md) states
which algorithms and containers are byte-compatible across runtimes.

## Compatibility and recovery

The default artifacts contain the maintained formats only. Historical
b256/A512/Bi512/Uhash513 text methods and the kFM/kFA/jMG media paths are
available only in an explicitly built recovery profile. Use that profile to
read existing data, then re-encrypt it with a maintained format.

Legacy recovery switches are opt-in and should be scoped to trusted old data:

- unauthenticated text payload v2
- raw historical b512file input
- legacy AES-CBC decryption
- retired media and text codecs

Authentication failure in a recognized current container does not fall back to
a legacy parser. [COMPATIBILITY.md](COMPATIBILITY.md) lists the exact switches
and [SECURITY.md](SECURITY.md) explains their risk.

The general C++ library follows a pre-stable source-compatibility policy. The
plugin ABI has its own frozen C contract. Native consumers must read
[ABI.md](ABI.md) before depending on either boundary.

## Documentation

- [BaseFWX explained](docs/EXPLAINED.md)
- [CLI and API reference](https://basefwx.fixcraft.jp/docs/CLI/)
- [Security model](https://basefwx.fixcraft.jp/docs/SECURITY_MODEL/)
- [Compatibility](COMPATIBILITY.md)
- [Native and plugin ABI](ABI.md)
- [Testing](https://basefwx.fixcraft.jp/docs/TESTING/)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Public automation context is isolated under [docs/agents/](docs/agents/).
It is not required to use the library.

## License

BaseFWX uses a split license. The core library, runtime APIs, and plugin ABI/SPI
are LGPL-3.0-or-later. Standalone tools, CLIs, benchmarks, and project scripts
are GPL-3.0-or-later. Example plugin templates are MIT OR Apache-2.0.

See [LICENSING.md](LICENSING.md) and [LICENSES/](LICENSES/) for the exact terms.
