<h1 align="center">
<img src="https://raw.githubusercontent.com/f1xgod/basefwx/main/src/ui/basefwx.svg" width="300">
</h1><br>

[![PyPI version](https://img.shields.io/pypi/v/basefwx)](https://pypi.org/project/basefwx/)
[![PyPI downloads](https://img.shields.io/pypi/dm/basefwx.svg?label=PyPI%20downloads)](https://pypi.org/project/basefwx/)
[![CI](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/ci.yml?label=CI)](https://github.com/F1xGOD/basefwx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/publish.yml?label=Release)](https://github.com/F1xGOD/basefwx/actions/workflows/publish.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/codeql.yml?label=CodeQL)](https://github.com/F1xGOD/basefwx/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat)](https://github.com/F1xGOD/basefwx/blob/main/LICENCE)
[![Discord](https://img.shields.io/discord/1130897522051788821?color=7289da&label=Discord&logo=discord&logoColor=ffffff)](https://discord.gg/3eRHYkjgk8)

BASEFWX is a hybrid post-quantum + AEAD encryption toolkit for files and media, with cross-compatible Python and C++ implementations.

- Website: https://basefwx.fixcraft.jp
- Documentation: https://basefwx.fixcraft.jp/docs/CLI.html
- Source code: https://github.com/F1xGOD/basefwx
- Contributing: https://basefwx.fixcraft.jp/docs/CONTRIBUTING.html
- Bug reports: https://github.com/F1xGOD/basefwx/issues
- Report a security vulnerability: https://basefwx.fixcraft.jp/docs/SECURITY_MODEL.html

It provides:

- ML-KEM-768 master key wrapping (optional) and AES-GCM payload protection
- Password-based encryption with Argon2id or PBKDF2
- fwxAES file encryption with optional normalize wrapper
- b512/pb512 reversible encodings and file modes
- jMG media cipher for images, video, and audio with metadata control
- C++ library and CLI with Python and C++ format parity
- Java (JVM) library and CLI for cross-compatible fwxAES/b512/pb512/b256/jMG

Quick Start
-----------

```bash
pip install basefwx
python -m basefwx cryptin aes-light file.bin -p "password" --strip
python -m basefwx cryptin aes-light file.bin.fwx -p "password"
```

Optional extras:

```bash
pip install basefwx[argon2]
```

Documentation
-------------

- [Docs home (HTML)](https://basefwx.fixcraft.jp)
- [CLI and usage](https://basefwx.fixcraft.jp/docs/CLI.html)
- [Security model](https://basefwx.fixcraft.jp/docs/SECURITY_MODEL.html)
- [Testing and benchmarks](https://basefwx.fixcraft.jp/docs/TESTING.html)
- [Release & signing](https://basefwx.fixcraft.jp/docs/RELEASE.html)
- [Contributing and code of conduct](https://basefwx.fixcraft.jp/docs/CONTRIBUTING.html)
- [Java module](https://basefwx.fixcraft.jp/docs/CLI.html#java-cli)

License
-------

See https://basefwx.fixcraft.jp/LICENCE.
