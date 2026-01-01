<h1 align="center">
<img src="src/ui/basefwx.svg" width="300">
</h1><br>

[![PyPI version](https://img.shields.io/pypi/v/basefwx)](https://pypi.org/project/basefwx/)
[![PyPI downloads](https://img.shields.io/pypi/dm/basefwx.svg?label=PyPI%20downloads)](https://pypi.org/project/basefwx/)
[![CI](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/ci.yml?label=CI)](https://github.com/F1xGOD/basefwx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/publish.yml?label=Release)](https://github.com/F1xGOD/basefwx/actions/workflows/publish.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/F1xGOD/basefwx/codeql.yml?label=CodeQL)](https://github.com/F1xGOD/basefwx/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/F1xGOD/basefwx?style=flat)](https://github.com/F1xGOD/basefwx/blob/main/LICENCE)
[![Discord](https://img.shields.io/discord/1130897522051788821?color=7289da&label=Discord&logo=discord&logoColor=ffffff)](https://discord.gg/3eRHYkjgk8)

BASEFWX is a hybrid post-quantum + AEAD encryption toolkit for files and media, with cross-compatible Python and C++ implementations.

- Website: https://www.fixcraft.jp and https://www.fixcraft.org
- Documentation: docs/CLI.md
- Source code: https://github.com/F1xGOD/basefwx
- Contributing: docs/CONTRIBUTING.md
- Bug reports: https://github.com/F1xGOD/basefwx/issues
- Report a security vulnerability: SECURITY.md

It provides:

- ML-KEM-768 master key wrapping (optional) and AES-GCM payload protection
- Password-based encryption with Argon2id or PBKDF2
- fwxAES file encryption with optional normalize wrapper
- b512/pb512 reversible encodings and file modes
- jMG media cipher for images, video, and audio with metadata control
- C++ library and CLI with Python and C++ format parity

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

- [Docs home (HTML)](https://github.com/F1xGOD/basefwx/blob/main/docs/index.html)
- [CLI and usage](https://github.com/F1xGOD/basefwx/blob/main/docs/CLI.md)
- [Security model](https://github.com/F1xGOD/basefwx/blob/main/docs/SECURITY_MODEL.md)
- [Testing and benchmarks](https://github.com/F1xGOD/basefwx/blob/main/docs/TESTING.md)
- [Release & signing](https://github.com/F1xGOD/basefwx/blob/main/docs/RELEASE.md)
- [Contributing and code of conduct](https://github.com/F1xGOD/basefwx/blob/main/docs/CONTRIBUTING.md)

License
-------

See https://github.com/F1xGOD/basefwx/blob/main/LICENCE.
