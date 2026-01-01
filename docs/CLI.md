---
layout: doc
title: CLI
---

# CLI

## Python CLI

```
python -m basefwx cryptin <method> <paths...> [flags]
```

Methods (aliases in parentheses):

- `fwxaes` (file mode with optional media auto-detect)
- `b512` (`512`, `fwx512`)
- `aes-light` (`aes`, `256`, `light`)
- `aes-heavy` (`pb512`, `aes512`, `heavy`)

Common flags:

- `-p`, `--password` password text or a file path (empty means "master-only")
- `--no-master` disable master key wrapping and recovery
- `--use-master-pub <path>` ML-KEM-768 public key for master wrapping
- `--strip` or `--trim` remove internal metadata from payload
- `--no-obf` disable size-preserving obfuscation
- `--compress` pack folders/files to tar before encrypting (auto-unpack on decrypt)
- `--keep-input` do not delete the input after encrypting

fwxAES-only flags:

- `--normalize` wrap output in a zero-width cover text (small files only)
- `--normalize-threshold <bytes>` max plaintext bytes for normalize
- `--cover-phrase <text>` cover phrase for normalize
- `--ignore-media` disable media auto-detection (use normal fwxAES)
- `--keep-meta` keep media metadata (encrypted) when using jMG

Examples:

```
python -m basefwx cryptin aes-light secret.bin -p "pass" --strip
python -m basefwx cryptin aes-light secret.bin.fwx -p "pass"

python -m basefwx cryptin fwxaes photo.jpg -p "pass"
python -m basefwx cryptin fwxaes video.mp4 -p "pass" --keep-meta
```

Master key usage (master-only payloads):

```
export BASEFWX_MASTER_PQ_PUB=/secure/mlkem768.pub
python -m basefwx cryptin aes-heavy payload.bin -p ""
```

Notes:

- If a password string resolves to an existing file path, the file contents are used as the password.
- PQ private key lookup defaults to `~/master_pq.sk` (or `W:\master_pq.sk` on Windows).

## Python API

Media helpers:

```
from basefwx import jMGe, jMGd
jMGe("input.mp4", "password", output="out.mp4")
jMGd("out.mp4", "password", output="plain.mp4")
```

Use an empty password to rely on the master key only (requires the private key to be available).

## C++ CLI

Build:

```
cmake -S cpp -B cpp/build
cmake --build cpp/build
```

Usage:

```
cpp/build/basefwx_cpp fwxaes-enc <file> -p <password> [--out <path>]
cpp/build/basefwx_cpp fwxaes-dec <file> -p <password> [--out <path>]

cpp/build/basefwx_cpp jmge <media> [-p <password>] [--master-pub <path>] [--out <path>]
cpp/build/basefwx_cpp jmgd <media> [-p <password>] [--out <path>]
```

Master-only media encryption (C++):

```
cpp/build/basefwx_cpp jmge input.mp4 --master-pub /secure/mlkem768.pub --out out.mp4
```
