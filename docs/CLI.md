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

Streaming (fwxAES):

```
from basefwx import fwxAES_encrypt_stream, fwxAES_decrypt_stream

with open("input.bin", "rb") as src, open("output.fwx", "wb") as dst:
    fwxAES_encrypt_stream(src, dst, "password", use_master=False)

with open("output.fwx", "rb") as src, open("decoded.bin", "wb") as dst:
    fwxAES_decrypt_stream(src, dst, "password", use_master=False)
```

Bytes helpers for b512/pb512 file containers:

```
from basefwx import b512file_encode_bytes, b512file_decode_bytes
from basefwx import pb512file_encode_bytes, pb512file_decode_bytes

blob = b512file_encode_bytes(data, ".bin", "password", use_master=False)
plain, ext = b512file_decode_bytes(blob, "password", use_master=False)

blob = pb512file_encode_bytes(data, ".bin", "password", use_master=False)
plain, ext = pb512file_decode_bytes(blob, "password", use_master=False)
```

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
cpp/build/basefwx_cpp fwxaes-stream-enc <file> -p <password> [--out <path>]
cpp/build/basefwx_cpp fwxaes-stream-dec <file> -p <password> [--out <path>]

cpp/build/basefwx_cpp b512-enc <text> -p <password>
cpp/build/basefwx_cpp b512-dec <text> -p <password>
cpp/build/basefwx_cpp pb512-enc <text> -p <password>
cpp/build/basefwx_cpp pb512-dec <text> -p <password>

cpp/build/basefwx_cpp b512file-enc <file> -p <password>
cpp/build/basefwx_cpp b512file-dec <file.fwx> -p <password>
cpp/build/basefwx_cpp pb512file-enc <file> -p <password>
cpp/build/basefwx_cpp pb512file-dec <file.fwx> -p <password>

cpp/build/basefwx_cpp jmge <media> [-p <password>] [--master-pub <path>] [--out <path>]
cpp/build/basefwx_cpp jmgd <media> [-p <password>] [--out <path>]
```

Master-only media encryption (C++):

```
cpp/build/basefwx_cpp jmge input.mp4 --master-pub /secure/mlkem768.pub --out out.mp4
```

## C++ API

Streaming (fwxAES):

```
#include "basefwx/fwxaes.hpp"

std::ifstream in("input.bin", std::ios::binary);
std::ofstream out("output.fwx", std::ios::binary);
basefwx::fwxaes::Options opts;
opts.use_master = false;
basefwx::fwxaes::EncryptStream(in, out, "password", opts);
```

Bytes helpers for b512/pb512 file containers:

```
#include "basefwx/filecodec.hpp"

basefwx::filecodec::FileOptions file_opts;
file_opts.use_master = false;
auto blob = basefwx::filecodec::B512EncodeBytes(data, ".bin", "password", file_opts);
auto decoded = basefwx::filecodec::B512DecodeBytes(blob, "password", file_opts);

auto blob2 = basefwx::filecodec::Pb512EncodeBytes(data, ".bin", "password", file_opts);
auto decoded2 = basefwx::filecodec::Pb512DecodeBytes(blob2, "password", file_opts);
```

## Java CLI

```
java -jar build/libs/basefwx-java.jar fwxaes-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-dec <in> <out> <password>

java -jar build/libs/basefwx-java.jar b512-enc <text> <password>
java -jar build/libs/basefwx-java.jar b512-dec <text> <password>
java -jar build/libs/basefwx-java.jar pb512-enc <text> <password>
java -jar build/libs/basefwx-java.jar pb512-dec <text> <password>

java -jar build/libs/basefwx-java.jar b512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar b512file-dec <in> <out> <password>
```

Notes:

- AES-heavy file containers (pb512file) and jMG are not implemented in the Java module yet.

## Java API

```
import com.fixcraft.basefwx.BaseFwx;

try (InputStream in = new FileInputStream("input.bin");
     OutputStream out = new FileOutputStream("output.fwx")) {
    BaseFwx.fwxAesEncryptStream(in, out, "password", false);
}

byte[] blob = BaseFwx.b512FileEncodeBytes(data, ".bin", "password", false);
BaseFwx.DecodedFile decoded = BaseFwx.b512FileDecodeBytes(blob, "password", false);
```
