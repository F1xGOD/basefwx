---
layout: doc
title: CLI
permalink: /docs/CLI/
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
- `--no-archive` jMG mode: skip embedded full-payload archive (Python default)
- `--archive` jMG mode: embed full-payload archive for exact restore

Examples:

```
python -m basefwx cryptin aes-light secret.bin -p "pass" --strip
python -m basefwx cryptin aes-light secret.bin.fwx -p "pass"

python -m basefwx cryptin fwxaes photo.jpg -p "pass"
python -m basefwx cryptin fwxaes video.mp4 -p "pass" --keep-meta
python -m basefwx cryptin fwxaes video.mp4 -p "pass"            # default no-archive
python -m basefwx cryptin fwxaes video.mp4 -p "pass" --archive  # exact-restore trailer
```

n10 helpers:

```
python -m basefwx n10-enc "hello"
python -m basefwx n10-dec "<digits>"
python -m basefwx n10file-enc in.bin out.n10
python -m basefwx n10file-dec out.n10 restored.bin
```

kFM carrier commands:

```
python -m basefwx kFMe input.png -o input.wav
python -m basefwx kFMe input.mp3 -o input.png --bw
python -m basefwx kFMd input.wav -o restored.png
python -m basefwx kFMd input.png -o restored.mp3
```

Master key usage (master-only payloads):

```
export BASEFWX_MASTER_PQ_PUB=/secure/mlkem768.pub
python -m basefwx cryptin aes-heavy payload.bin -p ""
```

Notes:

- If a password string resolves to an existing file path, the file contents are used as the password.
- PQ private key lookup defaults to `~/master_pq.sk` (or `W:\master_pq.sk` on Windows).
- `kFMe` auto-detects source type (audio -> PNG, non-audio -> WAV).
- `kFMd` strictly decodes BaseFWX carriers only.
- `kFAe`/`kFAd` are deprecated compatibility aliases.
- Python jMG HW accel policy: NVIDIA (`nvenc`) -> Intel (`qsv`) -> VAAPI -> CPU.
- Set `BASEFWX_HWACCEL_STRICT=1` to fail instead of CPU fallback when the requested accelerator cannot be used.

## Python API

Streaming (fwxAES):

```
from basefwx import fwxAES_encrypt_stream, fwxAES_decrypt_stream

with open("input.bin", "rb") as src, open("output.fwx", "wb") as dst:
    fwxAES_encrypt_stream(src, dst, "password", use_master=False)

with open("output.fwx", "rb") as src, open("decoded.bin", "wb") as dst:
    fwxAES_decrypt_stream(src, dst, "password", use_master=False)
```

Live packetized streaming (transport-agnostic):

```
from basefwx import LiveEncryptor, LiveDecryptor
from basefwx import fwxAES_live_encrypt_stream, fwxAES_live_decrypt_stream

enc = LiveEncryptor("password", use_master=False)
dec = LiveDecryptor("password", use_master=False)

packets = [enc.start(), enc.update(b"frame-1"), enc.update(b"frame-2"), enc.finalize()]
restored = []
for packet in packets:
    restored.extend(dec.update(packet))
dec.finalize()

with open("input.bin", "rb") as src, open("live.enc", "wb") as dst:
    fwxAES_live_encrypt_stream(src, dst, "password", use_master=False)
with open("live.enc", "rb") as src, open("live.out", "wb") as dst:
    fwxAES_live_decrypt_stream(src, dst, "password", use_master=False)
```

Live ffmpeg bridge helpers:

```
from basefwx import fwxAES_live_encrypt_ffmpeg, fwxAES_live_decrypt_ffmpeg

fwxAES_live_encrypt_ffmpeg(
    ["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", "input.mp4", "-f", "matroska", "-c", "copy", "-"],
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

Bytes helpers for b512/pb512 file containers:

```
from basefwx import b512file_encode_bytes, b512file_decode_bytes
from basefwx import pb512file_encode_bytes, pb512file_decode_bytes

blob = b512file_encode_bytes(data, ".bin", "password", use_master=False)
plain, ext = b512file_decode_bytes(blob, "password", use_master=False)

blob = pb512file_encode_bytes(data, ".bin", "password", use_master=False)
plain, ext = pb512file_decode_bytes(blob, "password", use_master=False)
```

n10 and kFM helpers:

```
from basefwx import n10encode, n10decode, n10encode_bytes, n10decode_bytes
from basefwx import kFMe, kFMd

digits = n10encode("hello")
text = n10decode(digits)
blob_digits = n10encode_bytes(b"\x00\x01\x02")
blob = n10decode_bytes(blob_digits)

carrier = kFMe("input.mp3", output="input.png", bw_mode=True)
restored = kFMd("input.png", output="restored.mp3")
```

Media helpers:

```
from basefwx import jMGe, jMGd
jMGe("input.mp4", "password", output="out-small.mp4")  # default no-archive
jMGe("input.mp4", "password", output="out.mp4", archive_original=True)
jMGd("out-small.mp4", "password", output="plain.mp4")  # may not be byte-identical
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
cpp/build/basefwx_cpp fwxaes-live-enc <file> -p <password> [--out <path>]
cpp/build/basefwx_cpp fwxaes-live-dec <file> -p <password> [--out <path>]
cpp/build/basefwx_cpp n10-enc <text>
cpp/build/basefwx_cpp n10-dec <digits>
cpp/build/basefwx_cpp n10file-enc <in-file> <out-file>
cpp/build/basefwx_cpp n10file-dec <in-file> <out-file>
cpp/build/basefwx_cpp kFMe <in-file> [--out <path>] [--bw]
cpp/build/basefwx_cpp kFMd <carrier-file> [--out <path>] [--bw]
cpp/build/basefwx_cpp kFAe <in-file> [--out <path>] [--bw]   # deprecated alias
cpp/build/basefwx_cpp kFAd <carrier-file> [--out <path>]     # deprecated alias

cpp/build/basefwx_cpp b512-enc <text> -p <password>
cpp/build/basefwx_cpp b512-dec <text> -p <password>
cpp/build/basefwx_cpp pb512-enc <text> -p <password>
cpp/build/basefwx_cpp pb512-dec <text> -p <password>

cpp/build/basefwx_cpp b512file-enc <file> -p <password>
cpp/build/basefwx_cpp b512file-dec <file.fwx> -p <password>
cpp/build/basefwx_cpp pb512file-enc <file> -p <password>
cpp/build/basefwx_cpp pb512file-dec <file.fwx> -p <password>

cpp/build/basefwx_cpp jmge <media> [-p <password>] [--master-pub <path>] [--out <path>] [--no-archive]
cpp/build/basefwx_cpp jmgd <media> [-p <password>] [--out <path>]
```

Master-only media encryption (C++):

```
cpp/build/basefwx_cpp jmge input.mp4 --master-pub /secure/mlkem768.pub --out out.mp4
```

Notes:

- `jmge --no-archive` writes a key-only `JMG1` trailer (smaller output, decode may not be byte-identical).
- `fwxaes-live-*` implements the packetized `LIVE` v1 stream format used by Python/Java.
- `fwxaes-live-*` supports `-` for stdin/stdout, so you can pipe media streams (for example with `ffmpeg`).
- Optional NVIDIA acceleration for jMG: set `BASEFWX_HWACCEL=nvenc` (auto fallback to CPU if unavailable).

Example live audio pipe (C++):

```bash
ffmpeg -hide_banner -loglevel error -i input.m4a -vn -ac 1 -ar 16000 -f wav pipe:1 \
  | cpp/build/basefwx_cpp fwxaes-live-enc - -p password --no-master --out - \
  | cpp/build/basefwx_cpp fwxaes-live-dec - -p password --no-master --out - > restored.wav
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

Live packet stream:

```
#include "basefwx/basefwx.hpp"

std::ifstream src("input.bin", std::ios::binary);
std::ofstream live("output.live", std::ios::binary);
basefwx::FwxAesLiveEncryptStream(src, live, "password", false);

std::ifstream live_in("output.live", std::ios::binary);
std::ofstream plain("restored.bin", std::ios::binary);
basefwx::FwxAesLiveDecryptStream(live_in, plain, "password", false);
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

n10 and kFM helpers:

```
#include "basefwx/basefwx.hpp"

std::string digits = basefwx::N10Encode("hello");
std::string text = basefwx::N10Decode(digits);

std::string carrier = basefwx::Kfme("input.mp3", "input.png", true);
std::string restored = basefwx::Kfmd("input.png", "restored.mp3");
```

## Java CLI

```
java -jar build/libs/basefwx-java.jar fwxaes-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-live-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-live-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar n10-enc <text>
java -jar build/libs/basefwx-java.jar n10-dec <digits>
java -jar build/libs/basefwx-java.jar n10file-enc <in> <out>
java -jar build/libs/basefwx-java.jar n10file-dec <in> <out>
java -jar build/libs/basefwx-java.jar kFMe <in> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFMd <carrier> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFAe <in> [--out <out>] [--bw]   # deprecated alias
java -jar build/libs/basefwx-java.jar kFAd <carrier> [--out <out>]     # deprecated alias

java -jar build/libs/basefwx-java.jar b512-enc <text> <password>
java -jar build/libs/basefwx-java.jar b512-dec <text> <password>
java -jar build/libs/basefwx-java.jar pb512-enc <text> <password>
java -jar build/libs/basefwx-java.jar pb512-dec <text> <password>

java -jar build/libs/basefwx-java.jar b512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar b512file-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar pb512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar pb512file-dec <in> <out> <password>

java -jar build/libs/basefwx-java.jar jmge <in> <out> <password> [--no-archive]
java -jar build/libs/basefwx-java.jar jmgd <in> <out> <password>
```

Notes:

- jMG media requires `ffmpeg` and `ffprobe` to be available on PATH.
- `jmge` supports `--keep-meta`, `--keep-input`, and `--no-archive`.
- `--no-archive` writes a key-only `JMG1` trailer (smaller output, but restore may not be byte-identical).
- `kFMd` strictly decodes BaseFWX carriers and refuses plain files.
- The Java module does not include ML-KEM or Argon2 support yet.

## Java API

```
import com.fixcraft.basefwx.BaseFwx;

try (InputStream in = new FileInputStream("input.bin");
     OutputStream out = new FileOutputStream("output.fwx")) {
    BaseFwx.fwxAesEncryptStream(in, out, "password", false);
}

byte[] blob = BaseFwx.b512FileEncodeBytes(data, ".bin", "password", false);
BaseFwx.DecodedFile decoded = BaseFwx.b512FileDecodeBytes(blob, "password", false);

BaseFwx.jmgEncryptFile(new File("input.mp4"), new File("out.mp4"), "password", true, false, true);
BaseFwx.jmgDecryptFile(new File("out.mp4"), new File("plain.mp4"), "password", true);
BaseFwx.jmgEncryptFile(new File("input.mp4"), new File("out-small.mp4"), "password", true, false, true, false);

try (InputStream in = new FileInputStream("input.bin");
     OutputStream out = new FileOutputStream("output.live")) {
    BaseFwx.fwxAesLiveEncryptStream(in, out, "password", false);
}
try (InputStream in = new FileInputStream("output.live");
     OutputStream out = new FileOutputStream("restored.bin")) {
    BaseFwx.fwxAesLiveDecryptStream(in, out, "password", false);
}

String digits = BaseFwx.n10Encode("hello");
String text = BaseFwx.n10Decode(digits);

File carrier = BaseFwx.kFMe(new File("input.mp3"), new File("input.png"), true);
File restored = BaseFwx.kFMd(new File("input.png"), new File("restored.mp3"));
```
