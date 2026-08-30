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

- `fwxaes` (file mode)
- `b512` (`512`, `fwx512`)
- `aes-light` (`aes`, `256`, `light`)
- `aes-heavy` (`pb512`, `aes512`, `heavy`)
  `aes512` is a legacy alias; the cipher remains AES-256-GCM.

Current `b512`/`pb512` text writers emit authenticated payload v3 as canonical
standard base64. Use `BASEFWX_ALLOW_LEGACY_TEXT_V2=1` only to recover trusted
v2 text. `b512file` writers always use the outer AES-256-GCM container; raw
historical input requires `BASEFWX_ALLOW_LEGACY_B512FILE_RAW=1` for trusted
recovery. The former C++ `--no-aead` writer option is no longer available.

Common flags:

- `-p`, `--password` literal password text, `file://<path>`, or empty only
  with `--use-master` and a configured master public key
- `--use-master` enable master key wrapping and recovery (off by default)
- `--no-master` explicitly disable master key wrapping and recovery
- `--use-master-pub <path>` ML-KEM-768 or ML-KEM-1024 public key to use
  with `--use-master`
- `--strip` or `--trim` remove internal metadata from payload
- `--no-obf` disable size-preserving obfuscation
- `--compress` pack folders/files to tar before encrypting (auto-unpack on decrypt)
- `--keep-input` do not delete the input after encrypting

fwxAES-only flags:

- `--normalize` wrap output in a zero-width cover text (small files only)
- `--normalize-threshold <bytes>` max plaintext bytes for normalize
- `--cover-phrase <text>` cover phrase for normalize

`--ignore-media`, `--keep-meta`, `--archive`, and `--no-archive` belong to the
retired media path. A default build has no media auto-detection, so
`--ignore-media` does nothing and the other three fail with an error naming the
compatibility switch. See [Retired media commands](#retired-media-commands).

Examples:

```
python -m basefwx cryptin aes-light secret.bin -p "correct-horse-battery" --strip
python -m basefwx cryptin aes-light secret.bin.fwx -p "correct-horse-battery"

python -m basefwx cryptin fwxaes photo.jpg -p "correct-horse-battery"
python -m basefwx cryptin fwxaes track.m4a -p "correct-horse-battery"
```

`--strip` is not available when b512 or AES-heavy file encryption selects the
streaming container. The stream marker is required for unambiguous decode
dispatch, so the encoder rejects that combination before creating output.

n10 helpers:

```
python -m basefwx n10-enc "hello"
python -m basefwx n10-dec "<digits>"
python -m basefwx n10file-enc in.bin out.n10
python -m basefwx n10file-dec out.n10 restored.bin
```

Master key usage (master-only payloads):

```
export BASEFWX_MASTER_PQ_PUB=/secure/mlkem768.pub
python -m basefwx cryptin aes-heavy payload.bin -p "" --use-master
```

Notes:

- Passwords are literal by default in C++, Java, and Python. To load a
  password from a file, use an explicit `file://<path>` URI (`~/` expands).
  Use `password://<literal>` to force a literal string that happens to
  contain `://`. Bare strings are never interpreted as file paths.
- PQ private key lookup uses `BASEFWX_MASTER_PQ_SK` when set, otherwise `~/master_pq.sk`.
- Set `BASEFWX_PQ_STRICT` (or `BASEFWX_PQ_ONLY`) to `1`, `true`, `yes`,
  or `on` (case-insensitive) to disable EC fallback and require ML-KEM
  for a requested master wrap. On decrypt, an intact independent
  password wrap remains usable even if master recovery is unavailable
  or rejected by strict policy.
- Set `BASEFWX_MASTER_PQ_ALG=ml-kem-1024` (or `BASEFWX_PQ_MAX=1`) to opt
  key generation and default capability reporting into the larger ML-KEM
  parameter set. A provisioned public key's actual size selects 768 versus
  1024 for wrapping and authenticated `ENC-KEM` metadata; recovery selects
  by private-key/ciphertext size. Default generation remains `ml-kem-768`.
  Upstream ships with
  **no** baked master public key — provision via `BASEFWX_MASTER_PQ_PUB`
  or a build-time `-DBASEFWX_MASTER_PQ_PUB_B64=…` /
  `-Dbasefwx.master.pq.public.b64=…` opt-in.
- Explicit-salt HKDF and X25519 helpers are public multi-lang APIs
  (C++ `HkdfSha256`/`x25519`, Java `Crypto.hkdfSha256`/`X25519`,
  Python `basefwx.hkdf_sha256(salt=…)` / `basefwx.x25519`). They are not wired
  into fwxAES file formats.
- C++ `info` / `identify` / `probe` recognize length-prefixed containers and
  `FWX1` headers. A compatibility build also recognizes kFM PNG/WAV carriers,
  including legacy `kFAe` output.
- When a file is not recognized as BaseFWX, the C++ CLI reports a heuristic guess (`unknown`, random-like, or a simple format hint) instead of only saying "corrupted container".
- New encrypt operations reject passwords shorter than 10 characters unless `BASEFWX_ALLOW_WEAK_PASSWORD=1` is set.
- Default user KDF targets are hardened to `PBKDF2=600000` / `Argon2id=4 x 64 MiB`, and heavy-mode payloads advertise `PBKDF2=2000000` / `Argon2id=6 x 256 MiB`.
- Support policy is single-version: only the latest release is maintained; all older releases are immediately unsupported.
- Python `n10` is optimized for large payloads, but C++/Java remain faster in heavy benchmark runs.
- CLI progress includes live system telemetry (CPU/GPU/RAM/I/O/TEMP when available).
  Set `BASEFWX_PROGRESS_TELEMETRY=0` to disable.

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

n10 helpers:

```
from basefwx import n10encode, n10decode, n10encode_bytes, n10decode_bytes

digits = n10encode("hello")
text = n10decode(digits)
blob_digits = n10encode_bytes(b"\x00\x01\x02")
blob = n10decode_bytes(blob_digits)
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
cpp/build/basefwx [global flags] <command> ...
global flags: --verbose|-v --no-log --no-color

cpp/build/basefwx fwxaes-enc <file> -p <password> [--out <path>]
cpp/build/basefwx fwxaes-dec <file> -p <password> [--out <path>]
cpp/build/basefwx fwxaes-stream-enc <file> -p <password> [--out <path>]
cpp/build/basefwx fwxaes-stream-dec <file> -p <password> [--out <path>]
cpp/build/basefwx fwxaes-live-enc <file> -p <password> [--out <path>]
cpp/build/basefwx fwxaes-live-dec <file> -p <password> [--out <path>]
cpp/build/basefwx n10-enc <text>
cpp/build/basefwx n10-dec <digits>
cpp/build/basefwx n10file-enc <in-file> <out-file>
cpp/build/basefwx n10file-dec <in-file> <out-file>

cpp/build/basefwx b512-enc <text> -p <password>
cpp/build/basefwx b512-dec <text> -p <password>
cpp/build/basefwx pb512-enc <text> -p <password>
cpp/build/basefwx pb512-dec <text> -p <password>

cpp/build/basefwx b512file-enc <file> -p <password>
cpp/build/basefwx b512file-dec <file.fwx> -p <password>
cpp/build/basefwx pb512file-enc <file> -p <password>
cpp/build/basefwx pb512file-dec <file.fwx> -p <password>
```

Notes:

- `--no-log` suppresses telemetry/progress/warnings and keeps primary outputs/errors only.
- `--verbose` adds detailed hardware routing reason lines.
- `fwxaes-live-*` implements the packetized `LIVE` v1 stream format used by Python/Java.
- `fwxaes-live-*` supports `-` for stdin/stdout, so you can pipe media streams (for example with `ffmpeg`).

Example live audio pipe (C++):

```bash
ffmpeg -hide_banner -loglevel error -i input.m4a -vn -ac 1 -ar 16000 -f wav pipe:1 \
  | cpp/build/basefwx fwxaes-live-enc - -p correct-horse-battery --no-master --out - \
  | cpp/build/basefwx fwxaes-live-dec - -p correct-horse-battery --no-master --out - > restored.wav
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

n10 helpers:

```
#include "basefwx/basefwx.hpp"

std::string digits = basefwx::N10Encode("hello");
std::string text = basefwx::N10Decode(digits);
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

java -jar build/libs/basefwx-java.jar b512-enc <text> <password>
java -jar build/libs/basefwx-java.jar b512-dec <text> <password>
java -jar build/libs/basefwx-java.jar pb512-enc <text> <password>
java -jar build/libs/basefwx-java.jar pb512-dec <text> <password>

java -jar build/libs/basefwx-java.jar b512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar b512file-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar pb512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar pb512file-dec <in> <out> <password>
```

Notes:

- Java CLI global flags: `--verbose|-v`, `--no-log`.
- `--no-log` suppresses telemetry/warnings while preserving primary outputs/errors.
- The Java module includes Argon2id (BouncyCastle, optional libargon2 JNI) and ML-KEM-768/1024 master wrap (BouncyCastle PQC). LZMA is not available. See `COMPATIBILITY.md`.
- C++ CLI plugin flags: `--plugin <path>`, `--plugin-id <hex>`, `--plugin-pos pre|post`, `--plugin-config <file>` (Profile A PRE/POST). Keyed/`POS_RAW` host wiring is incomplete — see `examples/plugins/THREAT_MODEL.md`.

## Java API

```
import com.fixcraft.basefwx.BaseFwx;

try (InputStream in = new FileInputStream("input.bin");
     OutputStream out = new FileOutputStream("output.fwx")) {
    BaseFwx.fwxAesEncryptStream(in, out, "password", false);
}

byte[] blob = BaseFwx.b512FileEncodeBytes(data, ".bin", "password", false);
BaseFwx.DecodedFile decoded = BaseFwx.b512FileDecodeBytes(blob, "password", false);

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
```

## Retired media commands

The kFM and kFA carriers and the jMG media cipher were retired in 3.8.0. A
default CLI, JAR, or wheel does not contain them, and none of the commands
below appear in its help output.

They ship only in a compatibility artifact, and their job there is to read
media files you already have. The formats, flags, and bytes are unchanged; the
profile gets security, correctness, and existing-data compatibility fixes only.
Encrypt new media with `fwxaes`, which treats it as bytes and gives it the same
AEAD guarantees as any other file.

Selecting the compatibility profile happens at build time, so the switch cannot
restore these commands in an artifact that shipped without them. Use a
compatibility artifact of the same BaseFWX version that wrote the file.

| Runtime | How to select |
| :-- | :-- |
| C++ | Configure with `-DBASEFWX_ENABLE_RETIRED_MEDIA=ON`. |
| Java | `BASEFWX_ENABLE_RETIRED_MEDIA=1`, or Gradle `-PbasefwxEnableRetiredMedia=true` (the property wins). |
| Python | Build from source with `BASEFWX_ENABLE_RETIRED_MEDIA=1` and the `retired-media` extra, then set the same variable before importing BaseFWX. |

The same compatibility profile contains b256, A512, Bi512, and Uhash513. The
historical environment-variable name remains unchanged so existing build
automation does not break. None of these retired commands or their benchmarks
ship in a default artifact.

🫡 b256 has been retired since BaseFWX 3.7.0. It was the first BaseFWX
encoding method, born in V1 back when this was a proof of concept and not yet a
project. Existing data still decodes through the compatibility profile, but
for new work, it's time to go. ❤️

### Python

```
BASEFWX_ENABLE_RETIRED_MEDIA=1 python -m pip install './python[retired-media]'

BASEFWX_ENABLE_RETIRED_MEDIA=1 python -m basefwx kFMe input.png -o input.wav
BASEFWX_ENABLE_RETIRED_MEDIA=1 python -m basefwx kFMe input.mp3 -o input.png --bw
BASEFWX_ENABLE_RETIRED_MEDIA=1 python -m basefwx kFMd input.wav -o restored.png
```

```
from basefwx import kFMe, kFMd, jMGe, jMGd

carrier = kFMe("input.mp3", output="input.png", bw_mode=True)
restored = kFMd("input.png", output="restored.mp3")

jMGe("input.m4a", "password", output="out-small.m4a")  # default no-archive
jMGe("cover.png", "password", output="out.png", archive_original=True)
jMGd("out-small.m4a", "password", output="plain.m4a")  # may not be byte-identical
```

The `fwxaes` media flags belong here too: `--keep-meta` preserves and encrypts
media metadata, `--archive` embeds the full payload for exact restore, and
`--no-archive` (the Python default) skips it. On a default build these raise an
error naming the switch rather than silently writing a different format.

### C++

```
cpp/build/basefwx kFMe <in-file> [--out <path>] [--bw]
cpp/build/basefwx kFMd <carrier-file> [--out <path>] [--bw]
cpp/build/basefwx jmge <media> [-p <password>] [--master-pub <path>] [--out <path>] [--archive]
cpp/build/basefwx jmgd <media> [-p <password>] [--out <path>]
```

Master-only media encryption:

```
cpp/build/basefwx jmge input.mp4 --master-pub /secure/mlkem768.pub --out out.mp4
```

```
std::string carrier = basefwx::Kfme("input.mp3", "input.png", true);
std::string restored = basefwx::Kfmd("input.png", "restored.mp3");
```

### Java

```
java -jar build/libs/basefwx-java.jar kFMe <in> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFMd <carrier> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFAe <in> [--out <out>] [--bw]   # deprecated alias
java -jar build/libs/basefwx-java.jar kFAd <carrier> [--out <out>]     # deprecated alias
java -jar build/libs/basefwx-java.jar jmge <in> <out> <password> [--no-archive]
java -jar build/libs/basefwx-java.jar jmgd <in> <out> <password>
```

```
BaseFwxImage.jmgEncryptFile(new File("input.mp4"), new File("out.mp4"), "password", true, false, true);
BaseFwxImage.jmgDecryptFile(new File("out.mp4"), new File("plain.mp4"), "password", true);

File carrier = BaseFwxImage.kFMe(new File("input.mp3"), new File("input.png"), true);
File restored = BaseFwxImage.kFMd(new File("input.png"), new File("restored.mp3"));
```

### Behaviour notes

- `kFMe` picks the carrier from the source type: audio becomes PNG, everything
  else becomes WAV. It writes only `.png` or `.wav`, and rejects a mismatched
  output extension.
- `kFMd` decodes BaseFWX carriers strictly and refuses plain media files.
- C++ kFM carriers are block-coded into PNG/WAV at near full carrier capacity
  rather than copying container bytes straight into pixels or samples. Legacy
  raw carriers still decode.
- C++ `jmge` defaults to a key-only `JMG1` trailer: smaller output,
  concealment-first, and decode may not be byte-identical. `--archive` appends
  the encrypted original for exact restore.
- Java `jmge` accepts `--keep-meta`, `--keep-input`, and `--no-archive`.
- jMG media needs `ffmpeg` and `ffprobe` on `PATH`.
- jMG video stays disabled unless `BASEFWX_ENABLE_JMG_VIDEO=1`, on top of the
  compatibility profile.
- kFM/kFA acceleration: `BASEFWX_KFM_ACCEL=auto|cuda|cpu` (default `auto`) and
  `BASEFWX_KFM_ACCEL_MIN_BYTES=<bytes>` (default `1048576`).
- Python jMG hardware acceleration order is NVIDIA (`nvenc`), Intel (`qsv`),
  VAAPI, then CPU. `BASEFWX_HWACCEL_STRICT=1` fails instead of falling back to
  CPU; C++ selects `nvenc` with `BASEFWX_HWACCEL=nvenc`.
- Retired methods have no benchmark commands or rows. Compatibility
  qualification checks exact bytes and existing-data decoding instead.
