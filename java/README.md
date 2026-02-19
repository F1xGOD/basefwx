# BaseFWX Java

This module provides a Java implementation of the core BaseFWX codecs so it can run on any JVM (desktop, server, or Android runtime).

## Scope (v1)
- fwxAES raw encrypt/decrypt (PBKDF2 mode + EC master-key wrap)
- fwxAES streaming encrypt/decrypt (InputStream/OutputStream)
- jMG media cipher for images, video, and audio (ffmpeg/ffprobe required)
- b512 / pb512 encode/decode (PBKDF2 + optional EC master-key wrap)
- b256 encode/decode
- n10 numeric encode/decode (text + bytes/file helpers)
- kFM carrier transforms (auto media/audio encode + strict carrier decode)
- b64 encode/decode
- hash512 / uhash513
- a512 encode/decode
- bi512 / b1024 encode
- Minimal CLI entrypoint
- b512file + pb512file bytes + file helpers (in-memory)

Not yet included:
- PQ master-key (ML-KEM) support
- Argon2 KDF support

## Build
Use Gradle if available:
```
cd java
gradle build
```

Manual build (no Gradle):
```
cd java
javac -source 8 -target 8 -d build/classes $(find src/main/java -name "*.java")
jar cfe build/libs/basefwx-java.jar com.fixcraft.basefwx.cli.BaseFwxCli -C build/classes .
```
On Windows PowerShell, you can build sources with:
```
$sources = Get-ChildItem -Recurse src/main/java -Filter *.java | ForEach-Object { $_.FullName }
javac -source 8 -target 8 -d build/classes $sources
jar cfe build/libs/basefwx-java.jar com.fixcraft.basefwx.cli.BaseFwxCli -C build/classes .
```

## CLI
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

java -jar build/libs/basefwx-java.jar pb512file-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar pb512file-dec <in> <out> <password>

java -jar build/libs/basefwx-java.jar jmge <in> <out> <password>
java -jar build/libs/basefwx-java.jar jmgd <in> <out> <password>

java -jar build/libs/basefwx-java.jar b64-enc <text>
java -jar build/libs/basefwx-java.jar b64-dec <text>

java -jar build/libs/basefwx-java.jar n10-enc <text>
java -jar build/libs/basefwx-java.jar n10-dec <digits>
java -jar build/libs/basefwx-java.jar n10file-enc <in> <out>
java -jar build/libs/basefwx-java.jar n10file-dec <in> <out>

java -jar build/libs/basefwx-java.jar kFMe <in> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFMd <carrier> [--out <out>] [--bw]
java -jar build/libs/basefwx-java.jar kFAe <in> [--out <out>] [--bw]   # deprecated alias
java -jar build/libs/basefwx-java.jar kFAd <carrier> [--out <out>]     # deprecated alias

java -jar build/libs/basefwx-java.jar hash512 <text>
java -jar build/libs/basefwx-java.jar uhash513 <text>

java -jar build/libs/basefwx-java.jar a512-enc <text>
java -jar build/libs/basefwx-java.jar a512-dec <text>

java -jar build/libs/basefwx-java.jar bi512-enc <text>
java -jar build/libs/basefwx-java.jar b1024-enc <text>

java -jar build/libs/basefwx-java.jar b256-enc <text>
java -jar build/libs/basefwx-java.jar b256-dec <text>
```

Notes:
- jMG requires `ffmpeg` and `ffprobe` on PATH.
- `jmge` supports `--keep-meta` and `--keep-input` for metadata/input preservation.
- `kFMd` only decodes BaseFWX carriers and refuses plain WAV/PNG/MP3/M4A inputs.

## Cross-compat notes
- For b512/pb512, set the KDF label to `pbkdf2` in Python/C++ when you need Java interop.
- fwxAES PBKDF2 mode is fully compatible across Python/C++/Java.
- EC master-key wrap is supported using P-521 (secp521r1) and EC1 blobs.
- AES-heavy file containers (pb512file) are implemented and cross-compatible with Python/C++ (PBKDF2 mode).
- kFM containers are compatible across Python/C++/Java (including `--bw` PNG carrier mode).
- `kFMe` is the primary encoder (`kFAe` is deprecated alias).
- `kFMd` is the primary decoder (`kFAd` is deprecated alias).

## API quick refs

```java
import com.fixcraft.basefwx.BaseFwx;
import java.io.File;

// n10 API
String digits = BaseFwx.n10Encode("hello");
String text = BaseFwx.n10Decode(digits);

// kFM API (auto media/audio encode + strict decode)
File carrier = BaseFwx.kFMe(new File("input.mp3"), new File("input.png"), true);
File restored = BaseFwx.kFMd(new File("input.png"), new File("restored.mp3"));
```

### Master key paths (EC)
Java reads EC public/private keys from:
- `BASEFWX_MASTER_EC_PUB` and `BASEFWX_MASTER_EC_PRIV`, or
- `~/master_ec_public.pem` and `~/master_ec_private.pem`

## Android
The library is pure Java and uses standard `javax.crypto` APIs. AES-GCM requires API 21+ on Android.
File helpers are built on `java.io` to keep Android compatibility.
The jMG media pipeline depends on `ffmpeg`/`ffprobe` and `ImageIO`, so it is not Android-compatible.

## Testing overrides
For fast tests, you can set `BASEFWX_TEST_KDF_ITERS` to reduce PBKDF2 iterations.
