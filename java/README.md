# BaseFWX Java

This module provides a Java implementation of the core BaseFWX codecs so it can run on any JVM (desktop, server, or Android runtime).

## Pure Java vs JNI

The fwxAES family (`fwxAES`, `fwxAES-light`, `fwxAES-live`) is exposed through a single interface, [`FwxAES`](src/main/java/com/fixcraft/basefwx/FwxAES.java), with two concrete implementations:

| Class | Backend | When to use |
| --- | --- | --- |
| [`FwxAESPureJava`](src/main/java/com/fixcraft/basefwx/FwxAESPureJava.java) | `javax.crypto.Cipher` (JCA) | Default. No native dependency. Works on any JVM, including Android. Pick this for libraries and apps that prefer a clean classpath. |
| [`FwxAESJNI`](src/main/java/com/fixcraft/basefwx/FwxAESJNI.java) | `basefwxcrypto` shared library via JNI | Opt-in. Slightly faster on desktop / server when the JCA path isn't well-tuned (older Android, ARM without AES extensions, JREs with software AES). On x86 with AES-NI the JCA is already very fast, so the gap is small. |

Both implementations are routed through the same wire-format code in `BaseFwx`, so blobs they produce are byte-identical and interchangeable, and a blob produced by one is decryptable by the other and by the Python and C++ implementations.

### Picking a backend

```java
// Default: pure Java (FwxAESPureJava)
FwxAES aes = FwxAES.create();
byte[] blob = aes.encryptRaw(plaintext, "password");
byte[] back = aes.decryptRaw(blob, "password");

// Opt into JNI. Falls back to pure Java with a single warning line if the
// shared library cannot be loaded.
FwxAES fast = FwxAES.create(true);
boolean usingNative = fast.isNative();

// Builder
FwxAES configured = FwxAES.builder()
    .enableJNI(true)
    .useMaster(false)
    .build();

// Direct construction is supported when you want to be explicit
FwxAES pinnedPure = new FwxAESPureJava();
FwxAES pinnedJni  = new FwxAESJNI(); // throws if the native lib can't be loaded
```

The opt-in is also wired to `-Dbasefwx.useJNI=true` and `BASEFWX_NATIVE=1` (kill switches: `-Dbasefwx.useJNI=false` and `BASEFWX_NATIVE=0`). Per-instance routing is done through a thread-local override on `CryptoBackends`, so a `FwxAESPureJava` instance always uses the pure-Java AEAD even if the JVM was started with `BASEFWX_NATIVE=1` (and vice versa).

### Building the native library

The C++ source for the JNI lib lives at [`cpp/src/jni/basefwx_jni.cpp`](../cpp/src/jni/basefwx_jni.cpp). Build it with:

```bash
cmake -S basefwx/cpp -B build/jni \
    -DBASEFWX_BUILD_CLI=OFF \
    -DBASEFWX_BUILD_JNI=ON \
    -DBASEFWX_REQUIRE_ARGON2=OFF \
    -DBASEFWX_REQUIRE_OQS=OFF
cmake --build build/jni --target basefwxcrypto -j
```

The result is `libbasefwxcrypto.so` (Linux), `libbasefwxcrypto.dylib` (macOS), or `basefwxcrypto.dll` (Windows). Set `JAVA_HOME` if `jni.h` isn't on the default include path.

### Loading the native library

[`NativeLibraryLoader`](src/main/java/com/fixcraft/basefwx/NativeLibraryLoader.java) looks in this order:

1. `/native/<os>/<arch>/<filename>` inside the running JAR (extracted to a temp file and `System.load`-ed). Convention: `native/linux/x86_64/libbasefwxcrypto.so`, `native/macos/aarch64/libbasefwxcrypto.dylib`, `native/windows/x86_64/basefwxcrypto.dll`, etc.
2. `System.loadLibrary("basefwxcrypto")`, which uses the JVM's `java.library.path`.

So either bundle the lib into the JAR under `/native/...` or run with `-Djava.library.path=<dir-containing-the-lib>`.

### Benchmark

A standalone microbenchmark for both backends is shipped as `FwxAESBenchmark`:

```bash
# default: 4 MiB payload, 5 iterations, pure-Java only
java -cp basefwx-java.jar com.fixcraft.basefwx.FwxAESBenchmark

# include JNI path
java -Dbasefwx.useJNI=true \
     -Djava.library.path=/path/to/dir \
     -cp basefwx-java.jar com.fixcraft.basefwx.FwxAESBenchmark 16777216 5
```

Sample run on x86_64 (Linux, JDK 25, OpenSSL 3.5, OpenJDK JCA with AES-NI):

```
=== 4 MiB / 5 iters ===
  pure-java   encrypt 57.87 ms (69.1 MiB/s)   decrypt 7.44 ms (537.6 MiB/s)
  jni         encrypt 60.29 ms (66.3 MiB/s)   decrypt 7.52 ms (532.1 MiB/s)
  speedup (encrypt): jni is 0.96x pure-java

=== 16 MiB / 3 iters ===
  pure-java   encrypt 66.96 ms (238.9 MiB/s)   decrypt 9.35 ms (1711.6 MiB/s)
  jni         encrypt 61.64 ms (259.6 MiB/s)   decrypt 7.42 ms (2156.3 MiB/s)
  speedup (encrypt): jni is 1.09x pure-java
```

On platforms without AES-NI or with weaker JCA implementations the gap is wider; on Android it's been measured at 2-4x in earlier prototypes. On a modern x86 desktop the two backends are within a few percent of each other and the pure-Java path is preferable for the smaller deployment surface.


## Scope (v1)
- fwxAES raw encrypt/decrypt (PBKDF2 mode + EC master-key wrap)
- fwxAES streaming encrypt/decrypt (InputStream/OutputStream)
- fwxAES live packet streaming encrypt/decrypt (frame-based, transport-agnostic)
- jMG media cipher for images/audio (video path is temporarily disabled by default unless `BASEFWX_ENABLE_JMG_VIDEO=1`)
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
java -jar build/libs/basefwx-java.jar [global flags] <command> ...
# global flags: --verbose|-v --no-log
java -jar build/libs/basefwx-java.jar fwxaes-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-stream-dec <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-live-enc <in> <out> <password>
java -jar build/libs/basefwx-java.jar fwxaes-live-dec <in> <out> <password>

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
- `jmge` supports `--keep-meta`, `--keep-input`, and `--no-archive`.
- `--no-archive` stores only key material (`JMG1`) instead of a full embedded original payload (`JMG0`), so decode output may not be byte-identical.
- `--no-log` suppresses telemetry/warnings while preserving primary outputs/errors.
- `--verbose` prints additional hardware routing reason lines.
- jMG video is disabled by default unless `BASEFWX_ENABLE_JMG_VIDEO=1`.
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

// jMG API (archive_original defaults to true)
BaseFwx.jmgEncryptFile(
    new File("input.mp4"),
    new File("out.mp4"),
    "password",
    true,
    false,
    true,
    false // archiveOriginal=false (no-archive mode)
);

// Live stream API (transport-agnostic framing)
try (InputStream src = new FileInputStream("in.bin");
     OutputStream enc = new FileOutputStream("out.live")) {
    BaseFwx.fwxAesLiveEncryptStream(src, enc, "password", true);
}
try (InputStream enc = new FileInputStream("out.live");
     OutputStream dec = new FileOutputStream("out.bin")) {
    BaseFwx.fwxAesLiveDecryptStream(enc, dec, "password", true);
}
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
