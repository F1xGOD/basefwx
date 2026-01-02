# BaseFWX Java

This module provides a Java implementation of the core BaseFWX codecs so it can run on any JVM (desktop, server, or Android runtime).

## Scope (v1)
- fwxAES raw encrypt/decrypt (PBKDF2 mode + EC master-key wrap)
- fwxAES streaming encrypt/decrypt (InputStream/OutputStream)
- b512 / pb512 encode/decode (PBKDF2 + optional EC master-key wrap)
- b256 encode/decode
- b64 encode/decode
- hash512 / uhash513
- a512 encode/decode
- bi512 / b1024 encode
- Minimal CLI entrypoint
- b512file + pb512file bytes + file helpers (in-memory)

Not yet included:
- PQ master-key (ML-KEM) support
- Argon2 KDF support
- jMG media pipeline

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

java -jar build/libs/basefwx-java.jar b64-enc <text>
java -jar build/libs/basefwx-java.jar b64-dec <text>

java -jar build/libs/basefwx-java.jar hash512 <text>
java -jar build/libs/basefwx-java.jar uhash513 <text>

java -jar build/libs/basefwx-java.jar a512-enc <text>
java -jar build/libs/basefwx-java.jar a512-dec <text>

java -jar build/libs/basefwx-java.jar bi512-enc <text>
java -jar build/libs/basefwx-java.jar b1024-enc <text>

java -jar build/libs/basefwx-java.jar b256-enc <text>
java -jar build/libs/basefwx-java.jar b256-dec <text>
```

## Cross-compat notes
- For b512/pb512, set the KDF label to `pbkdf2` in Python/C++ when you need Java interop.
- fwxAES PBKDF2 mode is fully compatible across Python/C++/Java.
- EC master-key wrap is supported using P-521 (secp521r1) and EC1 blobs.
- AES-heavy file containers (pb512file) are implemented and cross-compatible with Python/C++ (PBKDF2 mode).

### Master key paths (EC)
Java reads EC public/private keys from:
- `BASEFWX_MASTER_EC_PUB` and `BASEFWX_MASTER_EC_PRIV`, or
- `~/master_ec_public.pem` and `~/master_ec_private.pem`

## Android
The library is pure Java and uses standard `javax.crypto` APIs. AES-GCM requires API 21+ on Android.
File helpers are built on `java.io` to keep Android compatibility.

## Testing overrides
For fast tests, you can set `BASEFWX_TEST_KDF_ITERS` to reduce PBKDF2 iterations.
