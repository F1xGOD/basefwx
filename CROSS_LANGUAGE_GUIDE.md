# Cross-Language Encryption Guide

## Overview

basefwx provides **full cross-language compatibility** for encryption and decryption across Python, C++, and Java implementations. You can encrypt data in one language and decrypt it in another seamlessly.

## Quick Start

### Text Encryption (pb512, b512)

#### Python -> C++ Example

```python
# Python: Encrypt
import basefwx
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'  # Important for cross-language

encrypted = basefwx.basefwx.pb512encode('Hello from Python!', 'password', use_master=False)
print(encrypted)
```

```bash
# C++: Decrypt
./basefwx_cpp pb512-dec "<encrypted_text>" -p password --no-master --kdf pbkdf2
```

#### C++ -> Python Example

```bash
# C++: Encrypt
./basefwx_cpp pb512-enc "Hello from C++!" -p password --no-master --kdf pbkdf2
```

```python
# Python: Decrypt
import basefwx
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

decrypted = basefwx.basefwx.pb512decode(encrypted_text, 'password', use_master=False)
print(decrypted)
```

#### Java Example

```bash
# Java: Encrypt
java -jar basefwx-java.jar pb512-enc "Hello from Java!" password --no-master

# Java: Decrypt
java -jar basefwx-java.jar pb512-dec "<encrypted_text>" password --no-master
```

### File Encryption (b512file, pb512file, fwxAES)

#### Python -> C++ File Encryption

```python
# Python: Encrypt a file
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

# Using CLI
os.system('python -m basefwx cryptin b512 myfile.txt -p password --no-master')
# Creates myfile.fwx
```

```bash
# C++: Decrypt the file
./basefwx_cpp b512file-dec myfile.fwx -p password --no-master --kdf pbkdf2
# Creates myfile.txt
```

#### fwxAES File Encryption (Raw API)

```python
# Python: Encrypt file with fwxAES
import basefwx
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

with open('input.txt', 'rb') as f:
    data = f.read()

encrypted = basefwx.basefwx.fwxAES_encrypt_raw(data, 'password', use_master=False)

with open('encrypted.fwx', 'wb') as f:
    f.write(encrypted)
```

```bash
# C++: Decrypt file with fwxAES
./basefwx_cpp fwxaes-dec encrypted.fwx -p password --no-master --out output.txt
```

## Important Compatibility Settings

### 1. KDF (Key Derivation Function)

**Critical**: All languages must use the same KDF!

- **PBKDF2** (recommended for cross-language): Supported by all languages, faster, compatible
- **Argon2** (Python/C++ default if available): More secure but ensure all languages support it

#### Setting KDF

**Python:**
```python
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'  # Use before encryption/decryption
```

**C++:**
```bash
./basefwx_cpp <command> --kdf pbkdf2
```

**Java:**
```bash
# Java only supports PBKDF2
java -jar basefwx-java.jar <command>
```

### 2. Master Key Usage

**Critical**: Use `use_master=False` or `--no-master` for portability.

Master keys are environment-specific and won't work across different machines unless you copy the master key files.

**Python:**
```python
basefwx.basefwx.pb512encode(text, password, use_master=False)
```

**C++/Java:**
```bash
./basefwx_cpp pb512-enc "text" -p password --no-master
java -jar basefwx-java.jar pb512-enc "text" password --no-master
```

## Common Issues and Solutions

### Issue 1: "ASCII trash binary" on decrypt

**Cause**: KDF mismatch between encryption and decryption.

**Solution**: Ensure both sides use the same KDF:

```python
# Encrypt with PBKDF2
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
encrypted = basefwx.basefwx.pb512encode(text, 'password', use_master=False)
```

```bash
# Decrypt with PBKDF2
./basefwx_cpp pb512-dec "$encrypted" -p password --no-master --kdf pbkdf2
```

### Issue 2: Decryption fails with "Bad password"

**Possible causes:**
1. **Wrong password** (obvious, but check!)
2. **KDF mismatch**: Python default is Argon2, C++/Java need `--kdf argon2`
3. **Master key mismatch**: One side used master key, other didn't
4. **Different KDF iterations**: Ensure `BASEFWX_TEST_KDF_ITERS` not set differently

### Issue 3: File decrypt outputs binary data

**Cause**: Wrong encryption format or corrupted file.

**Solution**: Ensure file extension matches encryption type:
- `.fwx` for b512file/pb512file/fwxAES
- Use correct decrypt command for encryption type

## API Examples

### Streaming API (Python)

```python
import basefwx
import os

# Stream encrypt large files
with open('large_input.bin', 'rb') as source:
    with open('large_output.fwx', 'wb') as dest:
        bytes_written = basefwx.basefwx.fwxAES_encrypt_stream(
            source, dest, 'password', 
            use_master=False,
            chunk_size=1024*1024  # 1MB chunks
        )
print(f"Encrypted {bytes_written} bytes")

# Stream decrypt
with open('large_output.fwx', 'rb') as source:
    with open('decrypted.bin', 'wb') as dest:
        bytes_written = basefwx.basefwx.fwxAES_decrypt_stream(
            source, dest, 'password',
            use_master=False
        )
```

### Streaming API (C++)

C++ supports streaming through file operations:

```bash
# Stream processing is built into file operations
./basefwx_cpp fwxaes-enc large_input.bin -p password --no-master --out large_output.fwx
./basefwx_cpp fwxaes-dec large_output.fwx -p password --no-master --out decrypted.bin
```

## Best Practices

1. **Always specify KDF explicitly** for cross-language work
2. **Use `--no-master`** unless you've set up master keys on all systems
3. **Test small examples first** before encrypting important data
4. **Keep passwords consistent** (obvious but important!)
5. **Document your encryption settings** (KDF, master key usage, etc.)

## Async/Await Support

### Python Async

While basefwx doesn't provide native async APIs, you can use it with asyncio:

```python
import asyncio
import basefwx
import os

async def encrypt_async(text, password):
    loop = asyncio.get_event_loop()
    # Run in executor to avoid blocking
    result = await loop.run_in_executor(
        None, 
        basefwx.basefwx.pb512encode, 
        text, password, False
    )
    return result

async def main():
    encrypted = await encrypt_async("Hello async!", "password")
    print(encrypted)

asyncio.run(main())
```

### Java Async

Java can use CompletableFuture for async operations:

```java
import com.fixcraft.basefwx.BaseFwx;
import java.util.concurrent.CompletableFuture;

CompletableFuture<String> futureEncrypt = CompletableFuture.supplyAsync(() -> {
    return BaseFwx.pb512Encode("Hello async!", "password", false);
});

futureEncrypt.thenAccept(encrypted -> {
    System.out.println("Encrypted: " + encrypted);
});
```

## Testing Cross-Language Compatibility

Use this simple test to verify your setup:

```bash
# Create test file
echo "Cross-language test!" > test.txt

# Python encrypt
python -c "import basefwx, os; os.environ['BASEFWX_USER_KDF']='pbkdf2'; enc=basefwx.basefwx.pb512encode('Test!', 'pw', False); print(enc)" > test_py.enc

# C++ decrypt
./basefwx_cpp pb512-dec "$(cat test_py.enc)" -p pw --no-master --kdf pbkdf2

# If you see "Test!" then it's working!
```

## Troubleshooting Checklist

- [ ] Same password on both sides?
- [ ] Same KDF (pbkdf2 recommended)?
- [ ] Both using `--no-master` or both using master keys?
- [ ] Correct encryption/decryption commands for the format?
- [ ] No environment variable differences (like BASEFWX_TEST_KDF_ITERS)?
- [ ] File not corrupted during transfer?

## Summary

Cross-language encryption in basefwx is **fully supported and tested**. The key requirements are:

1. **Use the same KDF** (recommend PBKDF2 for cross-language)
2. **Consistent master key settings** (recommend `--no-master`)
3. **Same password** (obviously!)

When these are met, you can seamlessly encrypt in Python and decrypt in C++/Java, or any combination!
