# Cross-Language Encryption - Quick Start

## TL;DR - Make It Work

**For Python users encrypting data that C++/Java will decrypt:**

```bash
export BASEFWX_USER_KDF=pbkdf2
```

Add this to your `.bashrc` or `.profile`, or set it in your Python code:

```python
import os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'
import basefwx  # Import AFTER setting the env var
```

**For C++/Java users encrypting data that Python will decrypt:**

Use `--kdf pbkdf2` flag:

```bash
./basefwx_cpp pb512-enc "text" -p password --no-master --kdf pbkdf2
java -jar basefwx-java.jar pb512-enc "text" password --no-master
```

## What's Supported

✅ **pb512** - Password-based text encryption (all languages)  
✅ **b512** - Password-based text encryption (Python ↔ C++)  
✅ **fwxAES** - File encryption (all languages)  
✅ **Streaming** - Large file processing (all languages)  

## Common Use Cases

### Share Encrypted Text Between Languages

```bash
# Python: Encrypt
export BASEFWX_USER_KDF=pbkdf2
python3 -c "import basefwx; print(basefwx.basefwx.pb512encode('secret', 'pass', False))" > encrypted.txt

# C++: Decrypt
./basefwx_cpp pb512-dec "$(cat encrypted.txt)" -p pass --no-master --kdf pbkdf2

# Output: secret
```

### Encrypt Files in One Language, Decrypt in Another

```python
# Python: Encrypt file
import basefwx, os
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

with open('input.txt', 'rb') as f:
    data = f.read()
    
encrypted = basefwx.basefwx.fwxAES_encrypt_raw(data, 'password', use_master=False)

with open('output.fwx', 'wb') as f:
    f.write(encrypted)
```

```bash
# C++: Decrypt file
./basefwx_cpp fwxaes-dec output.fwx -p password --no-master --out decrypted.txt
```

### Use as a Library in Your Application

**Python:**
```python
from basefwx import basefwx
import os

# Set KDF for cross-language compatibility
os.environ['BASEFWX_USER_KDF'] = 'pbkdf2'

# Encrypt
encrypted = basefwx.pb512encode("sensitive data", "password", use_master=False)

# Decrypt
decrypted = basefwx.pb512decode(encrypted, "password", use_master=False)
```

**C++:**
```cpp
#include <basefwx/basefwx.hpp>

basefwx::KdfOptions kdf;
kdf.label = "pbkdf2";

// Encrypt
std::string encrypted = basefwx::Pb512Encode("sensitive data", "password", false, kdf);

// Decrypt
std::string decrypted = basefwx::Pb512Decode(encrypted, "password", false, kdf);
```

**Java:**
```java
import com.fixcraft.basefwx.BaseFwx;

// Encrypt
String encrypted = BaseFwx.pb512Encode("sensitive data", "password", false);

// Decrypt
String decrypted = BaseFwx.pb512Decode(encrypted, "password", false);
```

## Troubleshooting

### "ASCII trash binary" or InvalidTag error

**Problem:** Python can't decrypt C++/Java encrypted data.

**Solution:** Set `export BASEFWX_USER_KDF=pbkdf2` before importing basefwx in Python.

### "Bad password" error but password is correct

**Problem:** Different KDF settings between encryption and decryption.

**Solution:** Ensure both sides use `--kdf pbkdf2` (C++/Java) or `BASEFWX_USER_KDF=pbkdf2` (Python).

### Working with Argon2

If you have Argon2 available in all languages:
- Python: Will use Argon2 by default
- C++: Use `--kdf argon2` flag
- Java: Only supports PBKDF2

**Recommendation:** Stick with PBKDF2 for maximum compatibility.

## Performance

- **PBKDF2**: Fast, compatible across all languages
- **Argon2**: More secure but requires library in each language
- **Cross-language overhead**: None - same encryption strength

## Security

✅ Both PBKDF2 and Argon2 are cryptographically secure  
✅ Cross-language doesn't compromise security  
✅ Same encryption algorithms used in all languages  
✅ 200,000+ iterations for PBKDF2 (400,000 for short passwords)  

## More Information

See [CROSS_LANGUAGE_GUIDE.md](CROSS_LANGUAGE_GUIDE.md) for:
- Detailed API examples
- Streaming and async support
- Advanced configuration
- Complete troubleshooting guide

## Quick Reference

| Language | Set KDF | Check Works |
|----------|---------|-------------|
| Python | `export BASEFWX_USER_KDF=pbkdf2` | `python3 -c "import basefwx; print(basefwx.basefwx.USER_KDF_ITERATIONS)"` should show `200000` |
| C++ | `--kdf pbkdf2` flag | Encrypt and decrypt should work |
| Java | Always PBKDF2 | No setup needed |

## Support

If you encounter issues:
1. Check you're using `BASEFWX_USER_KDF=pbkdf2` in Python
2. Check you're using `--no-master` flag consistently
3. Verify same password on both sides
4. See the [troubleshooting guide](CROSS_LANGUAGE_GUIDE.md#troubleshooting-checklist)
