# Compatibility and System Requirements

## Platform Support

### Linux
- **Minimum**: Debian 9+, Ubuntu 18.04+, RHEL/CentOS 7+
- **Architecture**: x86_64 (amd64), aarch64 (arm64)
- **Build**: Static linking for liboqs, dynamic for OpenSSL/glibc
- **Optimizations**: Generic CPU (no -march=native for max compatibility)

### Windows
- **Minimum**: Windows 10+
- **Architecture**: x64
- **Build**: Uses vcpkg for dependencies

### macOS
- **Minimum**: macOS 11+ (Big Sur)
- **Architecture**: x86_64, arm64 (Apple Silicon)
- **Dependencies**: Via Homebrew

## Memory Requirements

### Argon2id (Default KDF)
- **Recommended**: 256 MiB+ free RAM
- **Minimum**: 
  - Standard: ~128 MiB for default parameters (memory_cost=2^15 KiB)
  - Short passwords: ~256 MiB for enhanced security (memory_cost=2^16 KiB)
  - Heavy operations: ~512 MiB (memory_cost=2^17 KiB)

**Low Memory Fallback**: If you encounter "Insufficient memory for Argon2id" errors:
```bash
export BASEFWX_USER_KDF=pbkdf2
```

### PBKDF2 (Fallback KDF)
- **Memory**: Minimal (~1 MiB)
- **Security**: Still secure with high iteration count (200,000+ iterations)

## Error Messages

### Expected Errors (User-Friendly)
The application provides clear error messages for known issues:

1. **Insufficient Memory**:
   ```
   RuntimeError: Insufficient memory for Argon2id key derivation.
   Required: ~128 MiB, Consider using PBKDF2 instead (set BASEFWX_USER_KDF=pbkdf2)
   ```

2. **Missing Dependencies**:
   ```
   RuntimeError: Argon2 backend unavailable
   ```

3. **Invalid Input**:
   ```
   ValueError: User key salt must be at least 16 bytes
   ```

### Unexpected Errors
For unexpected errors, you may see full tracebacks. Please report these as bugs.

## Compatibility Features

### Static Linking
- **liboqs**: Statically linked in Linux builds for maximum portability
- **Benefits**: No dependency on system liboqs version

### Dynamic Linking
- **OpenSSL**: Uses system OpenSSL for security updates
- **glibc**: Dynamic (unavoidable on Linux)
- **ZLIB**: Dynamic (ubiquitous library)

### Build Flags
Release builds use:
- `-O3` optimization
- LTO (Link-Time Optimization)
- No CPU-specific optimizations (-march=native disabled)
- Deprecation warnings suppressed for clean output

## Troubleshooting

### Binary Won't Run on Older Linux
1. Check glibc version: `ldd --version`
   - Required: glibc 2.17+ (RHEL 7+) or 2.27+ (Ubuntu 18.04+)
2. Check OpenSSL: `openssl version`
   - Required: OpenSSL 1.1.1+ or 3.0+

### Memory Errors
1. Check available memory: `free -h`
2. Try PBKDF2: `export BASEFWX_USER_KDF=pbkdf2`
3. Reduce memory_cost if using Argon2 directly

### Performance Issues
1. Ensure you're using release builds (not debug)
2. Check CPU usage during operations
3. Consider SSD for file operations

## Environment Variables

### Memory and Performance
- `BASEFWX_USER_KDF`: Set to `pbkdf2` for low-memory systems
- `BASEFWX_PERF`: Enable performance mode for large files
- `BASEFWX_TEST_KDF_ITERS`: Reduce KDF iterations for testing only

### Development
- `BASEFWX_OBFUSCATE`: Enable/disable obfuscation
- `ALLOW_BAKED_PUB`: Allow using baked public key (testing only)
- `BASEFWX_MASTER_PQ_PUB`: Path to master PQ public key

## Architecture Support

### Tested Architectures
- ✅ x86_64 (AMD64)
- ✅ ARM64 (aarch64, Apple Silicon)

### Untested but Should Work
- ARM32 (ARMv7)
- RISC-V (with appropriate compiler)

## File Format Compatibility

All file formats are cross-platform and architecture-independent:
- Encoded files work across all platforms
- Encrypted files are portable
- Archive formats are standardized
