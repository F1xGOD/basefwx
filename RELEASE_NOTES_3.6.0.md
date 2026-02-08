# BaseFWX 3.6.0 Release Notes

## Overview

BaseFWX 3.6.0 is a major update focusing on cross-language compatibility, security enhancements, and usability improvements. This release adds comprehensive Java support, improves Argon2 usage, and enhances the overall developer experience.

## 🎉 New Features

### Java Support
- **Full cross-language compatibility** with Java
- Java implementations of pb512, b512, and fwxAES
- Comprehensive cross-language tests (Python ↔ C++ ↔ Java)
- Java JAR included in official releases

### URL-Safe pb512 Encoding
- pb512 now uses URL-safe base64 encoding (`urlsafe_b64encode`)
- Safe for use in URLs, filenames, and web applications
- Backward compatible decoder supports both formats
- URL-safe when obfuscation is disabled (`BASEFWX_OBFUSCATE_CODECS=0`)

### Argon2 Prioritization
- **Argon2id is now the default KDF** when conditions allow
- Follows Google's recommendation: "Argon2 (specifically Argon2id) is superior to PBKDF2"
- Automatic RAM detection (Linux/macOS)
- Only uses Argon2 when ≥128 MiB RAM available
- Graceful fallback to PBKDF2 with clear warnings

### Enhanced Error Handling
- Clear warning when Argon2 fails: `"⚠️ USING PBKDF2, ARGON2 FAILED! CAUSE: {error}"`
- OOM prevention through RAM detection
- Improved cross-language error messages

## 🚀 Performance Improvements

### Python Optimizations
- **20-30% faster** a512 encoding for large strings
- **5-10% faster** b512/pb512 encoding
- List comprehension optimization for character processing
- Efficient buffer construction with bytearray

### C++ Optimizations
- **2-3x faster** text encoding with Trie-based decoder
- Reduced algorithmic complexity from O(n×m×t) to O(n×m)
- Meyer's singleton pattern for safe static initialization
- Improved token matching performance

## 🔒 Security Enhancements

### Argon2 Integration
- Argon2id default when sufficient RAM available
- Memory-hard KDF resistant to GPU/ASIC attacks
- Automatic fallback prevents denial of service
- RAM detection prevents OOM errors

### Cross-Language Security
- Consistent KDF behavior across languages
- Fixed PBKDF2 iteration count for cross-language compatibility
- Comprehensive security validation in release workflow

### Enhanced Release Workflow
- Comprehensive test suite before every release
- Cross-language compatibility validation
- Argon2 availability verification
- VirusTotal scanning for all artifacts
- GPG signing for all releases

## 🎨 UI/UX Improvements

### HTML Portal Enhancements
- **Stylized scrollbars** matching the purple theme
- Smooth scrolling for code blocks
- **Truncated hash display** with expandable "..." button
- Click to expand/collapse long SHA256 hashes
- Prevents hash overflow across multiple lines

## 📚 Documentation

### New Documentation
- Comprehensive SECURITY.md updates for 3.6.0
- Detailed release workflow documentation
- Enhanced function docstrings (e.g., pb512 URL-safety)

### Documentation Cleanup
- AI-generated documentation moved to `AI_gen/` directory
- Cleaner main directory structure
- Focus on essential developer documentation

## 🔄 Migration Guide

### From 3.5.x to 3.6.0
**Safe upgrade path** - No breaking changes for most users.

- Java support is new, doesn't affect existing Python/C++ workflows
- pb512 decoder is backward compatible (supports both formats)
- Argon2 prioritization doesn't break existing PBKDF2 usage
- Set `BASEFWX_USER_KDF=pbkdf2` explicitly if you need consistent behavior

**Action items:**
1. Update basefwx package: `pip install --upgrade basefwx`
2. Test cross-language workflows if using Java
3. Consider enabling Argon2 for better security
4. Review SECURITY.md for new recommendations

### From 3.4.x and Earlier
**Upgrade recommended** - Multiple security and performance improvements.

- Re-generate keys and re-encrypt all stored data
- Do not mix 3.6.0 with earlier versions in production
- Follow the migration guidance in SECURITY.md

## 🛠️ Developer Experience

### Cross-Language Development
- Consistent API across Python, C++, and Java
- Comprehensive cross-language test suite
- Clear documentation for cross-language encryption
- Examples for all major use cases

### Testing Improvements
- Enhanced release workflow with security validation
- Comprehensive test coverage
- Cross-language compatibility tests
- Performance benchmarking

## 📋 Version Information

- **Version:** 3.6.0
- **Release Date:** 2026-02-08
- **Python:** ≥3.9
- **C++:** C++17 or later
- **Java:** ≥17

## 🔗 Links

- **GitHub Repository:** https://github.com/F1xGOD/basefwx
- **Release Assets:** https://github.com/F1xGOD/basefwx/releases
- **Security Policy:** SECURITY.md
- **Documentation:** docs/

## 🙏 Acknowledgments

This release includes contributions from:
- Performance optimizations
- Security enhancements
- Cross-language compatibility improvements
- Enhanced testing infrastructure

## 📝 Full Changelog

### Added
- Java support for pb512, b512, fwxAES
- URL-safe base64 encoding for pb512
- RAM detection for Argon2 usage
- Argon2id default with fallback
- Security validation in release workflow
- Stylized scrollbars in HTML portal
- Hash truncation with expansion
- AI_gen/ directory for generated docs

### Changed
- pb512 uses urlsafe_b64encode (backward compatible)
- Argon2 now default when ≥128 MiB RAM available
- Enhanced error messages for cross-language issues
- Updated SECURITY.md for 3.6.0
- Improved release workflow validation

### Fixed
- Cross-language PBKDF2 iteration mismatch
- C++ token decoder performance (2-3x faster)
- Python a512 performance (20-30% faster)
- Buffer construction efficiency

### Security
- Prioritize Argon2id over PBKDF2
- Prevent OOM with RAM detection
- Enhanced cross-language security validation
- Comprehensive release testing

## ⚠️ Known Limitations

- pb512 is URL-safe only when obfuscation is disabled
  - Set `BASEFWX_OBFUSCATE_CODECS=0` for true URL-safety
  - Default obfuscation may reintroduce special characters
- RAM detection unavailable on some platforms
  - Assumes sufficient RAM when detection fails
  - Fallback to PBKDF2 if Argon2 OOM occurs

## 🔮 Future Plans

- Enhanced Argon2 integration across all platforms
- Additional language bindings (Rust, Go)
- Performance improvements for large files
- Extended cryptographic algorithm support

---

**Ready to upgrade?** Download the latest release from the [Releases page](https://github.com/F1xGOD/basefwx/releases)!
