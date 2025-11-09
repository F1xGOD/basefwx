"""
BASEFWX - Hybrid post-quantum + AEAD encryption toolkit

This module provides easy-to-use functions for encrypting and decrypting text and files.
All functions support optional ML-KEM-768 (post-quantum) master key wrapping.
"""

from .main import *

# ============================================================================
# TEXT ENCODING FUNCTIONS (String → Encoded String)
# ============================================================================

def b64encode(string: str):
    """
    Standard Base64 encoding.
    
    Args:
        string: Plain text to encode
        
    Returns:
        Base64-encoded string
        
    Note:
        - Simple Base64 encoding, no encryption
        - Reversible with b64decode()
    """
    return basefwx.b64encode(string)


def b512encode(string: str, code: str="", use_master: bool = True):
    """
    FWX512R encryption with optional post-quantum protection.
    
    Args:
        string: Plain text to encrypt
        code: Password for encryption (optional if use_master=True)
        use_master: Enable ML-KEM-768 post-quantum key wrapping
        
    Returns:
        Base64-encoded encrypted string
        
    How it works:
        - Uses HKDF-derived mask key for XOR obfuscation
        - Optionally wraps with ML-KEM-768 (Kyber) for post-quantum security
        - Password-based key derivation uses Argon2id by default
        - Output is Base64-encoded for text-safe transport
        
    Security:
        - ★ Recommended for string encryption
        - Post-quantum resistant when use_master=True
        - Password required when use_master=False
    """
    return basefwx.b512encode(string, code, use_master=use_master)


def b256encode(string: str):
    """
    FWX256R encoding (NOT RECOMMENDED - use b512encode instead).
    
    Args:
        string: Plain text to encode
        
    Returns:
        Base32-encoded obfuscated string
        
    Note:
        - ❗❗❗ Weaker than b512encode
        - Uses character substitution + Base32 encoding
        - Reversible with b256decode()
    """
    return basefwx.b256encode(string)


def b1024encode(string: str):
    """
    FWX1024I irreversible hash encoding (BEST for one-way hashing).
    
    Args:
        string: Plain text to hash
        
    Returns:
        Irreversible hash string
        
    How it works:
        - Combines multiple SHA hashing rounds
        - Uses FWX encoding layers
        - Cannot be reversed/decoded
        
    Security:
        - ★ BEST for password hashing and checksums
        - ❙❙❙❙ Maximum security (irreversible)
        - Use for password verification, not encryption
    """
    return basefwx.b1024encode(string)


def bi512encode(string: str):
    """
    FWX512I irreversible code-based hash.
    
    Args:
        string: Plain text to hash
        
    Returns:
        SHA-256 hash of encoded input
        
    How it works:
        - Derives code from input
        - Applies multiple encoding layers
        - Final SHA-256 hash (irreversible)
        
    Security:
        - ★ Irreversible hash
        - Suitable for checksums and verification
    """
    return basefwx.bi512encode(string)


def pb512encode(string: str, code: str="", use_master: bool = True):
    """
    FWX512RP reversible obfuscation with AEAD protection.
    
    Args:
        string: Plain text to encrypt
        code: Password (required when use_master=False)
        use_master: Enable ML-KEM-768 post-quantum key wrapping
        
    Returns:
        Base64-encoded encrypted string
        
    How it works:
        - Masks payload with HKDF-derived keystream
        - Packs user/master key blobs with length prefixes
        - Applies Base64 encoding for transport
        - Uses Argon2id for password-based key derivation
        
    Security:
        - Confidentiality from AEAD layers (when used in file mode)
        - Post-quantum protection when use_master=True
        - Password required when use_master=False
    """
    return basefwx.pb512encode(string, code, use_master=use_master)


def a512encode(string: str):
    """
    FWX512C codeless encoding (NOT RECOMMENDED - use b512encode).
    
    Args:
        string: Plain text to encode
        
    Returns:
        Encoded string with length prefix
        
    Note:
        - ❗❗❗ Weaker security than b512encode
        - Uses binary-to-decimal conversion
        - Reversible with a512decode()
    """
    return basefwx.a512encode(string)


def hash512(string: str):
    """
    Simple SHA-256 hash (not SHA-512 despite the name).
    
    Args:
        string: Plain text to hash
        
    Returns:
        SHA-256 hexadecimal hash
        
    Note:
        - Standard SHA-256 hashing
        - Irreversible one-way function
        - Use for checksums and verification
    """
    return basefwx.hash512(string)


def uhash513(string: str):
    """
    HASH512U - Ultra hash with multiple SHA rounds and b512encode.
    
    Args:
        string: Plain text to hash
        
    Returns:
        SHA-256 hash of multi-layered encoding
        
    How it works:
        - SHA-256 → SHA-1 → SHA-512 → b512encode → SHA-256
        - Multiple rounds provide additional complexity
        - Irreversible hash
        
    Note:
        - More complex than hash512()
        - Suitable for enhanced verification needs
    """
    return basefwx.uhash513(string)


# ============================================================================
# TEXT DECODING FUNCTIONS (Encoded String → Plain Text)
# ============================================================================

def b64decode(string: str):
    """
    Standard Base64 decoding.
    
    Args:
        string: Base64-encoded text
        
    Returns:
        Decoded plain text
    """
    return basefwx.b64decode(string)


def b256decode(string: str):
    """
    FWX256R decoding (reverses b256encode).
    
    Args:
        string: FWX256R-encoded string
        
    Returns:
        Decoded plain text
    """
    return basefwx.b256decode(string)


def a512decode(string: str):
    """
    FWX512C codeless decoding (reverses a512encode).
    
    Args:
        string: FWX512C-encoded string
        
    Returns:
        Decoded plain text
        
    Note:
        - Reverses a512encode() transformation
        - May return error if input is corrupted
    """
    return basefwx.a512decode(string)


def b512decode(string: str, code: str="", use_master: bool = True):
    """
    FWX512R decryption (reverses b512encode).
    
    Args:
        string: Base64-encoded b512 ciphertext
        code: Password used during encryption
        use_master: Enable ML-KEM-768 master key unwrapping
        
    Returns:
        Decrypted plain text
        
    How it works:
        - Base64 decodes the input
        - Unpacks length-prefixed key blobs
        - Recovers mask key from password or master key
        - Unmasks payload to recover plaintext
        
    Raises:
        ValueError: If password is missing/wrong or data is corrupted
        
    Note:
        - Requires same password used during encoding
        - Master key required if use_master was True during encoding
    """
    return basefwx.b512decode(string, code, use_master=use_master)


def pb512decode(string: str, code: str="", use_master: bool = True):
    """
    FWX512RP decryption (reverses pb512encode).
    
    Args:
        string: Base64-encoded pb512 ciphertext
        code: Password used during encryption
        use_master: Enable ML-KEM-768 master key unwrapping
        
    Returns:
        Decrypted plain text
        
    How it works:
        - Same as b512decode with pb512-specific info contexts
        - Recovers mask key and unmasks payload
        
    Raises:
        ValueError: If password is missing/wrong or data is corrupted
    """
    return basefwx.pb512decode(string, code, use_master=use_master)


# ============================================================================
# IMAGE CIPHER FUNCTIONS
# ============================================================================

def jMGe(path: str, password: str, output: str | None = None):
    """
    Encrypt an image file by scrambling pixels (deterministic image cipher).
    
    Args:
        path: Path to input image file (PNG, JPEG, etc.)
        password: Password for encryption
        output: Optional output path (default: overwrites input)
        
    Returns:
        Path to encrypted image file (as string)
        
    How it works:
        - Loads image and converts to NumPy array
        - Applies XOR mask, channel rotation, and permutation
        - Saves scrambled pixels in original image format
        - Appends AEAD-encrypted archive of original file as trailer
        - Original file extension is preserved
        
    File format:
        - Saves as: same format as input (e.g., .png stays .png)
        - Appends magic trailer: 'JMG0' + length + encrypted archive
        - Output looks like a normal image but pixels are scrambled
        
    Security:
        - Uses AES-CTR for pixel masking
        - Deterministic permutation based on password
        - Archive encrypted with AES-GCM (AEAD)
        - Original file recoverable with jMGd()
        
    Note:
        - No PQ (post-quantum) wrapping for image cipher
        - Password is required (no master key option)
        - Encrypted image is same size as original
    """
    return basefwx.ImageCipher.encrypt_image_inv(path, password, output=output)


def jMGd(path: str, password: str, output: str | None = None):
    """
    Decrypt an image file encrypted with jMGe().
    
    Args:
        path: Path to encrypted image file
        password: Password used during encryption
        output: Optional output path (default: derived from input)
        
    Returns:
        Path to decrypted file (as string)
        
    How it works:
        - Reads image and checks for 'JMG0' trailer magic
        - If trailer exists, extracts and decrypts archived original file
        - Otherwise, unscrambles pixels by reversing cipher operations
        - Saves recovered file to output path
        
    File recovery:
        - If archive is present: restores exact original file
        - Otherwise: recovers image by unscrambling pixels
        
    Raises:
        ValueError: If password is wrong or file is corrupted
    """
    return basefwx.ImageCipher.decrypt_image_inv(path, password, output=output)


# ============================================================================
# FILE ENCRYPTION FUNCTIONS (File → .fwx File)
# ============================================================================

def b512encodefile(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
    """
    Encrypt a file using b512 method (FWX512R file encryption).
    
    Args:
        file: Path to file to encrypt
        code: Password for encryption
        strip_metadata: Remove internal metadata and zero timestamps
        use_master: Enable ML-KEM-768 post-quantum key wrapping
        
    Returns:
        "SUCCESS!" or "FAIL!"
        
    How it works:
        - Reads entire file into memory
        - Applies b512encode-style masking
        - Wraps with AEAD (AES-GCM) if BASEFWX_B512_AEAD=1
        - Saves encrypted file with .fwx extension
        - Removes original file after successful encryption
        
    File format:
        - Input:  any_file.ext
        - Output: any_file.fwx (original removed)
        
    PQ usage:
        - When use_master=True: wraps keys with ML-KEM-768
        - When use_master=False: password-only encryption
        - strip_metadata forces password-only mode
        
    Note:
        - Loads entire file into memory (size limit ~20GB)
        - Original file is deleted after encryption
        - Use b512decodefile() to decrypt
    """
    return basefwx.b512file_encode(file, code, strip_metadata=strip_metadata, use_master=use_master)


def b512decodefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True):
    """
    Decrypt a .fwx file created by b512encodefile().
    
    Args:
        file: Path to .fwx file to decrypt
        code: Password used during encryption
        strip_metadata: Must match encryption setting
        use_master: Enable ML-KEM-768 master key unwrapping
        
    Returns:
        "SUCCESS!" or "FAIL!"
        
    How it works:
        - Reads .fwx file
        - Decrypts with AEAD if applicable
        - Unmasks payload to recover original file
        - Restores original extension
        - Removes .fwx file after successful decryption
        
    File format:
        - Input:  any_file.fwx
        - Output: any_file.ext (original extension restored, .fwx removed)
        
    Raises:
        ValueError: If password is wrong or file is corrupted
        
    Note:
        - Requires correct password and master key (if used)
        - Original .fwx file is deleted after decryption
    """
    return basefwx.b512file_decode(file, code, strip_metadata=strip_metadata, use_master=use_master)


def b512handlefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True, silent: bool = False):
    """
    Smart file handler: encrypts or decrypts based on extension (b512 method).
    
    Args:
        file: Path to file (.fwx to decrypt, other to encrypt)
        code: Password for encryption/decryption
        strip_metadata: Remove internal metadata
        use_master: Enable ML-KEM-768 post-quantum key wrapping
        silent: Suppress progress output
        
    Returns:
        "SUCCESS!" or "FAIL!" (single file)
        Dict of {path: status} for multiple files
        
    How it works:
        - If file ends with .fwx: decrypts to original
        - If file has other extension: encrypts to .fwx
        - Automatically detects operation based on extension
        - Supports multiple files at once
        
    File operations:
        - Encrypt: file.ext → file.fwx (removes file.ext)
        - Decrypt: file.fwx → file.ext (removes file.fwx)
        
    PQ usage:
        - Same as b512encodefile/b512decodefile
        - Master key wrapping available when use_master=True
        
    Note:
        - Can process multiple files in parallel
        - Progress bars shown unless silent=True
        - Original files deleted after successful operation
    """
    return basefwx.b512file(file, code, strip_metadata=strip_metadata, use_master=use_master, silent=silent)


def fwxAES(file: str, code: str="", light: bool = True, strip_metadata: bool = False, use_master: bool = True, silent: bool = False):
    """
    AES-based file encryption with light or heavy mode (primary file encryption).
    
    Args:
        file: Path to file(s) (.fwx to decrypt, other to encrypt)
        code: Password (can be empty if use_master=True)
        light: True for AES-LIGHT (fast), False for AES-HEAVY (secure)
        strip_metadata: Remove metadata and force password-only mode
        use_master: Enable ML-KEM-768 post-quantum key wrapping
        silent: Suppress progress output
        
    Returns:
        "SUCCESS!" or "FAIL!" (single file)
        Dict of {path: status} for multiple files
        
    How it works (AES-LIGHT):
        - Base64 encodes file content
        - Encrypts with AES-GCM (AEAD)
        - Uses Argon2id for password KDF by default
        - Compresses with zlib
        - Small obfuscation layer if size <= 250KB
        
    How it works (AES-HEAVY):
        - Uses pb512encode for extension and data
        - Encrypts with AES-GCM (AEAD)  
        - Higher KDF iterations (1M for PBKDF2, 5/128MB/4 for Argon2)
        - Streaming mode for files > 250KB
        - Full obfuscation with permutation
        
    File format:
        - Encrypt: file.ext → file.fwx (removes file.ext)
        - Decrypt: file.fwx → file.ext (removes file.fwx)
        - Extension stored in encrypted payload
        
    PQ usage:
        - When use_master=True: wraps AES key with ML-KEM-768 (Kyber)
        - When use_master=False: password-only with Argon2id/PBKDF2
        - strip_metadata automatically disables master wrapping
        
    Streaming:
        - Files > 250KB use streaming mode (heavy only)
        - Chunks encrypted in 1MB blocks
        - Progress bars during processing
        
    Security notes:
        - Light mode: faster, suitable for most files
        - Heavy mode: maximum security, slower KDF
        - Both use AES-256-GCM with authenticated encryption
        - Nonces are random and unique per encryption
        - Master key enables recovery even if password is lost
        
    Environment:
        - BASEFWX_USER_KDF: "argon2id" or "pbkdf2" (default: argon2id)
        - BASEFWX_OBFUSCATE: "0" to disable obfuscation (default: "1")
        - BASEFWX_MASTER_PQ_PUB: path to ML-KEM-768 public key
        
    Note:
        - Can process multiple files at once
        - Supports YubiKey-derived passwords (code="yubikey:label")
        - Original files deleted after successful encryption
        - Progress shows two bars: overall and per-file
        - File size limit: ~20GB per file
    """
    return basefwx.AESfile(file, code, light, strip_metadata=strip_metadata, use_master=use_master, silent=silent)
