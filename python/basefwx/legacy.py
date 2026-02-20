# BASEFWX ENCRYPTION ENGINE ->

import os as _os_module
import re as _re_module
import sys as _sys_module
import warnings as _warnings_module

# Enable large integer string conversion for performance-critical decimal math
if hasattr(_sys_module, "set_int_max_str_digits"):
    _sys_module.set_int_max_str_digits(0)  # 0 = unlimited


class basefwx:
    import base64
    import concurrent.futures
    import enum
    import threading
    import sys
    import secrets
    import pathlib
    import typing
    import json
    import struct
    import wave
    try:
        from PIL import Image
    except Exception:  # pragma: no cover - optional dependency
        Image = None
    from io import BytesIO
    try:
        import numpy as np
    except Exception:  # pragma: no cover - optional dependency
        np = None
    try:
        import cupy as cp
    except Exception:  # pragma: no cover - optional dependency
        cp = None
    import os
    import zlib
    import hashlib
    import hmac as stdlib_hmac
    import contextlib
    import time
    import tempfile
    import string
    import tarfile
    import lzma
    import shutil
    import subprocess
    import math
    re = _re_module
    try:
        import colorama
        colorama.init()  # Initialize colorama for cross-platform color support
    except ImportError:
        pass  # Colorama is optional
    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        from pqcrypto.kem import ml_kem_768
    except Exception:  # pragma: no cover - optional dependency
        class _PQUnavailable:
            CIPHERTEXT_SIZE = 0

            @staticmethod
            def encrypt(_public_key):
                raise RuntimeError("pqcrypto is required for PQ operations (pip install pqcrypto)")

            @staticmethod
            def decrypt(_private_key, _ciphertext):
                raise RuntimeError("pqcrypto is required for PQ operations (pip install pqcrypto)")

        ml_kem_768 = _PQUnavailable()
    from datetime import datetime, timezone
    try:
        from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw, Type as _Argon2Type
    except Exception:  # pragma: no cover - optional dependency
        _argon2_hash_secret_raw = None
        _Argon2Type = None
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hmac

    @staticmethod
    def _env_int(name: str) -> "basefwx.typing.Optional[int]":
        value = _os_module.getenv(name)
        if not value:
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        if parsed <= 0:
            return None
        return parsed

    @staticmethod
    def _perf_mode_enabled() -> bool:
        raw = _os_module.getenv("BASEFWX_PERF")
        if not raw:
            return False
        value = raw.strip().lower()
        return value in ("1", "true", "yes", "on")

    @staticmethod
    def _use_fast_obfuscation(length: int) -> bool:
        return basefwx._perf_mode_enabled() and length >= basefwx.PERF_OBFUSCATION_THRESHOLD

    @staticmethod
    def _get_available_ram_mib():
        """
        Get available RAM in MiB. Returns None if unable to determine.
        """
        try:
            # Try psutil first (most reliable)
            import psutil
            return psutil.virtual_memory().available / (1024 * 1024)
        except ImportError:
            pass
        
        try:
            # Linux: Read /proc/meminfo
            if _os_module.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            # Value is in kB
                            kb = int(line.split()[1])
                            return kb / 1024
            
            # macOS: Use sysctl
            import subprocess
            result = subprocess.run(['sysctl', '-n', 'vm.stats.vm.v_free_count'], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                page_count = int(result.stdout.strip())
                # Get page size
                page_size_result = subprocess.run(['sysctl', '-n', 'hw.pagesize'],
                                                 capture_output=True, text=True, timeout=1)
                if page_size_result.returncode == 0:
                    page_size = int(page_size_result.stdout.strip())
                    return (page_count * page_size) / (1024 * 1024)
        except Exception:
            pass
        
        # Could not determine RAM
        return None
    
    @staticmethod
    def _check_ram_for_argon2():
        """
        Check if system has sufficient RAM for Argon2 (at least 128 MiB available).
        Returns True if sufficient, False otherwise.
        """
        ram_mib = None
        try:
            import psutil
            ram_mib = psutil.virtual_memory().available / (1024 * 1024)
        except Exception:
            pass
        if ram_mib is None:
            try:
                if _os_module.path.exists('/proc/meminfo'):
                    with open('/proc/meminfo', 'r') as f:
                        for line in f:
                            if line.startswith('MemAvailable:'):
                                kb = int(line.split()[1])
                                ram_mib = kb / 1024
                                break
                if ram_mib is None:
                    import subprocess
                    result = subprocess.run(
                        ['sysctl', '-n', 'vm.stats.vm.v_free_count'],
                        capture_output=True,
                        text=True,
                        timeout=1
                    )
                    if result.returncode == 0:
                        page_count = int(result.stdout.strip())
                        page_size_result = subprocess.run(
                            ['sysctl', '-n', 'hw.pagesize'],
                            capture_output=True,
                            text=True,
                            timeout=1
                        )
                        if page_size_result.returncode == 0:
                            page_size = int(page_size_result.stdout.strip())
                            ram_mib = (page_count * page_size) / (1024 * 1024)
            except Exception:
                ram_mib = None
        if ram_mib is None:
            # Unable to determine, assume sufficient RAM
            return True
        return ram_mib >= 128.0

    MAX_INPUT_BYTES = 20 * 1024 * 1024 * 1024  # allow up to ~20 GiB per file
    PROGRESS_BAR_WIDTH = 30
    FWX_DELIM = "\x1f\x1e"
    FWX_HEAVY_DELIM = "\x1f\x1d"
    LEGACY_FWX_DELIM = "A8igTOmG"
    LEGACY_FWX_HEAVY_DELIM = "673827837628292873"
    META_DELIM = "::FWX-META::"
    PACK_META_KEY = "ENC-P"
    PACK_TAR_GZ = "g"
    PACK_TAR_XZ = "x"
    PACK_SUFFIX_GZ = ".tgz"
    PACK_SUFFIX_XZ = ".txz"
    ENGINE_VERSION = "3.6.2"
    N10_MOD = 10_000_000_000
    N10_MUL = 3_816_547_291
    N10_ADD = 7_261_940_353
    N10_MAGIC = "927451"
    N10_VERSION = "01"
    N10_HEADER_DIGITS = 28
    N10_MASK64 = (1 << 64) - 1
    N10_MUL_INV = pow(N10_MUL, -1, N10_MOD)
    KFM_MAGIC = b"KFM!"
    KFM_VERSION = 1
    KFM_MODE_IMAGE_AUDIO = 1
    KFM_MODE_AUDIO_IMAGE = 2
    KFM_FLAG_BW = 1
    KFM_HEADER_STRUCT = struct.Struct(">4sBBBBQIQI")
    KFM_HEADER_LEN = KFM_HEADER_STRUCT.size
    KFM_MAX_PAYLOAD = 1_073_741_824
    KFM_AUDIO_RATE = 24000
    KFM_AUDIO_EXTENSIONS = frozenset({
        ".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga", ".opus",
        ".wma", ".amr", ".aiff", ".aif", ".alac", ".m4b", ".caf", ".mka",
    })
    KFM_IMAGE_EXTENSIONS = frozenset({
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff",
        ".ico", ".heic", ".heif", ".ppm", ".pgm",
    })
    MASTER_PQ_ALG = "ml-kem-768"
    MASTER_PQ_PUBLIC = b"eJwBoARf+/rkrYxhXn0CNFqTkzQUrIYloydzGrqpIuWXi+qnLO/XRnspzQBDwwTKLW3Ku6Zwii1AfriFM5t8PtugqMNFt/5HoHxIZLGkytTWKP3IKoP7EH2HFu14b5bagh+KIFTWoW12qZqLRNjJLBHZmzxasEIsN7AnsOiokMHxt4XwoLk5fscIhXSANBZpHUVEO+NkBhg5UnvzWkzAqPm6rEvCfE+CHxgFg1SjBJeFfVMyzpKpsUi6iCGXSl6nZuTkr10btfi8RHCEfxDrfhcJk0bsKMWEI6wVY23KQXXlmcJ4VydGZ/ZbjWhVbX6bo0DKqG5IlwpTDPJIwlumRpxbBog8JG10p8PTaRJEAKfiVo7jiD1Aki7hYqmyyBn2Q0RFy03Bm/Rpy1zlK3DahaaoMj1mJrJ5ff2FYYVsBQbrywcDUcdHUkIpUqwrrRyqdEIHq1T6AiKHmf2KHTXQnLuZpJ3Ih59bkH1GC2UzbEIWzFSImvQDkswCBW9cF0tFYCNnReiReb57XAjaW3smdOg1o9oyk2IbyptJtNe1teHoPsMJkBGin/ugUeFmEOa0f8lTEmK4u1/GxHrQxD65kxm2IHT4NPM8Z5oqQ9z0WthUE5MouNrZLK8EltZQzAcZJ/g7CesRi40qFecyD14hDPBcr6cEV6yqOXXrcDRQVCUhuYRyUNqrFe4JPks2kZlxXjABHMD1PHVzfJpsAtsTDJa2EdpoAkKRvfg2QOK6CpYix6zIyB1yGwdCG8L2QS9DQefDQntXDlwSIieqRrwmiWcba4mSgwfxsoH2SIbQPZKbtEA4XNGqen1CcldAw1w2mnO3otspreJEBZJjVSihGcoyVjWap9dWc0pLffeDC5mUyOTzWUQ3XBAxX817G9rIbFyMQ+4AdeP2zL/nk9s2wYuZT2MEbwTHW/6UJQXbRf+svg9Kq//ryl/YRiaxdK2xRkP7oaBBVbyyXxYUJEhXOD7cUar8HsGZlXmiDSxzCBZSJG+4ooAgOKfEx6liOvqHBQKrsG4ylg3JQqmKBUdXcf6cMImRqS4MFM23vQkSPqIckxGgkrJGDKLGg8DKsuOqUvkzexAWviAIJQZsJsqjUl2stBgnltsyysE2cdI5Poh7KgOFV27bfi4iCpFSXc46Aa2jjN0WFYAgfhcRXgvIanJ3L8/sPrR7QKvpTtPFSfdcBipqp8vRdYImF5HceU1TU+QwtOcmCKDmaDTBGtJLZDXYJ3/2VQAEr8Mhk1WxGQsWUikZBi9pHTTbh93gvl9gLaGlxlRCjwzSqcJVXF80UiVMA06hfDnzi9MFpIGZL0czax+1zwdLFsnnHLGLzm/YpgrUBIk0gTgMVhqiu0+JyagxwrXCsDmGbhj8PzJGUeR8xhoxzOtTMgtaFwekbEAss+JGzuZJeakDxhMJEvvbKabIFDeQLsImO4eaAslqXyNoSg7AtnDlHfzTTFvwk2/UppeXNmcEC9n1UyfyWNW6qAZRJe5zQkijzLfkGKWsR/ksjmUQwMHwOOWVQ8qqUapYxsmbZkosPBXRDNBhY6PNjfciD2hRoIqrd/pnkJ6cZd1FQyxge6FA3PMpHw=="
    MASTER_EC_MAGIC = b"EC1"
    MASTER_EC_CURVE_NAME = "secp521r1"
    MASTER_EC_PUBLIC_ENV = "BASEFWX_MASTER_EC_PUB"
    MASTER_EC_PRIVATE_ENV = "BASEFWX_MASTER_EC_PRIV"
    IMAGECIPHER_SCRAMBLE_CONTEXT = b'basefwx.imagecipher.scramble.v1'
    IMAGECIPHER_OFFSET_CONTEXT = b'basefwx.imagecipher.offset.v1'
    IMAGECIPHER_AEAD_INFO = b'basefwx.image.v1'
    IMAGECIPHER_STREAM_INFO = b'basefwx.imagecipher.stream.v1'
    IMAGECIPHER_ARCHIVE_INFO = b'basefwx.imagecipher.archive.v1'
    IMAGECIPHER_TRAILER_MAGIC = b'JMG0'
    IMAGECIPHER_KEY_TRAILER_MAGIC = b'JMG1'
    JMG_KEY_MAGIC = b'JMGK'
    JMG_KEY_VERSION_LEGACY = 1
    JMG_KEY_VERSION = 2
    JMG_SECURITY_PROFILE_LEGACY = 0
    JMG_SECURITY_PROFILE_MAX = 1
    JMG_SECURITY_PROFILE_DEFAULT = JMG_SECURITY_PROFILE_MAX
    JMG_SECURITY_PROFILE_LABELS = {
        JMG_SECURITY_PROFILE_LEGACY: "legacy",
        JMG_SECURITY_PROFILE_MAX: "max",
    }
    JMG_SECURITY_PROFILE_NAMES = {
        "legacy": JMG_SECURITY_PROFILE_LEGACY,
        "max": JMG_SECURITY_PROFILE_MAX,
    }
    JMG_MASK_INFO = b'basefwx.jmg.mask.v1'
    JMG_MASK_AAD = b'jmg'
    ENABLE_B512_AEAD = os.getenv("BASEFWX_B512_AEAD", "1") == "1"
    B512_AEAD_INFO = b'basefwx.b512file.v1'
    B512_FILE_MASK_INFO = b'basefwx.b512file.mask.v1'
    ENABLE_OBFUSCATION = os.getenv("BASEFWX_OBFUSCATE", "1") == "1"
    ENABLE_CODEC_OBFUSCATION = os.getenv("BASEFWX_OBFUSCATE_CODECS", "1") == "1"
    OBF_INFO_MASK = b'basefwx.obf.mask.v1'
    OBF_INFO_PERM = b'basefwx.obf.perm.v1'
    STREAM_THRESHOLD = 250 * 1024
    STREAM_CHUNK_SIZE = 1 << 20  # 1 MiB streaming blocks
    LIVE_STREAM_CHUNK_SIZE = 64 * 1024  # lower latency default for live stream framing
    PERF_OBFUSCATION_THRESHOLD = 1 << 20
    STREAM_MAGIC = b'STRMOBF1'
    STREAM_INFO_KEY = b'basefwx.stream.obf.key.v1'
    STREAM_INFO_IV = b'basefwx.stream.obf.iv.v1'
    STREAM_INFO_PERM = b'basefwx.stream.obf.perm.v1'
    HKDF_MAX_LEN = 255 * 32
    HEAVY_PBKDF2_ITERATIONS = 1_000_000
    HEAVY_ARGON2_TIME_COST = 5
    HEAVY_ARGON2_MEMORY_COST = 2 ** 17
    HEAVY_ARGON2_PARALLELISM = max(1, os.cpu_count() or 1)
    OFB_FAST_MIN = 64 * 1024
    PERM_FAST_MIN = 4 * 1024
    USER_KDF_SALT_SIZE = 16
    USER_KDF_ITERATIONS = 200_000
    SHORT_PASSWORD_MIN = 12
    SHORT_PBKDF2_ITERATIONS = 400_000
    SHORT_ARGON2_TIME_COST = 4
    SHORT_ARGON2_MEMORY_COST = 2 ** 16
    SHORT_ARGON2_PARALLELISM = max(1, os.cpu_count() or 1)
    if _Argon2Type is None:
        class _FallbackArgon2Type(enum.Enum):
            ID = 2
        Argon2Type = _FallbackArgon2Type
    else:
        Argon2Type = _Argon2Type
    hash_secret_raw = _argon2_hash_secret_raw
    _ARGON2_AVAILABLE = hash_secret_raw is not None
    # Use Argon2 by default if available AND sufficient RAM (>= 128 MiB)
    # This follows Google's recommendation: "Argon2 (specifically Argon2id) is superior to PBKDF2"
    _HAS_SUFFICIENT_RAM = _check_ram_for_argon2() if _ARGON2_AVAILABLE else True
    if _ARGON2_AVAILABLE and _HAS_SUFFICIENT_RAM:
        USER_KDF_DEFAULT = "argon2id"
    else:
        USER_KDF_DEFAULT = "pbkdf2"
        if _ARGON2_AVAILABLE and not _HAS_SUFFICIENT_RAM:
            import warnings
            warnings.warn(
                "Insufficient RAM for Argon2 (< 128 MiB available). Using PBKDF2. "
                "Set BASEFWX_USER_KDF=argon2 to override.",
                ResourceWarning
            )
    USER_KDF = os.getenv("BASEFWX_USER_KDF", USER_KDF_DEFAULT).lower()
    # Only reduce iterations if Argon2 is unavailable AND user didn't explicitly set KDF
    # This maintains cross-language compatibility when explicitly using PBKDF2
    if not _ARGON2_AVAILABLE and os.getenv("BASEFWX_USER_KDF") is None:
        USER_KDF_ITERATIONS = 32_768
    _TEST_KDF_ITERS = _env_int("BASEFWX_TEST_KDF_ITERS")
    _USER_KDF_ITERS_ENV = _env_int("BASEFWX_USER_KDF_ITERS")
    if _USER_KDF_ITERS_ENV is not None:
        USER_KDF_ITERATIONS = _USER_KDF_ITERS_ENV
    elif _TEST_KDF_ITERS is not None:
        USER_KDF_ITERATIONS = _TEST_KDF_ITERS
    _HEAVY_PBKDF2_ITERS_ENV = _env_int("BASEFWX_HEAVY_PBKDF2_ITERS")
    if _HEAVY_PBKDF2_ITERS_ENV is not None:
        HEAVY_PBKDF2_ITERATIONS = _HEAVY_PBKDF2_ITERS_ENV
    elif _TEST_KDF_ITERS is not None:
        HEAVY_PBKDF2_ITERATIONS = _TEST_KDF_ITERS
    _WARNED_ARGON2_MISSING = False
    _MASTER_PUBKEY_OVERRIDE: typing.ClassVar[typing.Optional[bytes]] = None
    _CPU_COUNT_OVERRIDE = _os_module.getenv("BASEFWX_MAX_THREADS")
    if _CPU_COUNT_OVERRIDE and _CPU_COUNT_OVERRIDE.strip().isdigit():
        _CPU_COUNT = max(1, int(_CPU_COUNT_OVERRIDE.strip()))
    else:
        _CPU_COUNT = max(1, os.cpu_count() or 1)
    # Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
    _FORCE_SINGLE_THREAD_ENV = _os_module.getenv("BASEFWX_FORCE_SINGLE_THREAD")
    _SINGLE_THREAD_OVERRIDE = bool(_FORCE_SINGLE_THREAD_ENV == "1" and (os.cpu_count() or 1) > 1)
    _WARNED_SINGLE_THREAD = False

    def _warn_single_thread_api() -> None:
        if basefwx._WARNED_SINGLE_THREAD:
            return
        if not basefwx._SINGLE_THREAD_OVERRIDE:
            return
        basefwx._WARNED_SINGLE_THREAD = True
        ansi_orange = "\033[38;5;208m"
        ansi_reset = "\033[0m"
        msg = (
            f"{ansi_orange}WARN: MULTI-THREAD DISABLED; PERFORMANCE MAY DETERIORATE."
            f" Using BASEFWX_MAX_THREADS=1 with {_os_module.cpu_count() or 1} cores available.{ansi_reset}"
        )
        try:
            print(msg, file=basefwx.sys.stderr)
        except Exception:
            pass

    _PARALLEL_CHUNK_SIZE = 1 << 20  # 1 MiB chunks when fan-out encoding
    # Python's native int is efficient up to millions of digits; use native math
    _DECIMAL_INT_LIMIT = 100_000
    _SILENT_MODE: typing.ClassVar[bool] = False
    PQ_CIPHERTEXT_SIZE = getattr(ml_kem_768, "CIPHERTEXT_SIZE", 0)
    AEAD_NONCE_LEN = 12
    AEAD_TAG_LEN = 16
    EPHEMERAL_KEY_LEN = 32
    USER_WRAP_FIXED_LEN = USER_KDF_SALT_SIZE + AEAD_NONCE_LEN + AEAD_TAG_LEN + EPHEMERAL_KEY_LEN  # salt + nonce + tag + key
    FWXAES_MAGIC = b"FWX1"
    FWXAES_ALGO = 0x01
    FWXAES_KDF_PBKDF2 = 0x01
    FWXAES_KDF_WRAP = 0x02
    FWXAES_SALT_LEN = 16
    FWXAES_IV_LEN = 12
    FWXAES_PBKDF2_ITERS = 200_000
    _FWXAES_PBKDF2_ITERS_ENV = _env_int("BASEFWX_FWXAES_PBKDF2_ITERS")
    if _FWXAES_PBKDF2_ITERS_ENV is not None:
        FWXAES_PBKDF2_ITERS = _FWXAES_PBKDF2_ITERS_ENV
    elif _TEST_KDF_ITERS is not None:
        FWXAES_PBKDF2_ITERS = _TEST_KDF_ITERS
    FWXAES_KEY_LEN = 32
    FWXAES_AAD = b"fwxAES"
    FWXAES_MASK_INFO = b"basefwx.fwxaes.mask.v1"
    FWXAES_KEY_INFO = b"basefwx.fwxaes.key.v1"
    LIVE_FRAME_MAGIC = b"LIVE"
    LIVE_FRAME_VERSION = 1
    LIVE_FRAME_TYPE_HEADER = 1
    LIVE_FRAME_TYPE_DATA = 2
    LIVE_FRAME_TYPE_FIN = 3
    LIVE_KEYMODE_PBKDF2 = 1
    LIVE_KEYMODE_WRAP = 2
    LIVE_NONCE_PREFIX_LEN = 4
    LIVE_HEADER_STRUCT = struct.Struct(">BBBBII")
    LIVE_FRAME_HEADER_STRUCT = struct.Struct(">4sBBQI")
    NORMALIZE_THRESHOLD = 8 * 1024
    ZW0 = "\u200b"
    ZW1 = "\u200c"
    FWX_PACK_MAGIC = b"FWXPK1"
    FWX_PACK_HEADER_LEN = len(FWX_PACK_MAGIC) + 1 + 8
    _CODE_MAP: typing.ClassVar[dict[str, str]] = {
        'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
        'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
        'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
        'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA', 'A': '(&Tav',
        'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(', 'H': '&GH+',
        'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB', 'N': '(*HSA$i',
        'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&', 'T': '|QG6',
        'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&', ' ': 'R7a{',
        '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!', '@': 'l@', '!': '/A',
        '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[', '}': '9j', '[': '[a)',
        ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA', ';': 'K}N=O', ':': 'YGOI&Ah',
        '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha', ',': 'I8ys#', '0': '(HPA7', '1': '}v',
        '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD', '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA',
        '9': 'U&G*C', '"': 'I(a-s'
    }
    _CODE_TRANSLATION: typing.ClassVar[dict[int, str]] = (lambda m: {ord(k): v for k, v in m.items()})(_CODE_MAP)
    _CODE_TRANSLATION_TABLE: typing.ClassVar[tuple[str, ...]] = (lambda t: tuple(t.get(i, chr(i)) for i in range(256)))(_CODE_TRANSLATION)
    _DECODE_MAP: typing.ClassVar[dict[str, str]] = {v: k for k, v in _CODE_MAP.items()}
    _DECODE_PATTERN = _re_module.compile(
        "|".join(
            _re_module.escape(token) for token in sorted(_DECODE_MAP, key=len, reverse=True)
        )
    )
    _MD_CODE_TABLE: typing.ClassVar[tuple[str, ...]] = tuple(
        f"{len(str(i))}{i}" for i in range(256)
    )
    # Pre-computed bytes lookup for faster _mdcode_ascii
    _MD_CODE_TABLE_BYTES: typing.ClassVar[tuple[bytes, ...]] = tuple(
        f"{len(str(i))}{i}".encode("ascii") for i in range(256)
    )
    _DECIMAL_BYTES_THRESHOLD = 4096

    # Base32hex alphabet for fast encoding
    _B32HEX_ALPHABET = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
    # Fast decode LUT: maps ASCII byte -> 5-bit value (255 = invalid)
    _B32HEX_DECODE_LUT: typing.ClassVar[bytes] = bytes(
        [255] * 48 + list(range(10)) + [255] * 7 + list(range(10, 32)) + [255] * 6 +
        list(range(10, 32)) + [255] * 153
    )
    _B32_FAST_THRESHOLD = 1024  # Use NumPy for data >= this size
    # Threshold for _mdcode_ascii optimization (tuned via microbenchmarks)
    # List comprehension is faster than generator for inputs > 500 chars
    _MDCODE_ASCII_THRESHOLD = 500

    @staticmethod
    def _fast_b32hexencode(data: bytes) -> bytes:
        """NumPy-accelerated base32hex encoding (18x faster than stdlib)."""
        np = basefwx.np
        arr = np.frombuffer(data, dtype=np.uint8)

        # Pad to multiple of 5 bytes
        pad_len = (5 - len(arr) % 5) % 5
        if pad_len:
            arr = np.concatenate([arr, np.zeros(pad_len, dtype=np.uint8)])

        # Reshape into groups of 5 bytes (40 bits each)
        groups = arr.reshape(-1, 5)

        # Extract 8 x 5-bit values from each 40-bit group
        out = np.empty((len(groups), 8), dtype=np.uint8)
        out[:, 0] = groups[:, 0] >> 3
        out[:, 1] = ((groups[:, 0] & 0x07) << 2) | (groups[:, 1] >> 6)
        out[:, 2] = (groups[:, 1] >> 1) & 0x1F
        out[:, 3] = ((groups[:, 1] & 0x01) << 4) | (groups[:, 2] >> 4)
        out[:, 4] = ((groups[:, 2] & 0x0F) << 1) | (groups[:, 3] >> 7)
        out[:, 5] = (groups[:, 3] >> 2) & 0x1F
        out[:, 6] = ((groups[:, 3] & 0x03) << 3) | (groups[:, 4] >> 5)
        out[:, 7] = groups[:, 4] & 0x1F

        # Map to base32hex alphabet
        b32_lut = np.frombuffer(basefwx._B32HEX_ALPHABET, dtype=np.uint8)
        result = b32_lut[out.ravel()]

        # Handle padding
        if pad_len:
            pad_chars = [0, 6, 4, 3, 1][pad_len]
            if pad_chars:
                result[-pad_chars:] = ord('=')

        return result.tobytes()

    @staticmethod
    def _fast_b32hexdecode(data: bytes) -> bytes:
        """NumPy-accelerated base32hex decoding."""
        np = basefwx.np

        # Count and remove padding
        pad_count = 0
        while data and data[-1 - pad_count] == ord('='):
            pad_count += 1
        if pad_count:
            data = data[:-pad_count]

        arr = np.frombuffer(data, dtype=np.uint8)

        # Decode using LUT
        lut = np.frombuffer(basefwx._B32HEX_DECODE_LUT, dtype=np.uint8)
        vals = lut[arr]

        # Pad to multiple of 8
        pad_to_8 = (8 - len(vals) % 8) % 8
        if pad_to_8:
            vals = np.concatenate([vals, np.zeros(pad_to_8, dtype=np.uint8)])

        # Reshape into groups of 8 x 5-bit values
        groups = vals.reshape(-1, 8)

        # Combine 8 x 5-bit values into 5 bytes
        out = np.empty((len(groups), 5), dtype=np.uint8)
        out[:, 0] = (groups[:, 0] << 3) | (groups[:, 1] >> 2)
        out[:, 1] = (groups[:, 1] << 6) | (groups[:, 2] << 1) | (groups[:, 3] >> 4)
        out[:, 2] = (groups[:, 3] << 4) | (groups[:, 4] >> 1)
        out[:, 3] = (groups[:, 4] << 7) | (groups[:, 5] << 2) | (groups[:, 6] >> 3)
        out[:, 4] = (groups[:, 6] << 5) | groups[:, 7]

        result = out.ravel().tobytes()

        # Remove padding bytes
        if pad_count:
            # Map = count to bytes to remove: 6->4, 4->3, 3->2, 1->1
            remove = [0, 1, 0, 2, 3, 0, 4][pad_count]
            if remove:
                result = result[:-remove]

        return result

    @staticmethod
    def _require_pil() -> None:
        if basefwx.Image is None:
            raise RuntimeError("Pillow is required for image operations (pip install Pillow)")

    class _ProgressReporter:
        """Lightweight textual progress reporter with two WinRAR-style bars."""

        def __init__(self, total_files: int, stream=None, min_interval: float = 0.1):
            self.total_files = max(total_files, 1)
            self.stream = stream or basefwx.sys.stdout
            self._printed = False
            self._min_interval = max(0.0, float(min_interval))
            self._is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
            self._last_render = 0.0
            self._last_fraction: dict[int, float] = {}
            self._lock = basefwx.threading.Lock()
            # Get terminal width, default to 80 if not available
            try:
                import shutil
                self._term_width = shutil.get_terminal_size().columns
            except Exception:
                self._term_width = 80
            
            # Try to import colorama for cross-platform color support
            try:
                import colorama
                self._has_colors = True
                self._green = colorama.Fore.GREEN
                self._reset = colorama.Fore.RESET
            except ImportError:
                self._has_colors = False
                self._green = ""
                self._reset = ""
            term = basefwx.os.getenv("TERM")
            self._supports_ansi = self._is_tty and (
                basefwx.os.name != "nt"
                or self._has_colors
                or basefwx.os.getenv("WT_SESSION")
                or basefwx.os.getenv("ANSICON")
                or (term and term != "dumb")
            )
                
        def reset_terminal_state(self):
            """Ensure terminal is in a clean state for subsequent output"""
            with self._lock:
                if self._printed:
                    # Always print a newline to ensure the cursor is at the start of a fresh line
                    try:
                        self.stream.write("\n")
                        self.stream.flush()
                    except Exception:
                        print()
                self._printed = False

        def _render_bar(self, fraction: float, width: int | None = None) -> str:
            width = width or basefwx.PROGRESS_BAR_WIDTH
            fraction = max(0.0, min(1.0, fraction))
            filled = int(fraction * width)
            
            # Style similar to bar.py - use block characters for filled part
            if filled >= width and fraction >= 1.0:
                bar = '❚' * width  # Use block character for filled bar
                if self._has_colors:
                    return f"({self._green}{'❚' * width}{self._reset})"
                return f"({'❚' * width})"
            else:
                filled_part = '❚' * filled
                empty_part = ' ' * (width - filled)
                # No color when not complete
                return f"({filled_part}{empty_part})"

        @staticmethod
        def _format_size_hint(size_hint: "basefwx.typing.Tuple[int, int]") -> str:
            src, dst = size_hint
            return f"{basefwx._human_readable_size(src)} -> {basefwx._human_readable_size(dst)}"

        def _write(self, line1: str, line2: str, force: bool = False) -> None:
            now = basefwx.time.monotonic()
            
            # Rate limiting: skip if too soon since last update (unless forced)
            if not force and self._printed and (now - self._last_render) < self._min_interval:
                return
            
            # Instead of truncating with ellipsis, we'll preserve filenames by intelligently trimming
            # middle parts of the line if needed
            max_width = self._term_width
            
            # For line1, simple truncation is fine as it doesn't contain filenames
            if len(line1) > max_width:
                line1 = line1[:max_width]
                
            # For line2, we need to be smarter to preserve filenames
            if len(line2) > max_width:
                # Extract parts of the line - we want to keep the filename in brackets intact
                parts = line2.split("[")
                
                if len(parts) > 1:
                    # We have something in brackets
                    prefix = parts[0]  # Everything before the [
                    
                    # Get the content including and after the bracket
                    rest = "[" + "[".join(parts[1:])
                    
                    # Further split to isolate the filename
                    filename_parts = rest.split("]", 1)
                    if len(filename_parts) > 1:
                        # We have found a proper [...] bracket pair
                        filename = filename_parts[0] + "]"  # The filename with brackets
                        suffix = filename_parts[1] if len(filename_parts) > 1 else ""
                        
                        # Calculate available space
                        avail_prefix_space = max(10, max_width - len(filename) - len(suffix) - 5)
                        
                        # Make sure we show the most important parts
                        if len(prefix) > avail_prefix_space:
                            prefix = prefix[:avail_prefix_space]
                        
                        # Construct the line with priority to filename
                        line2 = prefix + filename + suffix
                        
                        # Final safety check
                        if len(line2) > max_width:
                            line2 = line2[:max_width]
                    else:
                        # No closing bracket found, just truncate
                        line2 = line2[:max_width]
                else:
                    # No brackets found, just truncate
                    line2 = line2[:max_width]
            
            if self._is_tty and self._supports_ansi:
                # Two-line in-place update using ANSI cursor controls.
                if self._printed:
                    # Move cursor up one line and return to column 0.
                    self.stream.write("\x1b[1A\r")
                else:
                    # Clear any partial line (e.g. unittest dots) before first render.
                    self.stream.write("\r\x1b[2K")
                # Clear and render line1.
                self.stream.write("\r\x1b[2K")
                self.stream.write(line1)
                self.stream.write("\n")
                # Clear and render line2.
                self.stream.write("\r\x1b[2K")
                self.stream.write(line2)
                self.stream.flush()
            elif self._is_tty:
                # Best-effort fallback without ANSI cursor movement.
                if not self._printed:
                    try:
                        self.stream.write("\r")
                        self.stream.write(" " * self._term_width)
                        self.stream.write("\r")
                    except Exception:
                        pass
                try:
                    self.stream.write(line1 + "\n")
                    self.stream.write(line2)
                    self.stream.flush()
                except Exception:
                    print(line1)
                    print(line2, end="")
            else:
                # Non-TTY mode: only print on first call or when forced
                if not self._printed or force:
                    try:
                        self.stream.write(line1 + "\n")
                        self.stream.write(line2 + "\n")
                        self.stream.flush()
                    except Exception:
                        print(line1)
                        print(line2)
            
            self._printed = True
            self._last_render = now

        def update(
            self,
            file_index: int,
            fraction: float,
            phase: str,
            path: "basefwx.pathlib.Path",
            *,
            size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        ) -> None:
            # clamp fraction and ensure float
            fraction = max(0.0, min(1.0, float(fraction)))

            with self._lock:
                # Track per-file progress to support parallel updates.
                self._last_fraction[file_index] = fraction
                overall_fraction = sum(self._last_fraction.values()) / self.total_files
                overall = self._render_bar(overall_fraction)
                current = self._render_bar(fraction)

                # files complete counter: count fully finished files
                completed_files = sum(1 for frac in self._last_fraction.values() if frac >= 1.0)

                label = path.name if path else ""
                # build status message: show progress correctly
                if self.total_files == 1:
                    if fraction < 0.1:  # Show progress on current file in early stages
                        status_text = f"processing {label}" if label else "processing"
                    elif fraction < 1.0:
                        status_text = f"{phase} {label}" if label else phase
                    else:
                        status_text = "complete"
                else:
                    if fraction < 1.0:
                        status_text = f"{completed_files} complete, processing {label}" if label else f"{completed_files} complete"
                    else:
                        status_text = f"{completed_files}/{self.total_files} files"

                # Format similar to bar.py with better spacing
                percent_overall = f"{overall_fraction * 100:3.0f}%"
                percent_file = f"{fraction * 100:3.0f}%"

                hint_text = f" ({self._format_size_hint(size_hint)})" if size_hint else ""
                label_text = f" [{label}]" if label else ""

                # Clean formatting with consistent spacing
                line1 = f"Overall {overall} {percent_overall} {status_text}"
                line2 = f"File    {current} {percent_file} phase: {phase}{hint_text}{label_text}"

                # Remove any possible newline characters that might be in the phase name
                line1 = line1.replace("\n", " ")
                line2 = line2.replace("\n", " ")

                # normal write path; force final updates so 100% renders
                force = fraction >= 1.0 or overall_fraction >= 1.0
                self._write(line1, line2, force=force)

        def finalize_file(
            self,
            file_index: int,
            path: "basefwx.pathlib.Path",
            *,
            size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        ) -> None:
            with self._lock:
                # always print final completion status
                self._last_fraction[file_index] = 1.0
                overall_fraction = sum(self._last_fraction.values()) / self.total_files
                overall = self._render_bar(overall_fraction)
                label = path.name if path else ""
                current = self._render_bar(1.0)

                # Format like bar.py with completion indicator
                percent_overall = f"{overall_fraction * 100:3.0f}%"
                status_text = f"{sum(1 for frac in self._last_fraction.values() if frac >= 1.0)}/{self.total_files} files"

                hint_text = f" ({self._format_size_hint(size_hint)})" if size_hint else ""
                label_text = f" [{label}]" if label else ""

                # Show green checkmark for completed file
                completion_indicator = f" {self._green}✓{self._reset}" if self._has_colors else " ✓"

                line1 = f"Overall {overall} {percent_overall} {status_text}"
                line2 = f"File    {current} 100% phase: done{hint_text}{label_text}{completion_indicator}"

                # force final output (overwriting in TTY or printing in non-TTY)
                self._write(line1, line2, force=True)

                # Print a newline to finalize the output
                try:
                    self.stream.write("\n")
                    self.stream.flush()
                except Exception:
                    print()

                # Reset the printed state so future progress starts fresh
                self._printed = False

            

    @staticmethod
    def _human_readable_size(num_bytes: int) -> str:
        units = ["B", "KiB", "MiB", "GiB"]
        value = float(num_bytes)
        for unit in units:
            if value < 1024.0 or unit == units[-1]:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} TiB"

    @staticmethod
    def _del(varname: str) -> None:
        try:
            frame = basefwx.sys._getframe(1)
        except Exception:
            return
        try:
            if varname in frame.f_locals:
                frame.f_locals[varname] = None
        except Exception:
            pass

    @staticmethod
    def _hkdf(info: bytes, key: bytes, length: int = 32) -> bytes:
        hk = basefwx.HKDF(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hk.derive(key)

    @staticmethod
    def _splitmix64(state: int) -> "basefwx.typing.Tuple[int, int]":
        z = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        x = z
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9 & ((1 << 64) - 1)
        x = (x ^ (x >> 27)) * 0x94D049BB133111EB & ((1 << 64) - 1)
        x = x ^ (x >> 31)
        return z, x & ((1 << 64) - 1)

    @staticmethod
    def _permute_inplace(data: bytearray, seed: int) -> None:
        n = len(data)
        if n >= basefwx.PERM_FAST_MIN:
            rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed & ((1 << 64) - 1)))
            perm = rng.permutation(n)
            arr = basefwx.np.frombuffer(memoryview(data), dtype=basefwx.np.uint8)
            out = arr.take(perm)
            arr[:] = out
            return
        st = seed & ((1 << 64) - 1)
        for i in range(n - 1, 0, -1):
            st, rnd = basefwx._splitmix64(st)
            j = rnd % (i + 1)
            if j != i:
                data[i], data[j] = data[j], data[i]

    @staticmethod
    def _unpermute_inplace(data: bytearray, seed: int) -> None:
        n = len(data)
        if n >= basefwx.PERM_FAST_MIN:
            rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed & ((1 << 64) - 1)))
            perm = rng.permutation(n)
            inv = basefwx.np.empty_like(perm)
            inv[perm] = basefwx.np.arange(n, dtype=perm.dtype)
            arr = basefwx.np.frombuffer(memoryview(data), dtype=basefwx.np.uint8)
            out = arr.take(inv)
            arr[:] = out
            return
        swaps = []
        st = seed & ((1 << 64) - 1)
        for i in range(n - 1, 0, -1):
            st, rnd = basefwx._splitmix64(st)
            j = rnd % (i + 1)
            swaps.append((i, j))
        for i, j in reversed(swaps):
            if j != i:
                data[i], data[j] = data[j], data[i]

    @staticmethod
    def _xor_keystream_inplace(buf: bytearray, key: bytes, info: bytes = OBF_INFO_MASK) -> None:
        if not buf:
            return
        n = len(buf)
        block_key = basefwx._hkdf(info, key, 32)
        ctr = 0
        total_len_bytes = n.to_bytes(8, 'big')
        if n >= basefwx.OFB_FAST_MIN:
            mv = memoryview(buf)
            arr = basefwx.np.frombuffer(mv, dtype=basefwx.np.uint8)
            offset = 0
            while offset < n:
                h = basefwx.hmac.HMAC(block_key, basefwx.hashes.SHA256())
                meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
                h.update(meta)
                block = h.finalize()
                take = min(len(block), n - offset)
                block_arr = basefwx.np.frombuffer(block, dtype=basefwx.np.uint8)
                basefwx.np.bitwise_xor(
                    arr[offset:offset + take],
                    block_arr[:take],
                    out=arr[offset:offset + take]
                )
                offset += take
                ctr += 1
            return
        off = 0
        while off < n:
            h = basefwx.hmac.HMAC(block_key, basefwx.hashes.SHA256())
            meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
            h.update(meta)
            block = h.finalize()
            take = min(len(block), n - off)
            for i in range(take):
                buf[off + i] ^= block[i]
            off += take
            ctr += 1

    @staticmethod
    def _obfuscate_bytes(data: bytes, ephemeral_key: bytes, *, fast: bool = False) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        if not fast:
            perm_seed_bytes = basefwx._hkdf(
                basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
                ephemeral_key,
                16
            )
            perm_seed = int.from_bytes(perm_seed_bytes, 'big')
            out.reverse()
            basefwx._permute_inplace(out, perm_seed)
            basefwx._del('perm_seed')
        return bytes(out)

    @staticmethod
    def _deobfuscate_bytes(data: bytes, ephemeral_key: bytes, *, fast: bool = False) -> bytes:
        if not data:
            return data
        out = bytearray(data)
        if not fast:
            perm_seed_bytes = basefwx._hkdf(
                basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
                ephemeral_key,
                16
            )
            perm_seed = int.from_bytes(perm_seed_bytes, 'big')
            basefwx._unpermute_inplace(out, perm_seed)
            out.reverse()
            basefwx._del('perm_seed')
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        return bytes(out)

    class _StreamObfuscator:
        """Chunked obfuscation helper for large AES-heavy payloads."""

        _SALT_LEN = 16

        def __init__(self, cipher, perm_material: bytes, fast: bool):
            self._cipher = cipher
            self._perm_material = perm_material
            self._chunk_index = 0
            self._fast = fast

        @staticmethod
        def generate_salt() -> bytes:
            return basefwx.os.urandom(basefwx._StreamObfuscator._SALT_LEN)

        @classmethod
        def for_password(
            cls,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            salt: bytes,
            fast: bool = False
        ) -> "_StreamObfuscator":
            if not password:
                raise ValueError("Password required for streaming obfuscation")
            if len(salt) < cls._SALT_LEN:
                raise ValueError("Streaming obfuscation salt must be at least 16 bytes")
            base_material = basefwx._coerce_password_bytes(password) + salt
            mask_key = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_KEY, length=32)
            iv = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_IV, length=16)
            perm_material = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_PERM, length=32)
            cipher = basefwx.Cipher(basefwx.algorithms.AES(mask_key), basefwx.modes.CTR(iv)).encryptor()
            return cls(cipher, perm_material, fast)

        def _next_params(self) -> "basefwx.typing.Tuple[int, int, bool]":
            idx_bytes = self._chunk_index.to_bytes(8, 'big')
            seed_bytes = basefwx._hkdf_sha256(
                self._perm_material,
                info=basefwx.STREAM_INFO_PERM + idx_bytes,
                length=16
            )
            self._chunk_index += 1
            perm_seed = int.from_bytes(seed_bytes, 'big')
            rotation = seed_bytes[0] & 0x07  # 0-7 bits
            swap = bool(seed_bytes[1] & 0x01)
            return perm_seed, rotation, swap

        @staticmethod
        def _rotate_left_inplace(arr: "basefwx.np.ndarray", rotation: int) -> None:
            if rotation == 0:
                return
            left = basefwx.np.left_shift(arr, rotation) & 0xFF
            right = basefwx.np.right_shift(arr, 8 - rotation)
            basefwx.np.bitwise_or(left, right, out=arr, casting='unsafe')

        @staticmethod
        def _rotate_right_inplace(arr: "basefwx.np.ndarray", rotation: int) -> None:
            if rotation == 0:
                return
            right = basefwx.np.right_shift(arr, rotation)
            left = (basefwx.np.left_shift(arr, 8 - rotation)) & 0xFF
            basefwx.np.bitwise_or(left, right, out=arr, casting='unsafe')

        @staticmethod
        def _swap_nibbles_inplace(arr: "basefwx.np.ndarray") -> None:
            high = basefwx.np.right_shift(arr, 4)
            low = (arr & 0x0F) << 4
            basefwx.np.bitwise_or(high, low, out=arr, casting='unsafe')

        def encode_chunk(self, chunk: bytes) -> bytes:
            if not chunk:
                return b""
            if self._fast:
                buffer = bytearray(chunk)
                mask = self._cipher.update(bytes(len(buffer)))
                if mask:
                    arr = basefwx.np.frombuffer(memoryview(buffer), dtype=basefwx.np.uint8)
                    mask_arr = basefwx.np.frombuffer(mask, dtype=basefwx.np.uint8)
                    basefwx.np.bitwise_xor(arr, mask_arr, out=arr)
                self._chunk_index += 1
                return bytes(buffer)
            perm_seed, rotation, swap = self._next_params()
            buffer = bytearray(chunk)
            mask = self._cipher.update(bytes(len(buffer)))
            if mask:
                arr = basefwx.np.frombuffer(memoryview(buffer), dtype=basefwx.np.uint8)
                mask_arr = basefwx.np.frombuffer(mask, dtype=basefwx.np.uint8)
                basefwx.np.bitwise_xor(arr, mask_arr, out=arr)
                if swap:
                    basefwx._StreamObfuscator._swap_nibbles_inplace(arr)
                if rotation:
                    basefwx._StreamObfuscator._rotate_left_inplace(arr, rotation)
            basefwx._permute_inplace(buffer, perm_seed)
            return bytes(buffer)

        def decode_chunk(self, chunk: bytes) -> bytes:
            if not chunk:
                return b""
            if self._fast:
                buffer = bytearray(chunk)
                mask = self._cipher.update(bytes(len(buffer)))
                if mask:
                    arr = basefwx.np.frombuffer(memoryview(buffer), dtype=basefwx.np.uint8)
                    mask_arr = basefwx.np.frombuffer(mask, dtype=basefwx.np.uint8)
                    basefwx.np.bitwise_xor(arr, mask_arr, out=arr)
                self._chunk_index += 1
                return bytes(buffer)
            perm_seed, rotation, swap = self._next_params()
            buffer = bytearray(chunk)
            basefwx._unpermute_inplace(buffer, perm_seed)
            arr = basefwx.np.frombuffer(memoryview(buffer), dtype=basefwx.np.uint8)
            if rotation:
                basefwx._StreamObfuscator._rotate_right_inplace(arr, rotation)
            if swap:
                basefwx._StreamObfuscator._swap_nibbles_inplace(arr)
            mask = self._cipher.update(bytes(len(buffer)))
            if mask:
                mask_arr = basefwx.np.frombuffer(mask, dtype=basefwx.np.uint8)
                basefwx.np.bitwise_xor(arr, mask_arr, out=arr)
            return bytes(buffer)

        @classmethod
        def encode_file(
            cls,
            src_path: "basefwx.pathlib.Path",
            dst_handle: "basefwx.typing.Optional[basefwx.typing.Any]",
            password: str,
            salt: bytes,
            *,
            chunk_size: int,
            fast: bool = False,
            forward_chunk: "basefwx.typing.Callable[[bytes], None]",
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
        ) -> int:
            encoder = cls.for_password(password, salt, fast=fast)
            total = src_path.stat().st_size
            processed = 0
            with open(src_path, 'rb') as src:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    obf_chunk = encoder.encode_chunk(chunk)
                    if dst_handle is not None:
                        dst_handle.write(obf_chunk)
                    forward_chunk(obf_chunk)
                    processed += len(chunk)
                    if progress_cb:
                        progress_cb(processed, total)
            return processed

        @classmethod
        def decode_file(
            cls,
            src_handle,
            dst_handle,
            password: str,
            salt: bytes,
            *,
            chunk_size: int,
            total_plain: int,
            fast: bool = False,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
        ) -> int:
            decoder = cls.for_password(password, salt, fast=fast)
            processed = 0
            while processed < total_plain:
                to_read = min(chunk_size, total_plain - processed)
                chunk = src_handle.read(to_read)
                if not chunk:
                    raise ValueError("Streaming decode truncated input")
                plain = decoder.decode_chunk(chunk)
                dst_handle.write(plain)
                processed += len(plain)
                if progress_cb:
                    progress_cb(processed, total_plain)
            return processed

    @staticmethod
    def _build_metadata(
        method: str,
        strip: bool,
        use_master: bool,
        *,
        aead: str = "AESGCM",
        kdf: "basefwx.typing.Optional[str]" = None,
        mode: "basefwx.typing.Optional[str]" = None,
        obfuscation: "basefwx.typing.Optional[basefwx.typing.Union[bool, str]]" = None,
        kdf_iters: "basefwx.typing.Optional[int]" = None,
        argon2_time_cost: "basefwx.typing.Optional[int]" = None,
        argon2_memory_cost: "basefwx.typing.Optional[int]" = None,
        argon2_parallelism: "basefwx.typing.Optional[int]" = None,
        pack: "basefwx.typing.Optional[str]" = None
    ) -> str:
        if strip:
            return ""
        timestamp = basefwx.datetime.now(basefwx.timezone.utc).isoformat().replace("+00:00", "Z")
        version = getattr(basefwx, "__version__", basefwx.ENGINE_VERSION)
        kdf_label = (kdf or basefwx.USER_KDF or "argon2id").lower()
        info = {
            "ENC-TIME": timestamp,
            "ENC-VERSION": version,
            "ENC-METHOD": method,
            "ENC-MASTER": "yes" if use_master else "no",
            "ENC-KEM": basefwx.MASTER_PQ_ALG if use_master else "none",
            "ENC-AEAD": aead,
            "ENC-KDF": kdf_label
        }
        if mode:
            info["ENC-MODE"] = mode
        if obfuscation is not None:
            if isinstance(obfuscation, str):
                info["ENC-OBF"] = obfuscation.lower()
            else:
                info["ENC-OBF"] = "yes" if obfuscation else "no"
        if kdf_iters is not None:
            info["ENC-KDF-ITER"] = str(kdf_iters)
        if argon2_time_cost is not None:
            info["ENC-ARGON2-TC"] = str(argon2_time_cost)
        if argon2_memory_cost is not None:
            info["ENC-ARGON2-MEM"] = str(argon2_memory_cost)
        if argon2_parallelism is not None:
            info["ENC-ARGON2-PAR"] = str(argon2_parallelism)
        if pack:
            info[basefwx.PACK_META_KEY] = str(pack)
        data = basefwx.json.dumps(info, separators=(',', ':')).encode('utf-8')
        return basefwx.base64.b64encode(data).decode('utf-8')

    @staticmethod
    def _decode_metadata(blob: str) -> "basefwx.typing.Dict[str, basefwx.typing.Any]":
        if not blob:
            return {}
        try:
            raw = basefwx.base64.b64decode(blob.encode('utf-8'))
            return basefwx.json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    @staticmethod
    def _split_metadata(payload: str) -> "basefwx.typing.Tuple[str, str]":
        if basefwx.META_DELIM in payload:
            return payload.split(basefwx.META_DELIM, 1)
        return "", payload

    @staticmethod
    def _split_with_delims(
        payload: str,
        delims: "basefwx.typing.Iterable[str]",
        label: str
    ) -> "basefwx.typing.Tuple[str, str]":
        for delim in delims:
            if delim and delim in payload:
                return payload.split(delim, 1)
        raise ValueError(f"Malformed {label} payload")

    @staticmethod
    def _apply_strip_attributes(path: "basefwx.pathlib.Path") -> None:
        try:
            basefwx.os.utime(path, (0, 0))
        except Exception:
            pass

    @staticmethod
    def _remove_input(
        path: "basefwx.pathlib.Path",
        keep_input: bool,
        output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
    ) -> None:
        if keep_input:
            return
        try:
            if output_path is not None:
                norm_in = basefwx._normalize_path(path)
                norm_out = basefwx._normalize_path(output_path)
                if norm_in == norm_out:
                    return
        except Exception:
            pass
        try:
            if path.is_dir():
                basefwx.shutil.rmtree(path)
            else:
                basefwx.os.remove(path)
        except FileNotFoundError:
            pass

    @staticmethod
    def _pack_mode_for_path(path: "basefwx.pathlib.Path", compress: bool) -> str:
        if path.is_dir():
            return basefwx.PACK_TAR_XZ if compress else basefwx.PACK_TAR_GZ
        if compress:
            return basefwx.PACK_TAR_XZ
        return ""

    @staticmethod
    def _pack_input_to_archive(
        path: "basefwx.pathlib.Path",
        compress: bool,
        reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
        file_index: int = 0
    ) -> "basefwx.typing.Optional[tuple[basefwx.pathlib.Path, str, basefwx.tempfile.TemporaryDirectory]]":
        pack_flag = basefwx._pack_mode_for_path(path, compress)
        if not pack_flag:
            return None
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-pack-")
        base_name = path.stem if path.is_file() else path.name
        suffix = basefwx.PACK_SUFFIX_XZ if pack_flag == basefwx.PACK_TAR_XZ else basefwx.PACK_SUFFIX_GZ
        archive_path = basefwx.pathlib.Path(temp_dir.name) / f"{base_name}{suffix}"
        if reporter:
            reporter.update(file_index, 0.08, "pack", path)
        mode = "w:xz" if pack_flag == basefwx.PACK_TAR_XZ else "w:gz"
        tar_kwargs: dict[str, basefwx.typing.Any] = {}
        if pack_flag == basefwx.PACK_TAR_XZ:
            tar_kwargs["preset"] = 9 | basefwx.lzma.PRESET_EXTREME
        else:
            tar_kwargs["compresslevel"] = 1
        with basefwx.tarfile.open(archive_path, mode, **tar_kwargs) as tar:
            tar.add(path, arcname=path.name)
        return archive_path, pack_flag, temp_dir

    @staticmethod
    def _is_safe_tar_path(base_dir: "basefwx.pathlib.Path", member_name: str) -> bool:
        if not member_name:
            return False
        member_path = basefwx.pathlib.PurePosixPath(member_name)
        if member_path.is_absolute():
            return False
        if ".." in member_path.parts:
            return False
        resolved_base = base_dir.resolve()
        resolved_target = (base_dir / member_path.as_posix()).resolve(strict=False)
        return resolved_base == resolved_target or resolved_base in resolved_target.parents

    @staticmethod
    def _unpack_archive(
        archive_path: "basefwx.pathlib.Path",
        pack_flag: str,
        reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
        file_index: int = 0,
        target_dir: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
    ) -> "basefwx.pathlib.Path":
        mode = "r:xz" if pack_flag == basefwx.PACK_TAR_XZ else "r:gz"
        target_dir = target_dir or archive_path.parent
        roots: "basefwx.typing.Set[str]" = set()
        if reporter:
            reporter.update(file_index, 0.9, "unpack", archive_path)
        with basefwx.tarfile.open(archive_path, mode) as tar:
            members = tar.getmembers()
            for member in members:
                if not basefwx._is_safe_tar_path(target_dir, member.name):
                    raise ValueError("Unsafe archive entry detected")
                parts = basefwx.pathlib.PurePosixPath(member.name).parts
                if parts:
                    roots.add(parts[0])
            tar.extractall(target_dir)
        try:
            archive_path.unlink()
        except FileNotFoundError:
            pass
        if len(roots) == 1:
            return target_dir / next(iter(roots))
        return target_dir

    @staticmethod
    def _pack_flag_from_meta(meta: "basefwx.typing.Dict[str, basefwx.typing.Any]", ext: str) -> str:
        flag = (meta.get(basefwx.PACK_META_KEY) or "").lower() if meta else ""
        if flag in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
            return flag
        ext_lower = (ext or "").lower()
        if ext_lower == basefwx.PACK_SUFFIX_GZ:
            return basefwx.PACK_TAR_GZ
        if ext_lower == basefwx.PACK_SUFFIX_XZ:
            return basefwx.PACK_TAR_XZ
        return ""

    @staticmethod
    def _maybe_unpack_output(
        path: "basefwx.pathlib.Path",
        pack_flag: str,
        reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
        file_index: int = 0,
        strip_metadata: bool = False
    ) -> "basefwx.pathlib.Path":
        if not pack_flag:
            return path
        extracted = basefwx._unpack_archive(path, pack_flag, reporter, file_index)
        if strip_metadata:
            try:
                basefwx._apply_strip_attributes(extracted)
            except Exception:
                pass
        return extracted

    @staticmethod
    def _warn_on_metadata(meta: "basefwx.typing.Dict[str, basefwx.typing.Any]", expected_method: str) -> None:
        if not meta:
            return
        recorded_method = meta.get("ENC-METHOD")
        recorded_version = meta.get("ENC-VERSION")
        hints = []
        if recorded_method and recorded_method != expected_method:
            hints.append(recorded_method)
        if recorded_version and recorded_version != basefwx.ENGINE_VERSION:
            hints.append(recorded_version)
        if hints:
            print("Did you mean to use:\n" + " or ".join(hints))

    @staticmethod
    def _decode_pubkey_bytes(raw: bytes) -> bytes:
        """Best-effort decoding pipeline supporting raw/zlib/base64 inputs."""
        if not raw:
            return raw
        candidates = []
        for candidate in (raw, raw.strip()):
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        # Try base64 decode on each candidate; append successful variants
        decoded_variants = []
        for candidate in candidates:
            try:
                decoded = basefwx.base64.b64decode(candidate, validate=True)
            except Exception:
                continue
            if decoded not in candidates and decoded not in decoded_variants:
                decoded_variants.append(decoded)
        candidates.extend(decoded_variants)
        for candidate in candidates:
            try:
                return basefwx.zlib.decompress(candidate)
            except Exception:
                continue
        return candidates[-1] if candidates else raw

    @classmethod
    def _set_master_pubkey_override(cls, data: "basefwx.typing.Optional[bytes]") -> None:
        cls._MASTER_PUBKEY_OVERRIDE = data

    @staticmethod
    def _resolve_master_pubkey_path(cli_arg: "basefwx.typing.Optional[str]") -> "basefwx.typing.Optional[bytes]":
        path_spec = cli_arg or basefwx.os.getenv("BASEFWX_MASTER_PQ_PUB")
        if not path_spec:
            return None
        candidate = basefwx.pathlib.Path(path_spec).expanduser()
        if not candidate.exists():
            raise FileNotFoundError(f"Master PQ public key not found at {candidate}")
        return basefwx._decode_pubkey_bytes(candidate.read_bytes())

    @staticmethod
    def _load_master_pq_public() -> "basefwx.typing.Optional[bytes]":
        if basefwx._MASTER_PUBKEY_OVERRIDE:
            return basefwx._MASTER_PUBKEY_OVERRIDE
        env_path = basefwx.os.getenv("BASEFWX_MASTER_PQ_PUB")
        if env_path:
            return basefwx._resolve_master_pubkey_path(env_path)
        if basefwx.os.getenv("ALLOW_BAKED_PUB") == "1":
            return basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTER_PQ_PUBLIC))
        return None

    @staticmethod
    def _load_master_pq_private() -> bytes:
        candidates = (
            basefwx.pathlib.Path('~/master_pq.sk').expanduser(),
            basefwx.pathlib.Path(r'W:\master_pq.sk')
        )
        for path in candidates:
            if path.exists():
                data = path.read_bytes()
                try:
                    text = data.decode('utf-8').strip()
                    return basefwx.zlib.decompress(basefwx.base64.b64decode(text))
                except Exception:
                    try:
                        return basefwx.zlib.decompress(data)
                    except Exception:
                        return data
        raise FileNotFoundError('No master_pq.sk private key found')

    @staticmethod
    def _default_master_ec_public_path() -> "basefwx.pathlib.Path":
        return basefwx.pathlib.Path('~/master_ec_public.pem').expanduser()

    @staticmethod
    def _default_master_ec_private_path() -> "basefwx.pathlib.Path":
        return basefwx.pathlib.Path('~/master_ec_private.pem').expanduser()

    @staticmethod
    def _decode_ec_public_key(raw: bytes) -> "basefwx.ec.EllipticCurvePublicKey":
        if not raw:
            raise ValueError("Empty EC public key data")
        loaders = (
            lambda data: basefwx.serialization.load_pem_public_key(data),
            lambda data: basefwx.serialization.load_pem_private_key(data, password=None).public_key(),
            lambda data: basefwx.serialization.load_der_public_key(data),
            lambda data: basefwx.serialization.load_der_private_key(data, password=None).public_key(),
        )
        for loader in loaders:
            try:
                key = loader(raw)
            except Exception:
                continue
            if isinstance(key, basefwx.ec.EllipticCurvePublicKey):
                return key
        raise ValueError("Unsupported EC public key format")

    @staticmethod
    def _decode_ec_private_key(raw: bytes) -> "basefwx.ec.EllipticCurvePrivateKey":
        if not raw:
            raise ValueError("Empty EC private key data")
        loaders = (
            lambda data: basefwx.serialization.load_pem_private_key(data, password=None),
            lambda data: basefwx.serialization.load_der_private_key(data, password=None),
        )
        for loader in loaders:
            try:
                key = loader(raw)
            except Exception:
                continue
            if isinstance(key, basefwx.ec.EllipticCurvePrivateKey):
                return key
        raise ValueError("Unsupported EC private key format")

    @staticmethod
    def _write_ec_keypair(
        public_path: "basefwx.pathlib.Path",
        private_path: "basefwx.pathlib.Path"
    ) -> "tuple[basefwx.ec.EllipticCurvePublicKey, basefwx.ec.EllipticCurvePrivateKey]":
        private_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=basefwx.serialization.Encoding.PEM,
            format=basefwx.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=basefwx.serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=basefwx.serialization.Encoding.PEM,
            format=basefwx.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)
        try:
            basefwx.os.chmod(private_path, 0o600)
        except Exception:
            pass
        try:
            basefwx.os.chmod(public_path, 0o644)
        except Exception:
            pass
        return public_key, private_key

    @staticmethod
    def _load_master_ec_public(
        create_if_missing: bool = False
    ) -> "basefwx.typing.Optional[basefwx.ec.EllipticCurvePublicKey]":
        env_pub = basefwx.os.getenv(basefwx.MASTER_EC_PUBLIC_ENV)
        env_priv = basefwx.os.getenv(basefwx.MASTER_EC_PRIVATE_ENV)
        if env_pub:
            pub_path = basefwx.pathlib.Path(env_pub).expanduser()
            if pub_path.exists():
                return basefwx._decode_ec_public_key(pub_path.read_bytes())
            if create_if_missing:
                priv_path = basefwx.pathlib.Path(env_priv).expanduser() if env_priv else basefwx._default_master_ec_private_path()
                public_key, _ = basefwx._write_ec_keypair(pub_path, priv_path)
                return public_key
            return None
        pub_path = basefwx._default_master_ec_public_path()
        priv_path = basefwx._default_master_ec_private_path()
        if pub_path.exists():
            return basefwx._decode_ec_public_key(pub_path.read_bytes())
        if priv_path.exists():
            private_key = basefwx._decode_ec_private_key(priv_path.read_bytes())
            public_key = private_key.public_key()
            if not pub_path.exists():
                try:
                    pub_path.write_bytes(public_key.public_bytes(
                        encoding=basefwx.serialization.Encoding.PEM,
                        format=basefwx.serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    basefwx.os.chmod(pub_path, 0o644)
                except Exception:
                    pass
            return public_key
        if create_if_missing:
            public_key, _ = basefwx._write_ec_keypair(pub_path, priv_path)
            return public_key
        return None

    @staticmethod
    def _load_master_ec_private() -> "basefwx.ec.EllipticCurvePrivateKey":
        candidates = []
        env_priv = basefwx.os.getenv(basefwx.MASTER_EC_PRIVATE_ENV)
        if env_priv:
            candidates.append(basefwx.pathlib.Path(env_priv).expanduser())
        candidates.append(basefwx._default_master_ec_private_path())
        candidates.append(basefwx.pathlib.Path(r'W:\master_ec_private.pem'))
        for path in candidates:
            if path.exists():
                return basefwx._decode_ec_private_key(path.read_bytes())
        raise FileNotFoundError("No master EC private key found")

    @staticmethod
    def _ec_kem_enc(
        public_key: "basefwx.ec.EllipticCurvePublicKey"
    ) -> "tuple[bytes, bytes]":
        if public_key is None:
            raise ValueError("EC public key required for master wrap")
        ephemeral_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
        shared = ephemeral_key.exchange(basefwx.ec.ECDH(), public_key)
        epk_bytes = ephemeral_key.public_key().public_bytes(
            encoding=basefwx.serialization.Encoding.X962,
            format=basefwx.serialization.PublicFormat.UncompressedPoint
        )
        if len(epk_bytes) > 0xFFFF:
            raise ValueError("EC public key encoding too large")
        header = basefwx.MASTER_EC_MAGIC + len(epk_bytes).to_bytes(2, "big")
        return header + epk_bytes, shared

    @staticmethod
    def _ec_kem_dec(master_blob: bytes) -> bytes:
        if not master_blob.startswith(basefwx.MASTER_EC_MAGIC):
            raise ValueError("Invalid EC master blob")
        if len(master_blob) < 5:
            raise ValueError("Malformed EC master blob")
        length = int.from_bytes(master_blob[3:5], "big")
        start = 5
        end = start + length
        if len(master_blob) < end:
            raise ValueError("Truncated EC master blob")
        epk_bytes = master_blob[start:end]
        public_key = basefwx.ec.EllipticCurvePublicKey.from_encoded_point(
            basefwx.ec.SECP521R1(),
            epk_bytes
        )
        private_key = basefwx._load_master_ec_private()
        return private_key.exchange(basefwx.ec.ECDH(), public_key)

    @staticmethod
    def _resolve_master_usage(
        use_master: bool,
        master_pubkey: "basefwx.typing.Optional[bytes]",
        *,
        create_if_missing: bool = False
    ) -> "tuple[basefwx.typing.Optional[bytes], bool]":
        if not use_master:
            return None, False
        if master_pubkey is not None:
            return master_pubkey, True
        pq_pub = basefwx._load_master_pq_public()
        if pq_pub is not None:
            return pq_pub, True
        try:
            ec_pub = basefwx._load_master_ec_public(create_if_missing=create_if_missing)
        except Exception:
            ec_pub = None
        return None, ec_pub is not None

    @staticmethod
    def _kem_derive_key(shared: bytes, length: int = 32) -> bytes:
        return basefwx._hkdf_sha256(shared, length=length)

    @staticmethod
    def _hkdf_sha256(
        key_material: bytes,
        *,
        length: int = 32,
        info: bytes = b'basefwx.kem.v1'
    ) -> bytes:
        hk = basefwx.HKDF(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hk.derive(key_material)

    @staticmethod
    def _hkdf_stream_sha256(key_material: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand for arbitrary length output (optimized with memoryview)."""
        if length <= 0:
            return b""
        info_bytes = info or b""
        zero_salt = b"\x00" * 32
        prk = basefwx.stdlib_hmac.new(
            zero_salt,
            key_material,
            basefwx.hashlib.sha256
        ).digest()
        out = bytearray(length)
        mv = memoryview(out)
        prev = b""
        offset = 0
        counter = 1
        base_hmac = basefwx.stdlib_hmac.new(prk, digestmod=basefwx.hashlib.sha256)
        counter_bytes = bytearray(4)
        while offset < length:
            h = base_hmac.copy()
            if prev:
                h.update(prev)
            h.update(info_bytes)
            basefwx.struct.pack_into(">I", counter_bytes, 0, counter)
            h.update(counter_bytes)
            block = h.digest()
            take = min(32, length - offset)
            mv[offset:offset + take] = block[:take]
            offset += take
            prev = block
            counter += 1
        return bytes(out)

    @staticmethod
    def _mdcode_ascii(text: str) -> str:
        # Fast path using pre-computed bytes lookup table
        if not text.isascii():
            text.encode("ascii")  # Will raise if not ASCII
        data = text.encode("ascii")
        table = basefwx._MD_CODE_TABLE_BYTES
        
        # Optimization: For large inputs, use list comprehension to reduce
        # intermediate object creation overhead (20-30% faster for large strings).
        # For small inputs, generator expression is memory-efficient.
        # Note: b"".join() accepts any iterable, so list vs generator is transparent
        result_parts = (
            [table[b] for b in data]
            if len(data) > basefwx._MDCODE_ASCII_THRESHOLD
            else (table[b] for b in data)
        )
        return b"".join(result_parts).decode("ascii")

    @staticmethod
    def _mcode_digits(encoded: str) -> str:
        if not encoded:
            return ""
        try:
            data = encoded.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("Invalid mcode payload")
        out = bytearray(len(data) // 2)
        out_idx = 0
        idx = 0
        total = len(data)
        while idx < total:
            ch = data[idx]
            if ch < 48 or ch > 57:
                raise ValueError("Invalid mcode payload")
            span = ch - 48
            idx += 1
            if span <= 0 or idx + span > total:
                raise ValueError("Invalid mcode payload length")
            if span == 1:
                d0 = data[idx] - 48
                if d0 > 9:
                    raise ValueError("Invalid mcode payload")
                val = d0
                idx += 1
            elif span == 2:
                d0 = data[idx] - 48
                d1 = data[idx + 1] - 48
                if d0 > 9 or d1 > 9:
                    raise ValueError("Invalid mcode payload")
                val = (d0 * 10) + d1
                idx += 2
            elif span == 3:
                d0 = data[idx] - 48
                d1 = data[idx + 1] - 48
                d2 = data[idx + 2] - 48
                if d0 > 9 or d1 > 9 or d2 > 9:
                    raise ValueError("Invalid mcode payload")
                val = (d0 * 100) + (d1 * 10) + d2
                idx += 3
            else:
                val = 0
                for i in range(span):
                    d = data[idx + i] - 48
                    if d > 9:
                        raise ValueError("Invalid mcode payload")
                    val = val * 10 + d
                idx += span
            if out_idx >= len(out):
                out.extend(bytes(len(out) // 2 + 64))
            out[out_idx] = val
            out_idx += 1
        return out[:out_idx].decode("latin-1")

    @staticmethod
    def _aead_encrypt(key: bytes, plaintext: bytes, aad: "basefwx.typing.Optional[bytes]") -> bytes:
        nonce = basefwx.os.urandom(12)
        ct = basefwx.AESGCM(key).encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    @staticmethod
    def _aead_decrypt(key: bytes, blob: bytes, aad: "basefwx.typing.Optional[bytes]") -> bytes:
        if len(blob) < 13:
            raise ValueError("Malformed AEAD blob: too short")
        nonce, ct = blob[:12], blob[12:]
        return basefwx.AESGCM(key).decrypt(nonce, ct, aad or None)

    @staticmethod
    def _pack_length_prefixed(*parts: bytes) -> bytes:
        total = 4 * len(parts) + sum(len(p) for p in parts)
        out = bytearray(total)
        mv = memoryview(out)
        offset = 0
        for part in parts:
            mv[offset:offset + 4] = len(part).to_bytes(4, 'big')
            offset += 4
            mv[offset:offset + len(part)] = part
            offset += len(part)
        return bytes(out)

    @staticmethod
    def _unpack_length_prefixed(data: bytes, count: int) -> "basefwx.typing.Tuple[bytes, ...]":
        mv = memoryview(data)
        total_len = len(mv)
        offset = 0
        parts: "basefwx.typing.List[bytes]" = []
        for _ in range(count):
            if offset + 4 > total_len:
                raise ValueError("Malformed length-prefixed blob (missing length)")
            length = basefwx.struct.unpack_from('>I', mv, offset)[0]
            offset += 4
            if offset + length > total_len:
                raise ValueError("Malformed length-prefixed blob (truncated part)")
            parts.append(bytes(mv[offset:offset + length]))
            offset += length
        if offset != total_len:
            raise ValueError("Malformed length-prefixed blob (extra bytes)")
        return tuple(parts)

    @staticmethod
    def _mask_payload(mask_key: bytes, payload: bytes, *, info: bytes) -> bytes:
        if not payload:
            return b""
        if len(payload) > basefwx.HKDF_MAX_LEN:
            stream = basefwx._hkdf_stream_sha256(mask_key, info, len(payload))
        else:
            stream = basefwx._hkdf_sha256(mask_key, length=len(payload), info=info)
        data_arr = basefwx.np.frombuffer(payload, dtype=basefwx.np.uint8)
        mask_arr = basefwx.np.frombuffer(stream, dtype=basefwx.np.uint8)
        total_len = data_arr.size
        if total_len <= basefwx._PARALLEL_CHUNK_SIZE or basefwx._CPU_COUNT == 1:
            out_arr = basefwx.np.bitwise_xor(data_arr, mask_arr)
            return out_arr.tobytes()

        out_arr = basefwx.np.empty_like(data_arr)
        chunk = basefwx._PARALLEL_CHUNK_SIZE
        ranges = [
            (start, min(start + chunk, total_len))
            for start in range(0, total_len, chunk)
        ]

        def _xor_slice(bounds: "tuple[int, int]") -> None:
            start, end = bounds
            basefwx.np.bitwise_xor(
                data_arr[start:end],
                mask_arr[start:end],
                out=out_arr[start:end]
            )

        max_workers = min(len(ranges), basefwx._CPU_COUNT)
        with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(_xor_slice, ranges))
        return out_arr.tobytes()

    @staticmethod
    def _estimate_aead_blob_size(
        plaintext_bytes: int,
        metadata_bytes: int,
        *,
        include_user: bool,
        include_master: bool
    ) -> int:
        cipher_section = basefwx.AEAD_NONCE_LEN + plaintext_bytes + basefwx.AEAD_TAG_LEN
        payload_section = 4 + metadata_bytes + cipher_section
        user_section = basefwx.USER_WRAP_FIXED_LEN if include_user else 0
        master_section = basefwx.PQ_CIPHERTEXT_SIZE if include_master else 0
        total = (
            4 + user_section +
            4 + master_section +
            4 + payload_section
        )
        return total

    @staticmethod
    def _prepare_mask_key(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool,
        *,
        mask_info: bytes,
        require_password: bool,
        aad: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[bytes, bytes, bytes, bool]":
        if require_password and not password:
            raise ValueError("Password required for this mode")
        pubkey = basefwx._load_master_pq_public() if use_master else None
        ec_pub = None
        if use_master and pubkey is None:
            try:
                ec_pub = basefwx._load_master_ec_public(create_if_missing=True)
            except Exception:
                ec_pub = None
        use_master_effective = use_master and (pubkey is not None or ec_pub is not None)
        if not password and not use_master_effective:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        if use_master_effective:
            if pubkey is not None:
                kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(pubkey)
                master_blob = kem_ct
                mask_key = basefwx._hkdf_sha256(kem_shared, info=mask_info)
            else:
                ec_blob, ec_shared = basefwx._ec_kem_enc(ec_pub)
                master_blob = ec_blob
                mask_key = basefwx._hkdf_sha256(ec_shared, info=mask_info)
        else:
            master_blob = b""
            mask_key = basefwx.os.urandom(32)
        user_blob = b""
        if password:
            kdf_label = (basefwx.USER_KDF or "argon2id").lower()
            user_derived_key, salt = basefwx._derive_user_key(
                password,
                salt=None,
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_label
            )
            wrapped = basefwx._aead_encrypt(user_derived_key, mask_key, aad)
            kdf_bytes = kdf_label.encode('utf-8')
            if len(kdf_bytes) > 255:
                raise ValueError("KDF label too long")
            user_blob = bytes([len(kdf_bytes)]) + kdf_bytes + salt + wrapped
        return mask_key, user_blob, master_blob, use_master_effective

    @staticmethod
    def _recover_mask_key_from_blob(
        user_blob: bytes,
        master_blob: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool,
        *,
        mask_info: bytes,
        aad: "basefwx.typing.Optional[bytes]" = None
    ) -> bytes:
        master_present = len(master_blob) > 0
        user_present = len(user_blob) > 0
        if master_present:
            if not use_master:
                raise ValueError("Master key required to decode this payload")
            if master_blob.startswith(basefwx.MASTER_EC_MAGIC):
                shared = basefwx._ec_kem_dec(master_blob)
                return basefwx._hkdf_sha256(shared, info=mask_info)
            private_key = basefwx._load_master_pq_private()
            shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
            return basefwx._hkdf_sha256(shared, info=mask_info)
        if not user_present:
            raise ValueError("Ciphertext missing key transport data")
        if not password:
            raise ValueError("Password required to decode this payload")
        if len(user_blob) < 1:
            raise ValueError("Corrupted user key blob: missing KDF metadata")
        kdf_len = user_blob[0]
        header_len = 1 + kdf_len + basefwx.USER_KDF_SALT_SIZE
        if len(user_blob) < header_len:
            raise ValueError("Corrupted user key blob: truncated data")
        kdf_label = user_blob[1:1 + kdf_len].decode('utf-8') if kdf_len else (basefwx.USER_KDF or "argon2id")
        salt = user_blob[1 + kdf_len:header_len]
        wrapped = user_blob[header_len:]
        user_derived_key, _ = basefwx._derive_user_key(
            password,
            salt=salt,
            iterations=basefwx.USER_KDF_ITERATIONS,
            kdf=kdf_label
        )
        return basefwx._aead_decrypt(user_derived_key, wrapped, aad)

    @staticmethod
    def _jmg_security_profile_id(
        security_profile: "basefwx.typing.Union[str, int, None]"
    ) -> int:
        if security_profile is None:
            return basefwx.JMG_SECURITY_PROFILE_DEFAULT
        if isinstance(security_profile, str):
            profile = basefwx.JMG_SECURITY_PROFILE_NAMES.get(
                security_profile.strip().lower(),
                None
            )
            if profile is None:
                raise ValueError(f"Unsupported JMG security profile: {security_profile}")
            return profile
        profile = int(security_profile)
        if profile not in basefwx.JMG_SECURITY_PROFILE_LABELS:
            raise ValueError(f"Unsupported JMG security profile id: {profile}")
        return profile

    @staticmethod
    def _jmg_stream_info_for_profile(profile_id: int) -> bytes:
        if profile_id == basefwx.JMG_SECURITY_PROFILE_MAX:
            return basefwx.IMAGECIPHER_STREAM_INFO + b".max"
        return basefwx.IMAGECIPHER_STREAM_INFO

    @staticmethod
    def _jmg_archive_info_for_profile(profile_id: int) -> bytes:
        if profile_id == basefwx.JMG_SECURITY_PROFILE_MAX:
            return basefwx.IMAGECIPHER_ARCHIVE_INFO + b".max"
        return basefwx.IMAGECIPHER_ARCHIVE_INFO

    @staticmethod
    def _jmg_build_key_header(
        user_blob: bytes,
        master_blob: bytes,
        *,
        security_profile: "basefwx.typing.Union[str, int, None]" = None
    ) -> bytes:
        profile_id = basefwx._jmg_security_profile_id(security_profile)
        payload = bytes([profile_id]) + basefwx._pack_length_prefixed(user_blob, master_blob)
        return (
            basefwx.JMG_KEY_MAGIC
            + bytes([basefwx.JMG_KEY_VERSION])
            + len(payload).to_bytes(4, "big")
            + payload
        )

    @staticmethod
    def _jmg_profile_from_key_header(blob: bytes) -> int:
        header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
        if len(blob) < header_min or not blob.startswith(basefwx.JMG_KEY_MAGIC):
            raise ValueError("Invalid JMG key header")
        version = blob[len(basefwx.JMG_KEY_MAGIC)]
        payload_len = int.from_bytes(
            blob[len(basefwx.JMG_KEY_MAGIC) + 1:len(basefwx.JMG_KEY_MAGIC) + 5],
            "big"
        )
        header_len = header_min + payload_len
        if len(blob) != header_len:
            raise ValueError("Truncated JMG key header")
        if version == basefwx.JMG_KEY_VERSION_LEGACY:
            return basefwx.JMG_SECURITY_PROFILE_LEGACY
        if version != basefwx.JMG_KEY_VERSION:
            raise ValueError("Unsupported JMG key header version")
        payload = blob[header_min:header_len]
        if not payload:
            raise ValueError("Truncated JMG key header profile")
        return basefwx._jmg_security_profile_id(payload[0])

    @staticmethod
    def _jmg_parse_key_header(
        blob: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool
    ) -> "basefwx.typing.Optional[tuple[int, bytes, bytes, bytes, int]]":
        header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
        if len(blob) < header_min or not blob.startswith(basefwx.JMG_KEY_MAGIC):
            return None
        version = blob[len(basefwx.JMG_KEY_MAGIC)]
        if version not in {basefwx.JMG_KEY_VERSION_LEGACY, basefwx.JMG_KEY_VERSION}:
            raise ValueError("Unsupported JMG key header version")
        payload_len = int.from_bytes(blob[len(basefwx.JMG_KEY_MAGIC) + 1:len(basefwx.JMG_KEY_MAGIC) + 5], "big")
        header_len = header_min + payload_len
        if len(blob) < header_len:
            raise ValueError("Truncated JMG key header")
        payload = blob[header_min:header_len]
        if version == basefwx.JMG_KEY_VERSION_LEGACY:
            profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
            key_payload = payload
        else:
            if not payload:
                raise ValueError("Truncated JMG key header profile")
            profile_id = basefwx._jmg_security_profile_id(payload[0])
            key_payload = payload[1:]
        user_blob, master_blob = basefwx._unpack_length_prefixed(key_payload, 2)
        mask_key = basefwx._recover_mask_key_from_blob(
            user_blob,
            master_blob,
            password,
            use_master,
            mask_info=basefwx.JMG_MASK_INFO,
            aad=basefwx.JMG_MASK_AAD
        )
        material = basefwx._hkdf_sha256(
            mask_key,
            info=basefwx._jmg_stream_info_for_profile(profile_id),
            length=64
        )
        base_key = material[:32]
        archive_key = basefwx._hkdf_sha256(
            mask_key,
            info=basefwx._jmg_archive_info_for_profile(profile_id),
            length=32
        )
        return header_len, base_key, archive_key, material, profile_id

    @staticmethod
    def _jmg_prepare_keys(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool = True,
        *,
        security_profile: "basefwx.typing.Union[str, int, None]" = None
    ) -> "tuple[bytes, bytes, bytes, bytes]":
        profile_id = basefwx._jmg_security_profile_id(security_profile)
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            password,
            use_master,
            mask_info=basefwx.JMG_MASK_INFO,
            require_password=False,
            aad=basefwx.JMG_MASK_AAD
        )
        header = basefwx._jmg_build_key_header(
            user_blob,
            master_blob,
            security_profile=profile_id,
        )
        material = basefwx._hkdf_sha256(
            mask_key,
            info=basefwx._jmg_stream_info_for_profile(profile_id),
            length=64
        )
        base_key = material[:32]
        archive_key = basefwx._hkdf_sha256(
            mask_key,
            info=basefwx._jmg_archive_info_for_profile(profile_id),
            length=32
        )
        return base_key, archive_key, material, header

    @staticmethod
    def _append_balanced_trailer(
        output_path: "basefwx.pathlib.Path",
        magic: bytes,
        payload: bytes
    ) -> None:
        if not payload:
            return
        if len(payload) > 0xFFFFFFFF:
            raise ValueError("Trailer payload too large")
        with open(output_path, "ab") as handle:
            handle.write(magic)
            handle.write(len(payload).to_bytes(4, "big"))
            handle.write(payload)
            handle.write(magic)
            handle.write(len(payload).to_bytes(4, "big"))

    @staticmethod
    def _extract_balanced_trailer_from_bytes(
        file_bytes: bytes,
        magic: bytes
    ) -> "basefwx.typing.Optional[tuple[bytes, bytes]]":
        footer_len = len(magic) + 4
        if len(file_bytes) < footer_len:
            return None
        footer_idx = len(file_bytes) - footer_len
        if file_bytes[footer_idx:footer_idx + len(magic)] == magic:
            length = int.from_bytes(file_bytes[footer_idx + len(magic):footer_idx + footer_len], "big")
            trailer_start = len(file_bytes) - footer_len - length - footer_len
            if trailer_start >= 0:
                header = file_bytes[trailer_start:trailer_start + footer_len]
                if header[:len(magic)] == magic and int.from_bytes(header[len(magic):], "big") == length:
                    blob_start = trailer_start + footer_len
                    blob_end = blob_start + length
                    return file_bytes[blob_start:blob_end], file_bytes[:trailer_start]
        marker_idx = file_bytes.rfind(magic)
        if marker_idx < 0 or marker_idx + len(magic) + 4 > len(file_bytes):
            return None
        length = int.from_bytes(file_bytes[marker_idx + len(magic):marker_idx + len(magic) + 4], "big")
        blob_start = marker_idx + len(magic) + 4
        blob_end = blob_start + length
        if blob_end != len(file_bytes):
            return None
        return file_bytes[blob_start:blob_end], file_bytes[:marker_idx]

    @staticmethod
    def _extract_balanced_trailer_info(
        path: "basefwx.pathlib.Path",
        magic: bytes
    ) -> "basefwx.typing.Optional[tuple[int, int, int]]":
        footer_len = len(magic) + 4
        try:
            size = path.stat().st_size
        except Exception:
            return None
        if size < footer_len:
            return None
        with open(path, "rb") as handle:
            handle.seek(size - footer_len)
            footer = handle.read(footer_len)
            if len(footer) != footer_len or footer[:len(magic)] != magic:
                return None
            blob_len = int.from_bytes(footer[len(magic):], "big")
            trailer_start = size - footer_len - blob_len - footer_len
            if trailer_start < 0:
                return None
            handle.seek(trailer_start)
            header = handle.read(footer_len)
            if len(header) != footer_len or header[:len(magic)] != magic:
                return None
            if int.from_bytes(header[len(magic):], "big") != blob_len:
                return None
            blob_start = trailer_start + footer_len
            return blob_start, blob_len, trailer_start

    @staticmethod
    def _kem_shared_to_digits(shared: bytes, digits: int = 16) -> str:
        output = []
        seed = shared
        while len(output) < digits:
            digest = basefwx.hashlib.sha3_512(seed).digest()
            for byte in digest:
                output.append(str(byte % 10))
                if len(output) == digits:
                    break
            seed = digest
        return ''.join(output)

    @staticmethod
    def _derive_key_material(
        secret: "basefwx.typing.Union[str, bytes, bytearray]",
        context: "basefwx.typing.Union[str, bytes, bytearray]",
        *,
        length: int = 32,
        iterations: int = 200_000
    ) -> bytes:
        """
        Derive deterministic key material from a password-like secret using PBKDF2.
        The context parameter namespaces derivations for separate use-cases.
        """
        if isinstance(secret, str):
            secret_bytes = secret.encode('utf-8')
        else:
            secret_bytes = bytes(secret)
        if isinstance(context, str):
            context_bytes = context.encode('utf-8')
        else:
            context_bytes = bytes(context)
        iterations, _, _, _ = basefwx._harden_kdf_params(
            secret_bytes,
            iterations=iterations,
            argon2_time_cost=basefwx.SHORT_ARGON2_TIME_COST,
            argon2_memory_cost=basefwx.SHORT_ARGON2_MEMORY_COST,
            argon2_parallelism=basefwx.SHORT_ARGON2_PARALLELISM
        )
        return basefwx.hashlib.pbkdf2_hmac(
            'sha256',
            secret_bytes,
            context_bytes,
            iterations,
            dklen=length
        )

    @staticmethod
    def _pq_wrap_secret(secret: bytes) -> "basefwx.typing.Tuple[bytes, bytes, bytes]":
        public_key = basefwx._load_master_pq_public()
        if public_key is None:
            raise ValueError("Master public key unavailable for PQ wrap")
        kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(public_key)
        aes_key = basefwx._kem_derive_key(kem_shared)
        aesgcm = basefwx.AESGCM(aes_key)
        nonce = basefwx.os.urandom(12)
        wrapped = nonce + aesgcm.encrypt(nonce, secret, None)
        return kem_ct, wrapped, kem_shared

    @staticmethod
    def _pq_unwrap_secret(ciphertext: bytes, wrapped: bytes) -> bytes:
        secret, _ = basefwx._pq_unwrap_secret_with_shared(ciphertext, wrapped)
        return secret

    @staticmethod
    def _pq_unwrap_secret_with_shared(ciphertext: bytes, wrapped: bytes) -> "basefwx.typing.Tuple[bytes, bytes]":
        private_key = basefwx._load_master_pq_private()
        kem_shared = basefwx.ml_kem_768.decrypt(private_key, ciphertext)
        aes_key = basefwx._kem_derive_key(kem_shared)
        aesgcm = basefwx.AESGCM(aes_key)
        nonce, ct = wrapped[:12], wrapped[12:]
        secret = aesgcm.decrypt(nonce, ct, None)
        return secret, kem_shared

    @staticmethod
    def _normalize_path(path_like: "basefwx.typing.Union[str, basefwx.pathlib.Path]") -> "basefwx.pathlib.Path":
        if isinstance(path_like, basefwx.pathlib.Path):
            path = path_like
        else:
            path = basefwx.pathlib.Path(str(path_like))
        path = path.expanduser()
        try:
            return path.resolve(strict=False)
        except Exception:
            return path

    @staticmethod
    def _ensure_existing_file(path: "basefwx.pathlib.Path") -> None:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Input file not found: {path}")

    @staticmethod
    def _ensure_size_limit(path: "basefwx.pathlib.Path", max_bytes: int = None) -> None:
        limit = max_bytes or basefwx.MAX_INPUT_BYTES
        size = path.stat().st_size
        if size > limit:
            human_size = basefwx._human_readable_size(size)
            human_limit = basefwx._human_readable_size(limit)
            raise ValueError(
                f"{path.name} is {human_size}, exceeding the {human_limit} limit for this mode"
            )

    @staticmethod
    def _resolve_password(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool = True
    ) -> "basefwx.typing.Union[str, bytes]":
        if password is None:
            if not use_master:
                raise ValueError("Password required when master key usage is disabled")
            return ""
        if isinstance(password, (bytes, bytearray, memoryview)):
            return bytes(password)
        if isinstance(password, basefwx.pathlib.Path):
            candidate = password.expanduser()
            if candidate.is_file():
                return candidate.read_bytes()
            return str(candidate)
        if password == "":
            if not use_master:
                raise ValueError("Password required when master key usage is disabled")
            return ""

        if isinstance(password, str) and password.startswith("yubikey:"):
            label = password.split(":", 1)[1] or "default"
            try:
                from .yubikey_pq import YubiKeyPQKeyStore, YubiKeyUnavailableError
            except ImportError as exc:
                raise ValueError(
                    "YubiKey support is optional. Install python-fido2 inside your "
                    "environment to use 'yubikey:<label>' password specifications."
                ) from exc
            try:
                vault = YubiKeyPQKeyStore()
                return vault.derive_passphrase(label.strip() or "default")
            except YubiKeyUnavailableError as exc:
                raise ValueError(str(exc)) from exc

        candidate = basefwx.pathlib.Path(password).expanduser()
        if candidate.is_file():
            return candidate.read_bytes()
        return password

    @staticmethod
    def _coerce_file_list(files) -> "basefwx.typing.List[basefwx.pathlib.Path]":
        if isinstance(files, (str, basefwx.pathlib.Path)):
            candidates = [files]
        else:
            candidates = list(files)
        if not candidates:
            raise ValueError("No files provided")
        normalized = []
        for item in candidates:
            normalized.append(basefwx._normalize_path(item))
        return normalized

    def __init__(self):
        self.sys.set_int_max_str_digits(2000000000)
        pass

    @staticmethod
    def generate_random_string(length):
        """Generates a random string of the specified length."""

        alphabet = basefwx.string.ascii_letters + basefwx.string.digits
        return ''.join(basefwx.secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def derive_key_from_text(text, salt, key_length_bytes=32):

        """Derives an AES key from text using PBKDF2."""

        salt_bytes = salt.encode() if isinstance(salt, str) else bytes(salt)
        key, _ = basefwx._derive_user_key_pbkdf2(
            text,
            salt_bytes,
            iterations=100_000,
            length=key_length_bytes
        )
        return key

    @staticmethod
    def _derive_user_key_argon2id(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        salt: "basefwx.typing.Optional[bytes]" = None,
        *,
        length: int = 32,
        time_cost: int = 3,
        memory_cost: int = 2 ** 15,
        parallelism: int | None = None
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if salt is None:
            salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        if basefwx.hash_secret_raw is None:
            raise RuntimeError("Argon2 backend unavailable")
        parallelism = parallelism or basefwx._CPU_COUNT
        password_bytes = basefwx._coerce_password_bytes(password)
        
        # Calculate memory requirement (in bytes)
        required_memory_mb = (memory_cost * 1024) // 1024  # Convert KiB to MiB
        
        try:
            key = basefwx.hash_secret_raw(
                password_bytes,
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=length,
                type=basefwx.Argon2Type.ID
            )
        except MemoryError:
            raise RuntimeError(
                f"Insufficient memory for Argon2id key derivation. "
                f"Required: ~{required_memory_mb} MiB, "
                f"Consider using PBKDF2 instead (set BASEFWX_USER_KDF=pbkdf2)"
            )
        except Exception as e:
            # Catch other Argon2 errors and provide helpful message
            if "memory" in str(e).lower():
                raise RuntimeError(
                    f"Memory allocation failed for Argon2id (requires ~{required_memory_mb} MiB). "
                    f"Use BASEFWX_USER_KDF=pbkdf2 as a fallback."
                ) from e
            raise
        
        return key, salt

    @staticmethod
    def _derive_user_key_pbkdf2(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        salt: bytes,
        *,
        iterations: int | None = None,
        length: int = 32
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        iterations = iterations or basefwx.USER_KDF_ITERATIONS
        password_bytes = basefwx._coerce_password_bytes(password)
        return basefwx.hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt,
            iterations,
            dklen=length
        ), salt

    @staticmethod
    def _derive_user_key(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        salt: bytes | None = None,
        *,
        iterations: int | None = None,
        kdf: "basefwx.typing.Optional[str]" = None,
        argon2_time_cost: "basefwx.typing.Optional[int]" = None,
        argon2_memory_cost: "basefwx.typing.Optional[int]" = None,
        argon2_parallelism: "basefwx.typing.Optional[int]" = None
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if salt is None:
            salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
        iterations = iterations or basefwx.USER_KDF_ITERATIONS
        argon2_time_cost = argon2_time_cost or 3
        argon2_memory_cost = argon2_memory_cost or (2 ** 15)
        argon2_parallelism = argon2_parallelism or basefwx._CPU_COUNT
        iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism = basefwx._harden_kdf_params(
            password,
            iterations=iterations,
            argon2_time_cost=argon2_time_cost,
            argon2_memory_cost=argon2_memory_cost,
            argon2_parallelism=argon2_parallelism
        )
        requested_kdf = (kdf or basefwx.USER_KDF or basefwx.USER_KDF_DEFAULT).lower()
        if requested_kdf in {"argon2", "argon2id"}:
            if basefwx.hash_secret_raw is None:
                if kdf is not None:
                    raise RuntimeError("Argon2 KDF requested but argon2 backend is unavailable")
                if not basefwx._WARNED_ARGON2_MISSING:
                    print("⚠️  Warning: argon2 backend unavailable, falling back to PBKDF2.")
                    basefwx._WARNED_ARGON2_MISSING = True
                requested_kdf = "pbkdf2"
            else:
                try:
                    return basefwx._derive_user_key_argon2id(
                        password,
                        salt,
                        time_cost=argon2_time_cost,
                        memory_cost=argon2_memory_cost,
                        parallelism=argon2_parallelism
                    )
                except MemoryError as e:
                    # Argon2 failed with OOM - print warning and fall back to PBKDF2
                    print(f"⚠️  USING PBKDF2, ARGON2 FAILED! CAUSE: {e}")
                    print(f"⚠️  Insufficient memory for Argon2. Falling back to PBKDF2.")
                    requested_kdf = "pbkdf2"
                except RuntimeError as e:
                    if "memory" in str(e).lower() or "insufficient" in str(e).lower():
                        # Memory-related error - print warning and fall back
                        print(f"⚠️  USING PBKDF2, ARGON2 FAILED! CAUSE: {e}")
                        requested_kdf = "pbkdf2"
                    else:
                        # Other runtime error - re-raise
                        raise
        return basefwx._derive_user_key_pbkdf2(password, salt, iterations=iterations)

    @staticmethod
    def encryptAES(
        plaintext: str,
        user_key: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        use_master: bool = True,
        *,
        metadata_blob: "basefwx.typing.Optional[str]" = None,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        kdf: "basefwx.typing.Optional[str]" = None,
        progress_callback: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None,
        obfuscate: bool = True,
        fast_obfuscation: bool = False,
        kdf_iterations: "basefwx.typing.Optional[int]" = None,
        argon2_time_cost: "basefwx.typing.Optional[int]" = None,
        argon2_memory_cost: "basefwx.typing.Optional[int]" = None,
        argon2_parallelism: "basefwx.typing.Optional[int]" = None
    ) -> bytes:
        user_key = basefwx._resolve_password(user_key, use_master=use_master)
        if not user_key and not use_master:
            raise ValueError("Cannot encrypt without user password or master key")
        basefwx.sys.set_int_max_str_digits(2000000000)
        metadata_blob = metadata_blob if metadata_blob is not None else basefwx._split_metadata(plaintext)[0]
        metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
        aad = metadata_bytes if metadata_bytes else b''
        pq_public = master_public_key if master_public_key is not None else (basefwx._load_master_pq_public() if use_master else None)
        ec_public = None
        if use_master and pq_public is None:
            try:
                ec_public = basefwx._load_master_ec_public(create_if_missing=True)
            except Exception:
                ec_public = None
        use_master_effective = use_master and (pq_public is not None or ec_public is not None)
        if use_master_effective:
            if pq_public is not None:
                kem_ciphertext, kem_shared = basefwx.ml_kem_768.encrypt(pq_public)
                master_payload = kem_ciphertext
                ephemeral_key = basefwx._kem_derive_key(kem_shared)
            else:
                ec_blob, ec_shared = basefwx._ec_kem_enc(ec_public)
                master_payload = ec_blob
                ephemeral_key = basefwx._kem_derive_key(ec_shared)
        else:
            master_payload = b""
            ephemeral_key = basefwx.os.urandom(32)
        if user_key:
            kdf_used = (kdf or basefwx.USER_KDF or "argon2id").lower()
            user_derived_key, user_salt = basefwx._derive_user_key(
                user_key,
                salt=None,
                iterations=kdf_iterations or basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_used,
                argon2_time_cost=argon2_time_cost,
                argon2_memory_cost=argon2_memory_cost,
                argon2_parallelism=argon2_parallelism
            )
            wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
            ephemeral_enc_user = user_salt + wrapped_ephemeral
        else:
            ephemeral_enc_user = b""
        payload_bytes = plaintext.encode('utf-8')
        if obfuscate and basefwx.ENABLE_OBFUSCATION:
            payload_bytes = basefwx._obfuscate_bytes(payload_bytes, ephemeral_key, fast=fast_obfuscation)

        nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
        encryptor = basefwx.Cipher(
            basefwx.algorithms.AES(ephemeral_key),
            basefwx.modes.GCM(nonce)
        ).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        chunk_size = 1 << 20
        total = len(payload_bytes)
        processed = 0
        cipher_chunks: "basefwx.typing.List[bytes]" = []
        for offset in range(0, total, chunk_size):
            chunk = payload_bytes[offset:offset + chunk_size]
            cipher_chunks.append(encryptor.update(chunk))
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total)
        cipher_chunks.append(encryptor.finalize())
        tag = encryptor.tag
        ciphertext = nonce + b"".join(cipher_chunks) + tag
        payload = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + ciphertext

        def int_to_4(i):
            return i.to_bytes(4, byteorder='big', signed=False)

        blob = b''
        blob += int_to_4(len(ephemeral_enc_user)) + ephemeral_enc_user
        blob += int_to_4(len(master_payload)) + master_payload
        blob += int_to_4(len(payload)) + payload
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        basefwx._del('payload_bytes')
        return blob

    @staticmethod
    def decryptAES(
        encrypted_blob: bytes,
        key: "basefwx.typing.Union[str, bytes, bytearray, memoryview]" = "",
        use_master: bool = True,
        *,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        allow_legacy: "basefwx.typing.Optional[bool]" = None,
        progress_callback: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
    ) -> str:
        key = basefwx._resolve_password(key, use_master=use_master)
        basefwx.sys.set_int_max_str_digits(2000000000)

        def read_chunk(in_bytes, offset):
            length = int.from_bytes(in_bytes[offset:offset + 4], 'big')
            offset += 4
            chunk = in_bytes[offset:offset + length]
            offset += length
            return chunk, offset

        def legacy_decrypt(user_blob: bytes, master_blob: bytes, payload_blob: bytes) -> str:
            master_present = len(master_blob) > 0
            user_present = len(user_blob) > 0
            if master_present:
                if not use_master:
                    raise ValueError("Master key required to decrypt this payload (legacy)")
                if master_blob.startswith(basefwx.MASTER_EC_MAGIC):
                    kem_shared = basefwx._ec_kem_dec(master_blob)
                else:
                    private_key = basefwx._load_master_pq_private()
                    kem_shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
                ephemeral_key = basefwx._kem_derive_key(kem_shared)
            elif user_present:
                if not key:
                    raise ValueError("User password required to decrypt this payload (legacy)")
                min_len = basefwx.USER_KDF_SALT_SIZE + 16
                if len(user_blob) < min_len:
                    raise ValueError("Corrupted user key blob: missing salt or IV (legacy)")
                user_salt = user_blob[:basefwx.USER_KDF_SALT_SIZE]
                iv_user = user_blob[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
                enc_user_key = user_blob[basefwx.USER_KDF_SALT_SIZE + 16:]
                user_derived_key, _ = basefwx._derive_user_key(
                    key,
                    salt=user_salt,
                    iterations=basefwx.USER_KDF_ITERATIONS,
                    kdf="pbkdf2"
                )
                cipher_user = basefwx.Cipher(
                    basefwx.algorithms.AES(user_derived_key),
                    basefwx.modes.CBC(iv_user)
                )
                decryptor_user = cipher_user.decryptor()
                padded_b64 = decryptor_user.update(enc_user_key) + decryptor_user.finalize()
                unpadder = basefwx.padding.PKCS7(128).unpadder()
                ephemeral_key_b64 = unpadder.update(padded_b64) + unpadder.finalize()
                ephemeral_key = basefwx.base64.b64decode(ephemeral_key_b64)
            else:
                raise ValueError("Ciphertext missing key transport data (legacy)")
            if len(payload_blob) < 16:
                raise ValueError("Legacy ciphertext missing IV")
            iv_data = payload_blob[:16]
            real_ciphertext = payload_blob[16:]
            cipher_data = basefwx.Cipher(
                basefwx.algorithms.AES(ephemeral_key),
                basefwx.modes.CBC(iv_data)
            )
            decryptor_data = cipher_data.decryptor()
            padded_plaintext = decryptor_data.update(real_ciphertext) + decryptor_data.finalize()
            unpadder2 = basefwx.padding.PKCS7(128).unpadder()
            plaintext = unpadder2.update(padded_plaintext) + unpadder2.finalize()
            print("⚠️  Falling back to legacy CBC decryption (ALLOW_CBC_DECRYPT=1).")
            plaintext_str = plaintext.decode('utf-8')
            basefwx._del('ephemeral_key')
            basefwx._del('user_derived_key')
            basefwx._del('kem_shared')
            return plaintext_str

        legacy_allowed = allow_legacy if allow_legacy is not None else basefwx.os.getenv("ALLOW_CBC_DECRYPT") == "1"

        def _confirm_legacy_fallback(reason: str) -> None:
            prompt = (
                f"⚠️  {reason}.\n"
                "Falling back to legacy CBC decryption which is unauthenticated and weaker.\n"
                "Type YES to accept the security risk and continue: "
            )
            response = input(prompt)
            if response.strip() != "YES":
                raise ValueError("Legacy CBC fallback aborted by user")
        offset = 0
        ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
        ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
        payload_blob, offset = read_chunk(encrypted_blob, offset)
        master_blob_present = len(ephemeral_enc_master) > 0
        user_blob_present = len(ephemeral_enc_user) > 0

        if len(payload_blob) < 4:
            if legacy_allowed:
                _confirm_legacy_fallback("Ciphertext payload truncated; AEAD decode unavailable")
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Ciphertext payload truncated")

        metadata_len = int.from_bytes(payload_blob[:4], 'big')
        metadata_end = 4 + metadata_len
        if metadata_end > len(payload_blob):
            if legacy_allowed:
                _confirm_legacy_fallback("Malformed payload metadata; AEAD decode unavailable")
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Malformed payload metadata header")
        metadata_bytes = payload_blob[4:metadata_end]
        try:
            metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ""
        except UnicodeDecodeError:
            metadata_blob = ""
        aad = metadata_bytes if metadata_bytes else b''
        meta_info = basefwx._decode_metadata(metadata_blob) if metadata_blob else {}
        obf_hint = (meta_info.get("ENC-OBF") or "yes").lower()
        should_deobfuscate = basefwx.ENABLE_OBFUSCATION and obf_hint != "no"
        fast_obf = should_deobfuscate and obf_hint == "fast"

        def _parse_int(value: "basefwx.typing.Any", default: "basefwx.typing.Optional[int]") -> "basefwx.typing.Optional[int]":
            if value is None:
                return default
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        kdf_hint = (meta_info.get("ENC-KDF") or basefwx.USER_KDF or "argon2id").lower()
        kdf_iter_hint = _parse_int(meta_info.get("ENC-KDF-ITER"), basefwx.USER_KDF_ITERATIONS)
        argon2_time_hint = _parse_int(meta_info.get("ENC-ARGON2-TC"), None)
        argon2_mem_hint = _parse_int(meta_info.get("ENC-ARGON2-MEM"), None)
        argon2_par_hint = _parse_int(meta_info.get("ENC-ARGON2-PAR"), None)
        ciphertext = payload_blob[metadata_end:]

        if master_blob_present:
            if not use_master:
                raise ValueError("Master key required to decrypt this payload")
            if ephemeral_enc_master.startswith(basefwx.MASTER_EC_MAGIC):
                kem_shared = basefwx._ec_kem_dec(ephemeral_enc_master)
            else:
                private_key = basefwx._load_master_pq_private()
                kem_shared = basefwx.ml_kem_768.decrypt(private_key, ephemeral_enc_master)
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        elif user_blob_present:
            if not key:
                raise ValueError("User password required to decrypt this payload")
            min_len = basefwx.USER_KDF_SALT_SIZE + 13  # salt + nonce + tag
            if len(ephemeral_enc_user) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or AEAD data")
            user_salt = ephemeral_enc_user[:basefwx.USER_KDF_SALT_SIZE]
            wrapped_ephemeral = ephemeral_enc_user[basefwx.USER_KDF_SALT_SIZE:]
            user_derived_key, _ = basefwx._derive_user_key(
                key,
                salt=user_salt,
                iterations=kdf_iter_hint or basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_hint,
                argon2_time_cost=argon2_time_hint,
                argon2_memory_cost=argon2_mem_hint,
                argon2_parallelism=argon2_par_hint
            )
            try:
                ephemeral_key = basefwx._aead_decrypt(user_derived_key, wrapped_ephemeral, aad)
            except basefwx.InvalidTag as exc:
                if legacy_allowed:
                    _confirm_legacy_fallback("User-branch AEAD authentication failed; attempting legacy CBC decrypt")
                    return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
                raise ValueError("User branch authentication failed; incorrect password or tampering") from exc
        else:
            if legacy_allowed:
                _confirm_legacy_fallback("Ciphertext missing key transport data; AEAD decode unavailable")
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Ciphertext missing key transport data")

        try:
            if len(ciphertext) < basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN:
                raise ValueError("Ciphertext truncated")
            nonce = ciphertext[:basefwx.AEAD_NONCE_LEN]
            tag = ciphertext[-basefwx.AEAD_TAG_LEN:]
            cipher_body = ciphertext[basefwx.AEAD_NONCE_LEN:-basefwx.AEAD_TAG_LEN]
            decryptor_ctx = basefwx.Cipher(
                basefwx.algorithms.AES(ephemeral_key),
                basefwx.modes.GCM(nonce, tag)
            ).decryptor()
            if aad:
                decryptor_ctx.authenticate_additional_data(aad)
            chunk_size = 1 << 20
            total_ct = len(cipher_body)
            processed = 0
            plaintext_parts: "basefwx.typing.List[bytes]" = []
            for offset_chunk in range(0, total_ct, chunk_size):
                chunk = cipher_body[offset_chunk:offset_chunk + chunk_size]
                plaintext_parts.append(decryptor_ctx.update(chunk))
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, total_ct)
            plaintext_parts.append(decryptor_ctx.finalize())
            payload_bytes = b"".join(plaintext_parts)
        except basefwx.InvalidTag as exc:
            if legacy_allowed:
                print("⚠️  AEAD authentication failed; attempting legacy CBC decrypt.")
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("AEAD authentication failed; ciphertext or metadata tampered") from exc
        if should_deobfuscate:
            payload_bytes = basefwx._deobfuscate_bytes(payload_bytes, ephemeral_key, fast=fast_obf)
        plaintext = payload_bytes.decode('utf-8')
        header_blob, _ = basefwx._split_metadata(plaintext)
        if metadata_blob and header_blob and header_blob != metadata_blob:
            raise ValueError("Metadata integrity mismatch detected")
        basefwx._del('payload_bytes')
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        return plaintext

    @staticmethod
    def _coerce_password_bytes(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
    ) -> bytes:
        if isinstance(password, str):
            return password.encode("utf-8")
        if isinstance(password, (bytes, bytearray, memoryview)):
            return bytes(password)
        raise TypeError(f"Unsupported password type: {type(password)!r}")

    @staticmethod
    def _harden_kdf_params(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        iterations: int,
        argon2_time_cost: int,
        argon2_memory_cost: int,
        argon2_parallelism: int
    ) -> "tuple[int, int, int, int]":
        pw = basefwx._coerce_password_bytes(password)
        if not pw:
            return iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism
        if basefwx._TEST_KDF_ITERS is not None:
            return iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism
        if len(pw) < basefwx.SHORT_PASSWORD_MIN:
            iterations = max(iterations, basefwx.SHORT_PBKDF2_ITERATIONS)
            argon2_time_cost = max(argon2_time_cost, basefwx.SHORT_ARGON2_TIME_COST)
            argon2_memory_cost = max(argon2_memory_cost, basefwx.SHORT_ARGON2_MEMORY_COST)
            argon2_parallelism = max(argon2_parallelism, basefwx.SHORT_ARGON2_PARALLELISM)
        return iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism

    @staticmethod
    def _fwxaes_iterations(
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
    ) -> int:
        iters = basefwx.FWXAES_PBKDF2_ITERS
        if basefwx._TEST_KDF_ITERS is not None:
            return iters
        pw = basefwx._coerce_password_bytes(password)
        if pw and len(pw) < basefwx.SHORT_PASSWORD_MIN:
            iters = max(iters, basefwx.SHORT_PBKDF2_ITERATIONS)
        return iters

    @staticmethod
    def _kdf_pbkdf2_raw(password: bytes, salt: bytes, iters: int) -> bytes:
        return basefwx.hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            iters,
            dklen=basefwx.FWXAES_KEY_LEN
        )

    @staticmethod
    def fwxAES_encrypt_raw(
        plaintext: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True
    ) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("fwxAES_encrypt_raw expects bytes")
        password = basefwx._resolve_password(password, use_master=use_master)
        pw = basefwx._coerce_password_bytes(password)
        use_wrap = False
        key_header = b""
        mask_key = b""
        if use_master:
            try:
                mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(
                    password,
                    use_master,
                    mask_info=basefwx.FWXAES_MASK_INFO,
                    require_password=False,
                    aad=basefwx.FWXAES_AAD
                )
                use_wrap = use_master_effective or not pw
                if use_wrap:
                    key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
            except Exception:
                if not pw:
                    raise
                use_wrap = False
        iv = basefwx.os.urandom(basefwx.FWXAES_IV_LEN)
        if use_wrap:
            header_len = len(key_header)
            if header_len > 0xFFFFFFFF:
                raise ValueError("fwxAES key header too large")
            key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
        else:
            salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
            iters = basefwx._fwxaes_iterations(pw)
            key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        aesgcm = basefwx.AESGCM(key)
        ct = aesgcm.encrypt(iv, bytes(plaintext), basefwx.FWXAES_AAD)
        header = bytearray()
        header += basefwx.FWXAES_MAGIC
        if use_wrap:
            header += bytes([
                basefwx.FWXAES_ALGO,
                basefwx.FWXAES_KDF_WRAP,
                0,
                basefwx.FWXAES_IV_LEN
            ])
            header += basefwx.struct.pack(">I", header_len)
            header += basefwx.struct.pack(">I", len(ct))
            return bytes(header) + key_header + iv + ct
        header += bytes([
            basefwx.FWXAES_ALGO,
            basefwx.FWXAES_KDF_PBKDF2,
            basefwx.FWXAES_SALT_LEN,
            basefwx.FWXAES_IV_LEN
        ])
        header += basefwx.struct.pack(">I", iters)
        header += basefwx.struct.pack(">I", len(ct))
        return bytes(header) + salt + iv + ct

    @staticmethod
    def fwxAES_decrypt_raw(
        blob: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True
    ) -> bytes:
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("fwxAES_decrypt_raw expects bytes")
        password = basefwx._resolve_password(password, use_master=use_master)
        blob_bytes = bytes(blob)
        header_len = 4 + 1 + 1 + 1 + 1 + 4 + 4
        if len(blob_bytes) < header_len:
            raise ValueError("fwxAES blob too short")
        if blob_bytes[:4] != basefwx.FWXAES_MAGIC:
            raise ValueError("fwxAES bad magic")
        algo, kdf, salt_len, iv_len = blob_bytes[4], blob_bytes[5], blob_bytes[6], blob_bytes[7]
        if algo != basefwx.FWXAES_ALGO or kdf not in (basefwx.FWXAES_KDF_PBKDF2, basefwx.FWXAES_KDF_WRAP):
            raise ValueError("fwxAES unsupported algo/kdf")
        iters = basefwx.struct.unpack(">I", blob_bytes[8:12])[0]
        ct_len = basefwx.struct.unpack(">I", blob_bytes[12:16])[0]
        off = 16
        if kdf == basefwx.FWXAES_KDF_WRAP:
            header_len = iters
            if len(blob_bytes) < off + header_len + iv_len + ct_len:
                raise ValueError("fwxAES blob truncated")
            header = blob_bytes[off:off + header_len]
            off += header_len
            iv = blob_bytes[off:off + iv_len]
            off += iv_len
            ct = blob_bytes[off:off + ct_len]
            user_blob, master_blob = basefwx._unpack_length_prefixed(header, 2)
            mask_key = basefwx._recover_mask_key_from_blob(
                user_blob,
                master_blob,
                password,
                use_master,
                mask_info=basefwx.FWXAES_MASK_INFO,
                aad=basefwx.FWXAES_AAD
            )
            key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
            aesgcm = basefwx.AESGCM(key)
            return aesgcm.decrypt(iv, ct, basefwx.FWXAES_AAD)
        if len(blob_bytes) < off + salt_len + iv_len + ct_len:
            raise ValueError("fwxAES blob truncated")
        salt = blob_bytes[off:off + salt_len]
        off += salt_len
        iv = blob_bytes[off:off + iv_len]
        off += iv_len
        ct = blob_bytes[off:off + ct_len]
        pw = basefwx._coerce_password_bytes(password)
        if not pw:
            raise ValueError("fwxAES password required for PBKDF2 payload")
        key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        aesgcm = basefwx.AESGCM(key)
        return aesgcm.decrypt(iv, ct, basefwx.FWXAES_AAD)

    @staticmethod
    def _is_seekable(handle) -> bool:
        try:
            return bool(handle.seekable())
        except Exception:
            return False

    @staticmethod
    def fwxAES_encrypt_stream(
        source,
        dest,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        password = basefwx._resolve_password(password, use_master=use_master)
        pw = basefwx._coerce_password_bytes(password)
        chunk = basefwx.STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))

        def _encrypt_to(handle) -> int:
            use_wrap = False
            key_header = b""
            mask_key = b""
            if use_master:
                try:
                    mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(
                        password,
                        use_master,
                        mask_info=basefwx.FWXAES_MASK_INFO,
                        require_password=False,
                        aad=basefwx.FWXAES_AAD
                    )
                    use_wrap = use_master_effective or not pw
                    if use_wrap:
                        key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
                except Exception:
                    if not pw:
                        raise
                    use_wrap = False
            iv = basefwx.os.urandom(basefwx.FWXAES_IV_LEN)
            header = bytearray()
            header += basefwx.FWXAES_MAGIC
            ct_len = 0
            if use_wrap:
                header_len = len(key_header)
                if header_len > 0xFFFFFFFF:
                    raise ValueError("fwxAES key header too large")
                key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
                header += bytes([
                    basefwx.FWXAES_ALGO,
                    basefwx.FWXAES_KDF_WRAP,
                    0,
                    basefwx.FWXAES_IV_LEN
                ])
                header += basefwx.struct.pack(">I", header_len)
                header += basefwx.struct.pack(">I", 0)
                handle.write(header)
                handle.write(key_header)
                handle.write(iv)
            else:
                if not pw and not use_master:
                    raise ValueError("Password required when master key usage is disabled")
                salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
                iters = basefwx._fwxaes_iterations(pw)
                key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
                header += bytes([
                    basefwx.FWXAES_ALGO,
                    basefwx.FWXAES_KDF_PBKDF2,
                    basefwx.FWXAES_SALT_LEN,
                    basefwx.FWXAES_IV_LEN
                ])
                header += basefwx.struct.pack(">I", iters)
                header += basefwx.struct.pack(">I", 0)
                handle.write(header)
                handle.write(salt)
                handle.write(iv)

            encryptor = basefwx.Cipher(
                basefwx.algorithms.AES(key),
                basefwx.modes.GCM(iv)
            ).encryptor()
            encryptor.authenticate_additional_data(basefwx.FWXAES_AAD)
            while True:
                buf = source.read(chunk)
                if not buf:
                    break
                ct = encryptor.update(buf)
                if ct:
                    handle.write(ct)
                    ct_len += len(ct)
            tail = encryptor.finalize()
            if tail:
                handle.write(tail)
                ct_len += len(tail)
            handle.write(encryptor.tag)
            ct_len += len(encryptor.tag)
            handle.flush()
            handle.seek(12)
            handle.write(basefwx.struct.pack(">I", ct_len))
            handle.seek(0, basefwx.os.SEEK_END)
            return ct_len

        if basefwx._is_seekable(dest):
            return _encrypt_to(dest)

        tmp = basefwx.tempfile.NamedTemporaryFile("w+b", delete=False)
        try:
            ct_len = _encrypt_to(tmp)
            tmp.seek(0)
            basefwx.shutil.copyfileobj(tmp, dest)
            return ct_len
        finally:
            tmp.close()
            try:
                basefwx.os.remove(tmp.name)
            except FileNotFoundError:
                pass

    @staticmethod
    def fwxAES_decrypt_stream(
        source,
        dest,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        password = basefwx._resolve_password(password, use_master=use_master)
        chunk = basefwx.STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))

        def _decrypt_from(handle) -> int:
            header = handle.read(16)
            if len(header) < 16:
                raise ValueError("fwxAES blob too short")
            if header[:4] != basefwx.FWXAES_MAGIC:
                raise ValueError("fwxAES bad magic")
            algo, kdf, salt_len, iv_len = header[4], header[5], header[6], header[7]
            if algo != basefwx.FWXAES_ALGO or kdf not in (basefwx.FWXAES_KDF_PBKDF2, basefwx.FWXAES_KDF_WRAP):
                raise ValueError("fwxAES unsupported algo/kdf")
            iters = basefwx.struct.unpack(">I", header[8:12])[0]
            ct_len = basefwx.struct.unpack(">I", header[12:16])[0]
            if ct_len < basefwx.AEAD_TAG_LEN:
                raise ValueError("fwxAES ciphertext too short")
            if kdf == basefwx.FWXAES_KDF_WRAP:
                header_len = iters
                key_header = handle.read(header_len)
                if len(key_header) != header_len:
                    raise ValueError("fwxAES blob truncated")
                iv = handle.read(iv_len)
                if len(iv) != iv_len:
                    raise ValueError("fwxAES blob truncated")
                user_blob, master_blob = basefwx._unpack_length_prefixed(key_header, 2)
                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    password,
                    use_master,
                    mask_info=basefwx.FWXAES_MASK_INFO,
                    aad=basefwx.FWXAES_AAD
                )
                key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
            else:
                salt = handle.read(salt_len)
                if len(salt) != salt_len:
                    raise ValueError("fwxAES blob truncated")
                iv = handle.read(iv_len)
                if len(iv) != iv_len:
                    raise ValueError("fwxAES blob truncated")
                pw = basefwx._coerce_password_bytes(password)
                if not pw:
                    raise ValueError("fwxAES password required for PBKDF2 payload")
                key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)

            ct_start = handle.tell()
            tag_pos = ct_start + ct_len - basefwx.AEAD_TAG_LEN
            handle.seek(tag_pos)
            tag = handle.read(basefwx.AEAD_TAG_LEN)
            if len(tag) != basefwx.AEAD_TAG_LEN:
                raise ValueError("fwxAES blob truncated")
            decryptor = basefwx.Cipher(
                basefwx.algorithms.AES(key),
                basefwx.modes.GCM(iv, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(basefwx.FWXAES_AAD)
            handle.seek(ct_start)
            remaining = ct_len - basefwx.AEAD_TAG_LEN
            written = 0
            while remaining > 0:
                buf = handle.read(min(chunk, remaining))
                if not buf:
                    raise ValueError("fwxAES blob truncated")
                remaining -= len(buf)
                plain = decryptor.update(buf)
                if plain:
                    dest.write(plain)
                    written += len(plain)
            try:
                tail = decryptor.finalize()
            except Exception as exc:
                raise ValueError("AES-GCM auth failed") from exc
            if tail:
                dest.write(tail)
                written += len(tail)
            return written

        if basefwx._is_seekable(source):
            return _decrypt_from(source)

        tmp = basefwx.tempfile.NamedTemporaryFile("w+b", delete=False)
        try:
            basefwx.shutil.copyfileobj(source, tmp)
            tmp.flush()
            tmp.seek(0)
            return _decrypt_from(tmp)
        finally:
            tmp.close()
            try:
                basefwx.os.remove(tmp.name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _live_nonce(prefix: bytes, sequence: int) -> bytes:
        if len(prefix) != basefwx.LIVE_NONCE_PREFIX_LEN:
            raise ValueError("Invalid live nonce prefix")
        if sequence < 0 or sequence >= (1 << 64):
            raise ValueError("Live stream sequence overflow")
        return prefix + sequence.to_bytes(8, "big")

    @staticmethod
    def _live_aad(frame_type: int, sequence: int, plain_len: int) -> bytes:
        if plain_len < 0:
            raise ValueError("Invalid live frame length")
        return basefwx.struct.pack(
            ">4sBBQI",
            basefwx.LIVE_FRAME_MAGIC,
            basefwx.LIVE_FRAME_VERSION,
            frame_type & 0xFF,
            sequence & ((1 << 64) - 1),
            plain_len & 0xFFFFFFFF
        )

    @staticmethod
    def _live_pack_frame(frame_type: int, sequence: int, body: bytes) -> bytes:
        if len(body) > 0xFFFFFFFF:
            raise ValueError("Live frame body too large")
        header = basefwx.LIVE_FRAME_HEADER_STRUCT.pack(
            basefwx.LIVE_FRAME_MAGIC,
            basefwx.LIVE_FRAME_VERSION,
            frame_type & 0xFF,
            sequence & ((1 << 64) - 1),
            len(body)
        )
        return header + body

    class LiveEncryptor:
        """Packetized live AEAD encryptor for arbitrary byte streams."""

        def __init__(
            self,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            *,
            use_master: bool = True
        ) -> None:
            self._password = basefwx._resolve_password(password, use_master=use_master)
            self._use_master = bool(use_master)
            self._started = False
            self._finalized = False
            self._sequence = 1
            self._key = b""
            self._nonce_prefix = b""

        def _init_session(self) -> bytes:
            pw = basefwx._coerce_password_bytes(self._password)
            key_mode = basefwx.LIVE_KEYMODE_PBKDF2
            key_header = b""
            salt = b""
            iters = 0
            mask_key = b""
            use_wrap = False
            if self._use_master:
                try:
                    mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(
                        self._password,
                        self._use_master,
                        mask_info=basefwx.FWXAES_MASK_INFO,
                        require_password=False,
                        aad=basefwx.FWXAES_AAD
                    )
                    use_wrap = use_master_effective or not pw
                    if use_wrap:
                        key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
                except Exception:
                    if not pw:
                        raise
                    use_wrap = False
            if use_wrap:
                key_mode = basefwx.LIVE_KEYMODE_WRAP
                self._key = basefwx._hkdf_sha256(
                    mask_key,
                    info=basefwx.FWXAES_KEY_INFO,
                    length=basefwx.FWXAES_KEY_LEN
                )
            else:
                if not pw:
                    raise ValueError("Password required when live stream master key wrapping is disabled")
                salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
                iters = basefwx._fwxaes_iterations(pw)
                self._key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
            self._nonce_prefix = basefwx.os.urandom(basefwx.LIVE_NONCE_PREFIX_LEN)
            body = basefwx.LIVE_HEADER_STRUCT.pack(
                key_mode,
                len(salt),
                len(self._nonce_prefix),
                0,
                len(key_header),
                iters
            ) + key_header + salt + self._nonce_prefix
            return basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_HEADER, 0, body)

        def start(self) -> bytes:
            if self._started:
                raise ValueError("LiveEncryptor already started")
            if self._finalized:
                raise ValueError("LiveEncryptor already finalized")
            frame = self._init_session()
            self._started = True
            return frame

        def update(self, chunk: bytes) -> bytes:
            if not self._started:
                raise ValueError("LiveEncryptor.start() must be called before update()")
            if self._finalized:
                raise ValueError("LiveEncryptor already finalized")
            payload = bytes(chunk)
            if not payload:
                return b""
            nonce = basefwx._live_nonce(self._nonce_prefix, self._sequence)
            aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_DATA, self._sequence, len(payload))
            ct = basefwx.AESGCM(self._key).encrypt(nonce, payload, aad)
            body = basefwx.struct.pack(">I", len(payload)) + ct
            frame = basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_DATA, self._sequence, body)
            self._sequence += 1
            return frame

        def finalize(self) -> bytes:
            if not self._started:
                raise ValueError("LiveEncryptor.start() must be called before finalize()")
            if self._finalized:
                raise ValueError("LiveEncryptor already finalized")
            nonce = basefwx._live_nonce(self._nonce_prefix, self._sequence)
            aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_FIN, self._sequence, 0)
            fin_blob = basefwx.AESGCM(self._key).encrypt(nonce, b"", aad)
            frame = basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_FIN, self._sequence, fin_blob)
            self._sequence += 1
            self._finalized = True
            return frame

    class LiveDecryptor:
        """Incremental parser/decryptor for packetized live AEAD frames."""

        def __init__(
            self,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            *,
            use_master: bool = True
        ) -> None:
            self._password = basefwx._resolve_password(password, use_master=use_master)
            self._use_master = bool(use_master)
            self._buffer = bytearray()
            self._started = False
            self._finished = False
            self._expected_sequence = 0
            self._key = b""
            self._nonce_prefix = b""

        def _parse_header(self, body: bytes) -> None:
            fixed_len = basefwx.LIVE_HEADER_STRUCT.size
            if len(body) < fixed_len:
                raise ValueError("Truncated live stream header")
            key_mode, salt_len, nonce_len, _reserved, key_header_len, iters = basefwx.LIVE_HEADER_STRUCT.unpack(
                body[:fixed_len]
            )
            offset = fixed_len
            need = fixed_len + key_header_len + salt_len + nonce_len
            if len(body) != need:
                raise ValueError("Invalid live stream header length")
            key_header = body[offset:offset + key_header_len]
            offset += key_header_len
            salt = body[offset:offset + salt_len]
            offset += salt_len
            nonce_prefix = body[offset:offset + nonce_len]
            if len(nonce_prefix) != basefwx.LIVE_NONCE_PREFIX_LEN:
                raise ValueError("Invalid live stream nonce prefix")
            if key_mode == basefwx.LIVE_KEYMODE_WRAP:
                if not key_header:
                    raise ValueError("Missing live key header")
                user_blob, master_blob = basefwx._unpack_length_prefixed(key_header, 2)
                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    self._password,
                    self._use_master,
                    mask_info=basefwx.FWXAES_MASK_INFO,
                    aad=basefwx.FWXAES_AAD
                )
                key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
            elif key_mode == basefwx.LIVE_KEYMODE_PBKDF2:
                pw = basefwx._coerce_password_bytes(self._password)
                if not pw:
                    raise ValueError("Password required for PBKDF2 live stream")
                if not salt:
                    raise ValueError("Missing live stream PBKDF2 salt")
                if iters <= 0:
                    raise ValueError("Invalid live stream PBKDF2 iterations")
                key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
            else:
                raise ValueError("Unsupported live key mode")
            self._key = key
            self._nonce_prefix = nonce_prefix
            self._started = True
            self._expected_sequence = 1

        def _decrypt_data_frame(self, sequence: int, body: bytes) -> bytes:
            if len(body) < 4 + basefwx.AEAD_TAG_LEN:
                raise ValueError("Truncated live data frame")
            plain_len = basefwx.struct.unpack(">I", body[:4])[0]
            ct = body[4:]
            nonce = basefwx._live_nonce(self._nonce_prefix, sequence)
            aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_DATA, sequence, plain_len)
            try:
                plain = basefwx.AESGCM(self._key).decrypt(nonce, ct, aad)
            except Exception as exc:
                raise ValueError("Live frame authentication failed") from exc
            if len(plain) != plain_len:
                raise ValueError("Live frame length mismatch")
            return plain

        def _decrypt_fin_frame(self, sequence: int, body: bytes) -> None:
            if len(body) < basefwx.AEAD_TAG_LEN:
                raise ValueError("Truncated live FIN frame")
            nonce = basefwx._live_nonce(self._nonce_prefix, sequence)
            aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_FIN, sequence, 0)
            try:
                plain = basefwx.AESGCM(self._key).decrypt(nonce, body, aad)
            except Exception as exc:
                raise ValueError("Live FIN authentication failed") from exc
            if plain:
                raise ValueError("Live FIN frame carries unexpected payload")
            self._finished = True

        def update(self, data: bytes) -> "list[bytes]":
            if self._finished and data:
                raise ValueError("Live stream already finalized")
            if data:
                self._buffer.extend(data)
            outputs: "list[bytes]" = []
            header_len = basefwx.LIVE_FRAME_HEADER_STRUCT.size
            while len(self._buffer) >= header_len:
                magic, version, frame_type, sequence, body_len = basefwx.LIVE_FRAME_HEADER_STRUCT.unpack(
                    bytes(self._buffer[:header_len])
                )
                if magic != basefwx.LIVE_FRAME_MAGIC:
                    raise ValueError("Invalid live frame magic")
                if version != basefwx.LIVE_FRAME_VERSION:
                    raise ValueError("Unsupported live frame version")
                if body_len > basefwx.KFM_MAX_PAYLOAD:
                    raise ValueError("Live frame too large")
                frame_len = header_len + body_len
                if len(self._buffer) < frame_len:
                    break
                body = bytes(self._buffer[header_len:frame_len])
                del self._buffer[:frame_len]
                if not self._started:
                    if frame_type != basefwx.LIVE_FRAME_TYPE_HEADER or sequence != 0:
                        raise ValueError("Live stream must start with header frame")
                    self._parse_header(body)
                    continue
                if sequence != self._expected_sequence:
                    raise ValueError("Live frame sequence mismatch")
                if frame_type == basefwx.LIVE_FRAME_TYPE_DATA:
                    plain = self._decrypt_data_frame(sequence, body)
                    if plain:
                        outputs.append(plain)
                elif frame_type == basefwx.LIVE_FRAME_TYPE_FIN:
                    self._decrypt_fin_frame(sequence, body)
                else:
                    raise ValueError("Unexpected live frame type")
                self._expected_sequence += 1
            return outputs

        def finalize(self) -> None:
            if not self._started:
                raise ValueError("Missing live stream header frame")
            if not self._finished:
                raise ValueError("Live stream ended without FIN frame")
            if self._buffer:
                raise ValueError("Trailing bytes after live stream FIN")

    @staticmethod
    def fwxAES_live_encrypt_chunks(
        chunks: "basefwx.typing.Iterable[bytes]",
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True
    ) -> "list[bytes]":
        encryptor = basefwx.LiveEncryptor(password, use_master=use_master)
        out: "list[bytes]" = [encryptor.start()]
        for chunk in chunks:
            frame = encryptor.update(bytes(chunk))
            if frame:
                out.append(frame)
        out.append(encryptor.finalize())
        return out

    @staticmethod
    def fwxAES_live_decrypt_chunks(
        chunks: "basefwx.typing.Iterable[bytes]",
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True
    ) -> "list[bytes]":
        decryptor = basefwx.LiveDecryptor(password, use_master=use_master)
        out: "list[bytes]" = []
        for chunk in chunks:
            out.extend(decryptor.update(bytes(chunk)))
        decryptor.finalize()
        return out

    @staticmethod
    def fwxAES_live_encrypt_stream(
        source,
        dest,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        encryptor = basefwx.LiveEncryptor(password, use_master=use_master)
        total = 0
        first = encryptor.start()
        dest.write(first)
        total += len(first)
        chunk = basefwx.LIVE_STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))
        readinto = getattr(source, "readinto", None)
        if callable(readinto):
            buf = bytearray(chunk)
            view = memoryview(buf)
            while True:
                size = readinto(view)
                if not size:
                    break
                frame = encryptor.update(view[:size])
                if frame:
                    dest.write(frame)
                    total += len(frame)
        else:
            while True:
                buf = source.read(chunk)
                if not buf:
                    break
                frame = encryptor.update(buf)
                if frame:
                    dest.write(frame)
                    total += len(frame)
        final = encryptor.finalize()
        dest.write(final)
        total += len(final)
        try:
            dest.flush()
        except Exception:
            pass
        return total

    @staticmethod
    def fwxAES_live_decrypt_stream(
        source,
        dest,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        decryptor = basefwx.LiveDecryptor(password, use_master=use_master)
        chunk = basefwx.LIVE_STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))
        written = 0
        readinto = getattr(source, "readinto", None)
        if callable(readinto):
            buf = bytearray(chunk)
            view = memoryview(buf)
            while True:
                size = readinto(view)
                if not size:
                    break
                for plain in decryptor.update(view[:size]):
                    dest.write(plain)
                    written += len(plain)
        else:
            while True:
                buf = source.read(chunk)
                if not buf:
                    break
                for plain in decryptor.update(buf):
                    dest.write(plain)
                    written += len(plain)
        decryptor.finalize()
        try:
            dest.flush()
        except Exception:
            pass
        return written

    @staticmethod
    def _is_pathlike_target(obj) -> bool:
        return isinstance(obj, (str, bytes, basefwx.os.PathLike, basefwx.pathlib.Path))

    @staticmethod
    def fwxAES_live_encrypt_ffmpeg(
        source_cmd: "basefwx.typing.Sequence[str]",
        encrypted_dest,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        if not source_cmd:
            raise ValueError("source_cmd must not be empty")
        cmd = [str(part) for part in source_cmd]
        hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
            "fwxAES_live_encrypt_ffmpeg",
            stream_type="live",
            prefer_cpu_decode=True,
        )
        basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
        dest_handle = None
        close_dest = False
        if basefwx._is_pathlike_target(encrypted_dest):
            dest_handle = open(basefwx.pathlib.Path(encrypted_dest), "wb")
            close_dest = True
        elif hasattr(encrypted_dest, "write"):
            dest_handle = encrypted_dest
        else:
            raise TypeError("encrypted_dest must be a writable stream or filesystem path")
        proc = basefwx.subprocess.Popen(
            cmd,
            stdin=basefwx.subprocess.DEVNULL,
            stdout=basefwx.subprocess.PIPE,
            stderr=basefwx.subprocess.PIPE,
        )
        stderr_parts: "list[bytes]" = []
        stderr_thread = None
        if proc.stderr is not None:
            def _drain_stderr() -> None:
                try:
                    data = proc.stderr.read()
                    if data:
                        stderr_parts.append(data)
                except Exception:
                    pass
            stderr_thread = basefwx.threading.Thread(target=_drain_stderr, daemon=True)
            stderr_thread.start()
        try:
            if proc.stdout is None:
                raise RuntimeError("source_cmd did not expose stdout")
            written = basefwx.fwxAES_live_encrypt_stream(
                proc.stdout,
                dest_handle,
                password,
                use_master=use_master,
                chunk_size=chunk_size,
            )
            proc.stdout.close()
            rc = proc.wait()
            if stderr_thread is not None:
                stderr_thread.join(timeout=1.0)
            if rc != 0:
                msg = b"".join(stderr_parts).decode("utf-8", errors="replace").strip()
                raise RuntimeError(msg or f"source command failed (exit {rc})")
            return written
        except Exception:
            with basefwx.contextlib.suppress(Exception):
                proc.kill()
            with basefwx.contextlib.suppress(Exception):
                proc.wait(timeout=1.0)
            raise
        finally:
            if proc.stdout is not None:
                with basefwx.contextlib.suppress(Exception):
                    proc.stdout.close()
            if proc.stderr is not None:
                with basefwx.contextlib.suppress(Exception):
                    proc.stderr.close()
            if close_dest and dest_handle is not None:
                with basefwx.contextlib.suppress(Exception):
                    dest_handle.close()

    @staticmethod
    def fwxAES_live_decrypt_ffmpeg(
        encrypted_source,
        sink_cmd: "basefwx.typing.Sequence[str]",
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        chunk_size: int | None = None
    ) -> int:
        if not sink_cmd:
            raise ValueError("sink_cmd must not be empty")
        cmd = [str(part) for part in sink_cmd]
        hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
            "fwxAES_live_decrypt_ffmpeg",
            stream_type="live",
            prefer_cpu_decode=True,
        )
        basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
        source_handle = None
        close_source = False
        if basefwx._is_pathlike_target(encrypted_source):
            source_handle = open(basefwx.pathlib.Path(encrypted_source), "rb")
            close_source = True
        elif hasattr(encrypted_source, "read"):
            source_handle = encrypted_source
        else:
            raise TypeError("encrypted_source must be a readable stream or filesystem path")
        proc = basefwx.subprocess.Popen(
            cmd,
            stdin=basefwx.subprocess.PIPE,
            stdout=basefwx.subprocess.DEVNULL,
            stderr=basefwx.subprocess.PIPE,
        )
        stderr_parts: "list[bytes]" = []
        stderr_thread = None
        if proc.stderr is not None:
            def _drain_stderr() -> None:
                try:
                    data = proc.stderr.read()
                    if data:
                        stderr_parts.append(data)
                except Exception:
                    pass
            stderr_thread = basefwx.threading.Thread(target=_drain_stderr, daemon=True)
            stderr_thread.start()
        try:
            if proc.stdin is None:
                raise RuntimeError("sink_cmd did not expose stdin")
            written = basefwx.fwxAES_live_decrypt_stream(
                source_handle,
                proc.stdin,
                password,
                use_master=use_master,
                chunk_size=chunk_size,
            )
            proc.stdin.close()
            rc = proc.wait()
            if stderr_thread is not None:
                stderr_thread.join(timeout=1.0)
            if rc != 0:
                msg = b"".join(stderr_parts).decode("utf-8", errors="replace").strip()
                raise RuntimeError(msg or f"sink command failed (exit {rc})")
            return written
        except Exception:
            with basefwx.contextlib.suppress(Exception):
                proc.kill()
            with basefwx.contextlib.suppress(Exception):
                proc.wait(timeout=1.0)
            raise
        finally:
            if proc.stdin is not None:
                with basefwx.contextlib.suppress(Exception):
                    proc.stdin.close()
            if proc.stderr is not None:
                with basefwx.contextlib.suppress(Exception):
                    proc.stderr.close()
            if close_source and source_handle is not None:
                with basefwx.contextlib.suppress(Exception):
                    source_handle.close()

    @staticmethod
    def _bytes_to_bits(data: bytes) -> str:
        return "".join(f"{b:08b}" for b in data)

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        if len(bits) % 8:
            raise ValueError("bits not multiple of 8")
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

    @staticmethod
    def normalize_wrap(blob: bytes, cover_phrase: str = "low taper fade") -> str:
        if not cover_phrase.strip():
            raise ValueError("cover_phrase empty")
        payload = basefwx.struct.pack(">I", len(blob)) + blob
        bits = basefwx._bytes_to_bits(payload)
        words = cover_phrase.split()
        token_count = len(bits) + 1
        repeats = (token_count + len(words) - 1) // len(words)
        tokens = (words * repeats)[:token_count]
        out_parts: "basefwx.typing.List[str]" = []
        bit_idx = 0
        for idx, token in enumerate(tokens):
            if idx > 0:
                out_parts.append(" ")
                out_parts.append(basefwx.ZW1 if bits[bit_idx] == "1" else basefwx.ZW0)
                bit_idx += 1
            out_parts.append(token)
        if bit_idx != len(bits):
            raise RuntimeError("failed to embed all bits")
        return "".join(out_parts)

    @staticmethod
    def normalize_unwrap(text: str) -> bytes:
        bits: "basefwx.typing.List[str]" = []
        for ch in text:
            if ch == basefwx.ZW0:
                bits.append("0")
            elif ch == basefwx.ZW1:
                bits.append("1")
        if len(bits) < 32:
            raise ValueError("not enough hidden data")
        length = int("".join(bits[:32]), 2)
        needed = 32 + length * 8
        if len(bits) < needed:
            raise ValueError("hidden data truncated")
        blob_bits = "".join(bits[32:needed])
        return basefwx._bits_to_bytes(blob_bits)

    @staticmethod
    def _wrap_pack_header(blob: bytes, pack_flag: str) -> bytes:
        if pack_flag not in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
            raise ValueError("Unsupported pack flag")
        header = basefwx.FWX_PACK_MAGIC + bytes([ord(pack_flag)]) + len(blob).to_bytes(8, 'big')
        return header + blob

    @staticmethod
    def _unwrap_pack_header(data: bytes) -> "basefwx.typing.Optional[tuple[str, bytes]]":
        if len(data) < basefwx.FWX_PACK_HEADER_LEN:
            return None
        if not data.startswith(basefwx.FWX_PACK_MAGIC):
            return None
        flag = chr(data[len(basefwx.FWX_PACK_MAGIC)])
        if flag not in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
            return None
        length_start = len(basefwx.FWX_PACK_MAGIC) + 1
        length = int.from_bytes(data[length_start:length_start + 8], 'big')
        if length != len(data) - basefwx.FWX_PACK_HEADER_LEN:
            return None
        return flag, data[basefwx.FWX_PACK_HEADER_LEN:]

    @staticmethod
    def fwxAES_file(
        file: "basefwx.typing.Union[str, basefwx.pathlib.Path]",
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
        *,
        use_master: bool = True,
        output: "basefwx.typing.Optional[str]" = None,
        normalize: bool = False,
        normalize_threshold: "basefwx.typing.Optional[int]" = None,
        cover_phrase: str = "low taper fade",
        compress: bool = False,
        ignore_media: bool = False,
        keep_meta: bool = False,
        archive_original: bool = False,
        keep_input: bool = False
    ) -> str:
        password = basefwx._resolve_password(password, use_master=use_master)
        path = basefwx._normalize_path(file)
        threshold = basefwx.NORMALIZE_THRESHOLD if normalize_threshold is None else int(normalize_threshold)
        if path.suffix.lower() == ".fwx":
            data = path.read_bytes()
            if data.startswith(basefwx.FWXAES_MAGIC):
                blob = data
            else:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError("Input is not a valid FWX1 blob or UTF-8 normalized text") from exc
                blob = basefwx.normalize_unwrap(text)
            plain = basefwx.fwxAES_decrypt_raw(blob, password, use_master=use_master)
            packed = basefwx._unwrap_pack_header(plain)
            if packed:
                pack_flag, archive_bytes = packed
                dest_path = basefwx._normalize_path(output) if output else path.parent
                dest_dir = dest_path if dest_path.exists() and dest_path.is_dir() else dest_path.parent
                temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-pack-dec-")
                try:
                    suffix = basefwx.PACK_SUFFIX_XZ if pack_flag == basefwx.PACK_TAR_XZ else basefwx.PACK_SUFFIX_GZ
                    archive_path = basefwx.pathlib.Path(temp_dir.name) / f"{path.stem}{suffix}"
                    archive_path.write_bytes(archive_bytes)
                    extracted = basefwx._unpack_archive(archive_path, pack_flag, target_dir=dest_dir)
                    return str(extracted)
                finally:
                    temp_dir.cleanup()
            out_path = basefwx._normalize_path(output) if output else path.with_suffix('')
            with open(out_path, 'wb') as handle:
                handle.write(plain)
            return str(out_path)
        if not ignore_media:
            try:
                media_ext = path.suffix.lower()
                if media_ext in (basefwx.MediaCipher.IMAGE_EXTS | basefwx.MediaCipher.VIDEO_EXTS | basefwx.MediaCipher.AUDIO_EXTS):
                    return basefwx.MediaCipher.encrypt_media(
                        str(path),
                        password,
                        output=output,
                        keep_meta=keep_meta,
                        archive_original=archive_original,
                        keep_input=keep_input
                    )
            except Exception:
                pass
        pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
        if pack_ctx:
            archive_path, pack_flag, pack_temp = pack_ctx
            try:
                payload = basefwx._wrap_pack_header(archive_path.read_bytes(), pack_flag)
            finally:
                pack_temp.cleanup()
        else:
            payload = path.read_bytes()
        blob = basefwx.fwxAES_encrypt_raw(payload, password, use_master=use_master)
        out_path = basefwx._normalize_path(output) if output else path.with_suffix('.fwx')
        if normalize and len(payload) <= threshold:
            text = basefwx.normalize_wrap(blob, cover_phrase)
            out_path.write_text(text, encoding="utf-8", newline="\n")
        else:
            out_path.write_bytes(blob)
        basefwx._remove_input(path, keep_input, out_path)
        return str(out_path)
    # REVERSIBLE  - SECURITY: ❙
    @staticmethod
    def b64encode(string: str):

        return basefwx.base64.b64encode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64decode(string: str):

        return basefwx.base64.b64decode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _n10_mod_sub(value: int, sub: int) -> int:
        if value >= sub:
            return value - sub
        return basefwx.N10_MOD - (sub - value)

    @staticmethod
    def _n10_mix64(value: int) -> int:
        value = (value + 0x9E3779B97F4A7C15) & basefwx.N10_MASK64
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & basefwx.N10_MASK64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & basefwx.N10_MASK64
        return (value ^ (value >> 31)) & basefwx.N10_MASK64

    @staticmethod
    def _n10_offset(index: int) -> int:
        return basefwx._n10_mix64(index ^ 0xA5A5F0F01234ABCD) % basefwx.N10_MOD

    @staticmethod
    def _n10_transform(value: int, index: int) -> int:
        if value < 0 or value >= basefwx.N10_MOD:
            raise ValueError("n10 value too large")
        mixed = (value + basefwx._n10_offset(index)) % basefwx.N10_MOD
        return ((basefwx.N10_MUL * mixed) + basefwx.N10_ADD) % basefwx.N10_MOD

    @staticmethod
    def _n10_inverse_transform(encoded: int, index: int) -> int:
        if encoded < 0 or encoded >= basefwx.N10_MOD:
            raise ValueError("n10 encoded value too large")
        step = basefwx._n10_mod_sub(encoded, basefwx.N10_ADD)
        mixed = (step * basefwx.N10_MUL_INV) % basefwx.N10_MOD
        return basefwx._n10_mod_sub(mixed, basefwx._n10_offset(index))

    @staticmethod
    def _n10_parse_fixed10(payload: str, offset: int) -> int:
        part = payload[offset:offset + 10]
        if len(part) != 10:
            raise ValueError("n10 payload truncated")
        if not part.isdigit():
            raise ValueError("n10 payload must contain only digits")
        return int(part)

    @staticmethod
    def _n10_fnv1a32(data: bytes) -> int:
        hash_value = 2166136261
        for byte in data:
            hash_value ^= byte
            hash_value = (hash_value * 16777619) & 0xFFFFFFFF
        return hash_value

    @staticmethod
    def n10encode(data):
        if isinstance(data, str):
            return basefwx.n10encode_bytes(data.encode('utf-8'))
        return basefwx.n10encode_bytes(data)

    @staticmethod
    def n10encode_bytes(data):
        if isinstance(data, memoryview):
            raw = data.tobytes()
        elif isinstance(data, bytearray):
            raw = bytes(data)
        elif isinstance(data, bytes):
            raw = data
        else:
            raise TypeError("n10encode_bytes expects bytes-like input")

        if len(raw) >= basefwx.N10_MOD:
            raise ValueError("n10 input is too large")

        block_count = (len(raw) + 3) // 4
        parts = [
            basefwx.N10_MAGIC,
            basefwx.N10_VERSION,
            f"{basefwx._n10_transform(len(raw), 0):010d}",
            f"{basefwx._n10_transform(basefwx._n10_fnv1a32(raw), 1):010d}",
        ]

        offset = 0
        for block in range(block_count):
            word = 0
            chunk = raw[offset:offset + 4]
            for idx, byte in enumerate(chunk):
                word |= byte << (24 - (idx * 8))
            parts.append(f"{basefwx._n10_transform(word, block + 2):010d}")
            offset += len(chunk)

        return "".join(parts)

    @staticmethod
    def n10decode(digits: str, errors: str = "strict"):
        return basefwx.n10decode_bytes(digits).decode('utf-8', errors=errors)

    @staticmethod
    def n10decode_bytes(digits: str):
        if not isinstance(digits, str):
            raise TypeError("n10decode expects string digits")
        payload = digits.strip()
        if len(payload) < basefwx.N10_HEADER_DIGITS:
            raise ValueError("n10 payload is too short")
        if payload[:6] != basefwx.N10_MAGIC or payload[6:8] != basefwx.N10_VERSION:
            raise ValueError("n10 header mismatch")

        payload_len = basefwx._n10_inverse_transform(basefwx._n10_parse_fixed10(payload, 8), 0)
        if payload_len >= basefwx.N10_MOD:
            raise ValueError("n10 decoded length is invalid")

        checksum_expected = basefwx._n10_inverse_transform(basefwx._n10_parse_fixed10(payload, 18), 1)
        if checksum_expected > 0xFFFFFFFF:
            raise ValueError("n10 checksum is invalid")

        block_count = (payload_len + 3) // 4
        expected_digits = basefwx.N10_HEADER_DIGITS + (block_count * 10)
        if len(payload) != expected_digits:
            raise ValueError("n10 payload length mismatch")

        out = bytearray(block_count * 4)
        in_offset = basefwx.N10_HEADER_DIGITS
        for block in range(block_count):
            decoded = basefwx._n10_inverse_transform(basefwx._n10_parse_fixed10(payload, in_offset), block + 2)
            in_offset += 10
            if decoded > 0xFFFFFFFF:
                raise ValueError("n10 block out of range")
            out_offset = block * 4
            out[out_offset] = (decoded >> 24) & 0xFF
            out[out_offset + 1] = (decoded >> 16) & 0xFF
            out[out_offset + 2] = (decoded >> 8) & 0xFF
            out[out_offset + 3] = decoded & 0xFF

        raw = bytes(out[:payload_len])
        if basefwx._n10_fnv1a32(raw) != checksum_expected:
            raise ValueError("n10 checksum mismatch")
        return raw

    @staticmethod
    def _kfm_clean_ext(ext: str) -> str:
        normalized = (ext or "").strip().lower()
        if not normalized:
            return ".bin"
        if not normalized.startswith("."):
            normalized = f".{normalized}"
        if len(normalized) > 24:
            return ".bin"
        allowed = set("._-abcdefghijklmnopqrstuvwxyz0123456789")
        if any(ch not in allowed for ch in normalized):
            return ".bin"
        return normalized

    @staticmethod
    def _kfm_is_audio_ext(ext: str) -> bool:
        return basefwx._kfm_clean_ext(ext) in basefwx.KFM_AUDIO_EXTENSIONS

    @staticmethod
    def _kfm_is_image_ext(ext: str) -> bool:
        return basefwx._kfm_clean_ext(ext) in basefwx.KFM_IMAGE_EXTENSIONS

    @staticmethod
    def _kfm_warn(message: str) -> None:
        _warnings_module.warn(message, RuntimeWarning, stacklevel=3)

    @staticmethod
    def _kfm_paths_equal(a: "basefwx.pathlib.Path", b: "basefwx.pathlib.Path") -> bool:
        try:
            return a.resolve() == b.resolve()
        except Exception:
            return a.absolute() == b.absolute()

    @staticmethod
    def _kfm_default_output(src: "basefwx.pathlib.Path", ext: str, tag: str) -> "basefwx.pathlib.Path":
        candidate = src.with_suffix(ext)
        if basefwx._kfm_paths_equal(candidate, src):
            candidate = src.with_name(f"{src.stem}.{tag}{ext}")
        return candidate

    @staticmethod
    def _kfm_resolve_output(src: "basefwx.pathlib.Path",
                            output: str | None,
                            ext: str,
                            tag: str) -> "basefwx.pathlib.Path":
        if output:
            out_path = basefwx.pathlib.Path(output)
            if basefwx._kfm_paths_equal(out_path, src):
                raise ValueError("Refusing to overwrite input file; choose a different output path")
            return out_path
        return basefwx._kfm_default_output(src, ext, tag)

    @staticmethod
    def _kfm_keystream(seed: int, length: int, *, legacy_blake2s: bool = False) -> bytes:
        if length <= 0:
            return b""
        out = bytearray(length)
        seed_bytes = seed.to_bytes(8, "big", signed=False)
        cursor = 0
        counter = 0
        digest_fn = basefwx.hashlib.blake2s if legacy_blake2s else basefwx.hashlib.sha256
        while cursor < length:
            block = digest_fn(
                seed_bytes + counter.to_bytes(8, "big", signed=False)
            ).digest()
            take = min(length - cursor, len(block))
            out[cursor:cursor + take] = block[:take]
            cursor += take
            counter += 1
        return bytes(out)

    @staticmethod
    def _kfm_xor(data: bytes, mask: bytes) -> bytes:
        if len(data) != len(mask):
            raise ValueError("kFM mask length mismatch")
        out = bytearray(len(data))
        for idx in range(len(data)):
            out[idx] = data[idx] ^ mask[idx]
        return bytes(out)

    @staticmethod
    def _kfm_pack_container(mode: int, payload: bytes, ext: str, *, flags: int = 0) -> bytes:
        if mode not in (basefwx.KFM_MODE_IMAGE_AUDIO, basefwx.KFM_MODE_AUDIO_IMAGE):
            raise ValueError("kFM mode is invalid")
        if isinstance(payload, memoryview):
            raw = payload.tobytes()
        elif isinstance(payload, bytearray):
            raw = bytes(payload)
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raise TypeError("kFM payload must be bytes-like")
        if len(raw) > basefwx.KFM_MAX_PAYLOAD:
            raise ValueError("kFM payload is too large")
        ext_clean = basefwx._kfm_clean_ext(ext)
        ext_bytes = ext_clean.encode("utf-8")
        if len(ext_bytes) > 255:
            ext_bytes = b".bin"
        seed = int.from_bytes(basefwx.secrets.token_bytes(8), "big", signed=False)
        body = ext_bytes + raw
        masked = basefwx._kfm_xor(body, basefwx._kfm_keystream(seed, len(body)))
        crc32 = basefwx.zlib.crc32(raw) & 0xFFFFFFFF
        header = basefwx.KFM_HEADER_STRUCT.pack(
            basefwx.KFM_MAGIC,
            basefwx.KFM_VERSION,
            mode,
            flags & 0xFF,
            len(ext_bytes),
            len(raw),
            crc32,
            seed,
            0,
        )
        return header + masked

    @staticmethod
    def _kfm_unpack_container(blob: bytes) -> "basefwx.typing.Optional[dict]":
        if isinstance(blob, memoryview):
            data = blob.tobytes()
        elif isinstance(blob, bytearray):
            data = bytes(blob)
        elif isinstance(blob, bytes):
            data = blob
        else:
            return None
        if len(data) < basefwx.KFM_HEADER_LEN:
            return None
        try:
            magic, version, mode, flags, ext_len, payload_len, crc32, seed, _ = (
                basefwx.KFM_HEADER_STRUCT.unpack(data[:basefwx.KFM_HEADER_LEN])
            )
        except basefwx.struct.error:
            return None
        if magic != basefwx.KFM_MAGIC or version != basefwx.KFM_VERSION:
            return None
        if mode not in (basefwx.KFM_MODE_IMAGE_AUDIO, basefwx.KFM_MODE_AUDIO_IMAGE):
            return None
        body_len = ext_len + payload_len
        if body_len < ext_len:
            return None
        if body_len > len(data) - basefwx.KFM_HEADER_LEN:
            return None
        masked = data[basefwx.KFM_HEADER_LEN:basefwx.KFM_HEADER_LEN + body_len]
        body = basefwx._kfm_xor(masked, basefwx._kfm_keystream(seed, body_len))
        ext_bytes = body[:ext_len]
        payload = body[ext_len:]
        if (basefwx.zlib.crc32(payload) & 0xFFFFFFFF) != crc32:
            # Backward compatibility: older Python previews used BLAKE2s here.
            legacy_body = basefwx._kfm_xor(
                masked,
                basefwx._kfm_keystream(seed, body_len, legacy_blake2s=True),
            )
            legacy_payload = legacy_body[ext_len:]
            if (basefwx.zlib.crc32(legacy_payload) & 0xFFFFFFFF) != crc32:
                return None
            body = legacy_body
            ext_bytes = body[:ext_len]
            payload = legacy_payload
        try:
            ext = ext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            ext = ".bin"
        return {
            "mode": mode,
            "flags": flags,
            "ext": basefwx._kfm_clean_ext(ext),
            "payload": payload,
        }

    @staticmethod
    def _kfm_bytes_to_wav(data: bytes, output_path: "basefwx.pathlib.Path") -> None:
        if isinstance(data, memoryview):
            raw = data.tobytes()
        elif isinstance(data, bytearray):
            raw = bytes(data)
        else:
            raw = data
        if len(raw) % 2:
            raw += b"\x00"
        pcm = bytearray(len(raw))
        for idx in range(0, len(raw), 2):
            value = raw[idx] | (raw[idx + 1] << 8)
            sample = value - 32768
            pcm[idx:idx + 2] = basefwx.struct.pack("<h", sample)
        with basefwx.wave.open(str(output_path), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(basefwx.KFM_AUDIO_RATE)
            wav_file.writeframes(bytes(pcm))

    @staticmethod
    def _kfm_wav_to_bytes(path: "basefwx.pathlib.Path") -> bytes:
        with basefwx.wave.open(str(path), "rb") as wav_file:
            channels = wav_file.getnchannels()
            width = wav_file.getsampwidth()
            frames = wav_file.readframes(wav_file.getnframes())
        if channels != 1 or width != 2:
            return frames
        return basefwx._kfm_pcm16le_to_bytes(frames)

    @staticmethod
    def _kfm_pcm16le_to_bytes(frames: bytes) -> bytes:
        if len(frames) % 2:
            frames += b"\x00"
        out = bytearray(len(frames))
        for idx in range(0, len(frames), 2):
            sample = basefwx.struct.unpack("<h", frames[idx:idx + 2])[0]
            value = (sample + 32768) & 0xFFFF
            out[idx:idx + 2] = basefwx.struct.pack("<H", value)
        return bytes(out)

    @staticmethod
    def _kfm_ffmpeg_audio_to_bytes(path: "basefwx.pathlib.Path") -> bytes:
        ffmpeg_bin = basefwx.os.environ.get("BASEFWX_FFMPEG_BIN", "ffmpeg")
        cmd = [
            ffmpeg_bin,
            "-v", "error",
            "-i", str(path),
            "-f", "s16le",
            "-ac", "1",
            "-ar", str(basefwx.KFM_AUDIO_RATE),
            "-",
        ]
        try:
            result = basefwx.subprocess.run(cmd, capture_output=True, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError(
                "ffmpeg is required to read non-WAV audio (mp3/m4a). "
                "Install ffmpeg or provide WAV input."
            ) from exc
        if result.returncode != 0:
            stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
            detail = f": {stderr}" if stderr else ""
            raise RuntimeError(f"ffmpeg failed to decode audio{detail}")
        if not result.stdout:
            raise RuntimeError("ffmpeg produced no PCM output")
        return basefwx._kfm_pcm16le_to_bytes(result.stdout)

    @staticmethod
    def _kfm_audio_to_bytes(path: "basefwx.pathlib.Path") -> bytes:
        wav_error = None
        try:
            return basefwx._kfm_wav_to_bytes(path)
        except Exception as exc:
            wav_error = exc
        try:
            return basefwx._kfm_ffmpeg_audio_to_bytes(path)
        except Exception as ffmpeg_error:
            raise RuntimeError(
                f"Failed to decode audio carrier from {path.name}. "
                f"WAV parse error: {wav_error}; ffmpeg error: {ffmpeg_error}"
            ) from ffmpeg_error

    @staticmethod
    def _kfm_bytes_to_png(data: bytes, output_path: "basefwx.pathlib.Path", *, bw_mode: bool = False) -> None:
        if basefwx.Image is None:
            raise RuntimeError("Pillow is required for kFM PNG operations")
        if isinstance(data, memoryview):
            raw = data.tobytes()
        elif isinstance(data, bytearray):
            raw = bytes(data)
        else:
            raw = data
        channels = 1 if bw_mode else 3
        mode = "L" if bw_mode else "RGB"
        pixels = max(1, (len(raw) + channels - 1) // channels)
        width = max(1, int(basefwx.math.sqrt(pixels)))
        if width * width < pixels:
            width += 1
        height = (pixels + width - 1) // width
        capacity = width * height * channels
        carrier = bytearray(basefwx.secrets.token_bytes(capacity))
        carrier[:len(raw)] = raw
        image = basefwx.Image.frombytes(mode, (width, height), bytes(carrier))
        image.save(str(output_path), format="PNG")

    @staticmethod
    def _kfm_png_to_bytes(path: "basefwx.pathlib.Path") -> bytes:
        if basefwx.Image is None:
            raise RuntimeError("Pillow is required for kFM PNG operations")
        with basefwx.Image.open(str(path)) as image:
            if image.mode == "L":
                return image.tobytes()
            if image.mode != "RGB":
                image = image.convert("RGB")
            return image.tobytes()

    @staticmethod
    def _kfm_detect_carrier_kinds(
        src: "basefwx.pathlib.Path",
        src_ext: str
    ) -> "basefwx.typing.List[str]":
        if basefwx._kfm_is_audio_ext(src_ext):
            return ["audio"]
        if basefwx._kfm_is_image_ext(src_ext):
            return ["image"]
        head = b""
        try:
            with src.open("rb") as handle:
                head = handle.read(16)
        except Exception:
            head = b""
        kinds: list[str] = []
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            kinds.append("image")
        if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WAVE":
            kinds.append("audio")
        if not kinds:
            kinds = ["audio", "image"]
        else:
            if "audio" not in kinds:
                kinds.append("audio")
            if "image" not in kinds:
                kinds.append("image")
        return kinds

    @staticmethod
    def _kfm_decode_container(src: "basefwx.pathlib.Path", src_ext: str) -> dict:
        kinds = basefwx._kfm_detect_carrier_kinds(src, src_ext)
        attempt_errors: list[str] = []
        for kind in kinds:
            try:
                carrier = (
                    basefwx._kfm_audio_to_bytes(src)
                    if kind == "audio"
                    else basefwx._kfm_png_to_bytes(src)
                )
            except Exception as exc:
                if len(kinds) == 1:
                    raise
                attempt_errors.append(f"{kind}: {exc}")
                continue
            decoded = basefwx._kfm_unpack_container(carrier)
            if decoded is not None:
                return decoded
            attempt_errors.append(f"{kind}: no BaseFWX header")
        detail = "; ".join(attempt_errors[:2])
        if detail:
            detail = f" ({detail})"
        raise ValueError(
            "kFMd refused input: file is not a BaseFWX kFM carrier. "
            f"Use kFMe to encode first{detail}."
        )

    @staticmethod
    def kFMe(path: str, output: str | None = None, *, bw_mode: bool = False) -> str:
        src = basefwx.pathlib.Path(path)
        src_ext = basefwx._kfm_clean_ext(src.suffix)
        payload = src.read_bytes()
        if basefwx._kfm_is_audio_ext(src_ext):
            flags = basefwx.KFM_FLAG_BW if bw_mode else 0
            container = basefwx._kfm_pack_container(
                basefwx.KFM_MODE_AUDIO_IMAGE,
                payload,
                src_ext,
                flags=flags,
            )
            out_path = basefwx._kfm_resolve_output(src, output, ".png", "kfme")
            basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
        else:
            container = basefwx._kfm_pack_container(
                basefwx.KFM_MODE_IMAGE_AUDIO,
                payload,
                src_ext,
            )
            out_path = basefwx._kfm_resolve_output(src, output, ".wav", "kfme")
            basefwx._kfm_bytes_to_wav(container, out_path)
        return str(out_path)

    @staticmethod
    def _kfae_legacy_encode(path: str, output: str | None = None, *, bw_mode: bool = False) -> str:
        src = basefwx.pathlib.Path(path)
        src_ext = basefwx._kfm_clean_ext(src.suffix)
        payload = src.read_bytes()
        flags = basefwx.KFM_FLAG_BW if bw_mode else 0
        container = basefwx._kfm_pack_container(
            basefwx.KFM_MODE_AUDIO_IMAGE,
            payload,
            src_ext,
            flags=flags,
        )
        out_path = basefwx._kfm_resolve_output(src, output, ".png", "kfae")
        basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
        return str(out_path)

    @staticmethod
    def kFMd(path: str, output: str | None = None, *, bw_mode: bool = False) -> str:
        src = basefwx.pathlib.Path(path)
        src_ext = basefwx._kfm_clean_ext(src.suffix)
        if bw_mode:
            basefwx._kfm_warn("kFMd --bw is deprecated and ignored in strict decode mode.")
        decoded = basefwx._kfm_decode_container(src, src_ext)
        ext = decoded["ext"]
        out_path = basefwx._kfm_resolve_output(src, output, ext, "kfmd")
        out_path.write_bytes(decoded["payload"])
        return str(out_path)

    @staticmethod
    def kFAe(path: str, output: str | None = None, *, bw_mode: bool = False) -> str:
        basefwx._kfm_warn(
            "kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode."
        )
        return basefwx._kfae_legacy_encode(path, output, bw_mode=bw_mode)

    @staticmethod
    def kFAd(path: str, output: str | None = None) -> str:
        basefwx._kfm_warn("kFAd is deprecated; use kFMd (auto-detect) instead.")
        return basefwx.kFMd(path, output)

    @staticmethod
    def hash512(string: str):

        return basefwx.hashlib.sha512(string.encode('utf-8')).hexdigest()

    @staticmethod
    def _looks_like_base64(text: str) -> bool:
        try:
            basefwx.base64.b64decode(text, validate=True)
            return True
        except Exception:
            return False

    @staticmethod
    def _maybe_obfuscate_codecs(text: str) -> str:
        if not basefwx.ENABLE_CODEC_OBFUSCATION:
            return text
        return basefwx.code(text)

    @staticmethod
    def _maybe_deobfuscate_codecs(text: str) -> str:
        if basefwx._looks_like_base64(text):
            return text
        try:
            return basefwx.decode(text)
        except Exception:
            return text

    @staticmethod
    def uhash513(string: str):
        sti = string
        if basefwx.os.getenv("BASEFWX_UHASH_LEGACY") == "1":
            return basefwx.hashlib.sha256(basefwx.b512encode(basefwx.hashlib.sha512(
                basefwx.hashlib.sha1(
                    basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                    "utf-8")).hexdigest(), basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
                'utf-8')).hexdigest()
        h1 = basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest()
        h2 = basefwx.hashlib.sha1(h1.encode('utf-8')).hexdigest()
        h3 = basefwx.hashlib.sha512(h2.encode('utf-8')).hexdigest()
        h4 = basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()
        return basefwx.hashlib.sha256((h3 + h4).encode('utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(t, p, use_master: bool = True):
        """
        Password-based reversible encoding with URL-safe base64.
        
        Output is URL-safe (no + or /) when BASEFWX_OBFUSCATE_CODECS=0.
        With obfuscation enabled (default), output may contain special characters
        but provides additional security through character substitution.
        
        Confidentiality comes from AEAD layers, not this routine.
        """
        p = basefwx._resolve_password(p, use_master=use_master)
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            p,
            use_master,
            mask_info=b'basefwx.pb512.mask.v1',
            require_password=True,
            aad=b'pb512'
        )
        plain_bytes = t.encode('utf-8')
        masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.pb512.stream.v1')
        # Use bytearray for efficient buffer construction
        # Payload format: [version(1)] [length(4)] [masked_data(n)]
        payload = bytearray(1 + 4 + len(masked))
        payload[0] = 0x02  # Version 2 format with length prefix
        payload[1:5] = len(plain_bytes).to_bytes(4, 'big')
        payload[5:] = masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, bytes(payload))
        # Use URL-safe base64 encoding (replaces + with - and / with _)
        result = basefwx.base64.urlsafe_b64encode(blob).decode('utf-8')
        result = basefwx._maybe_obfuscate_codecs(result)
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def pb512decode(digs, key, use_master: bool = True):
        key = basefwx._resolve_password(key, use_master=use_master)
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            digs = basefwx._maybe_deobfuscate_codecs(digs)
            # Support both URL-safe and standard base64 for backward compatibility
            raw = basefwx.base64.urlsafe_b64decode(digs)
        except Exception as exc:
            # Try standard base64 for backward compatibility with old pb512 format
            try:
                raw = basefwx.base64.b64decode(digs)
            except Exception:
                if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                    print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                    return basefwx._pb512decode_legacy(digs, key, use_master)
                raise ValueError("Invalid pb512 payload encoding") from exc
        try:
            user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
        except ValueError:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise
        mask_key = basefwx._recover_mask_key_from_blob(
            user_blob,
            master_blob,
            key,
            use_master,
            mask_info=b'basefwx.pb512.mask.v1',
            aad=b'pb512'
        )
        if not payload or payload[0] != 0x02:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("Unsupported pb512 payload format")
        if len(payload) < 5:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("Malformed pb512 payload")
        expected_len = int.from_bytes(payload[1:5], 'big')
        masked = payload[5:]
        if expected_len != len(masked):
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("pb512 payload length mismatch")
        clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.pb512.stream.v1')
        result = clear.decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('clear')
        basefwx._del('masked')
        return result

    @staticmethod
    def _pb512decode_legacy(digs, key, use_master: bool = True) -> str:
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            ln = int(digs[:6])
            val = int(digs[6:])
        except ValueError as exc:
            raise ValueError("Malformed legacy pb512 payload") from exc
        raw = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        if len(raw) < ln:
            raw = (b"\x00" * (ln - len(raw))) + raw

        def rc(buf, offset):
            length = int.from_bytes(buf[offset:offset + 4], 'big')
            offset += 4
            part = buf[offset:offset + length]
            offset += length
            return part, offset

        offset = 0
        ecu, offset = rc(raw, offset)
        ecm, offset = rc(raw, offset)
        cb, offset = rc(raw, offset)
        master_blob_present = len(ecm) > 0
        if master_blob_present and not use_master:
            raise ValueError("Master key required to decode this payload")

        def mdcode(s):
            parts = []
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                parts.append(str(len(x)))
                parts.append(x)
            return "".join(parts)

        def decrypt_chunks_from_string(e, n):
            c = len(n)
            z = []
            kx = int(n)
            x = 10 ** c
            l = int(e[-10:])
            e2 = e[:-10]
            for i in range(0, len(e2), c):
                d = int(e2[i:i + c])
                f = (d - kx) % x
                z.append(str(f).zfill(c))
            return ''.join(z)[:l]

        def mcode(s):
            chars = []
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for x in arr:
                h += 1
                if x != "":
                    if h == 1:
                        L = int(x)
                        chars.append(chr(int(s[h:h + L])))
                        o = h
                    elif L + o + 1 == h:
                        L = int(x)
                        chars.append(chr(int(s[h:h + L])))
                        o = h
            return "".join(chars)

        if master_blob_present:
            private_key = basefwx._load_master_pq_private()
            kem_shared = basefwx.ml_kem_768.decrypt(private_key, ecm)
            code = basefwx._kem_shared_to_digits(kem_shared, 16)
        else:
            min_len = basefwx.USER_KDF_SALT_SIZE + 16
            if len(ecu) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or IV")
            salt = ecu[:basefwx.USER_KDF_SALT_SIZE]
            iv = ecu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
            cf = ecu[basefwx.USER_KDF_SALT_SIZE + 16:]
            uk, _ = basefwx._derive_user_key(key, salt=salt, kdf="pbkdf2")
            decryptor = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            padded = decryptor.update(cf) + decryptor.finalize()
            unpadder = basefwx.padding.PKCS7(128).unpadder()
            decoded = basefwx.base64.b64decode(unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
            code = decoded
        result = mcode(decrypt_chunks_from_string(cb.decode('utf-8'), mdcode(code)))
        return result

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙

    @staticmethod
    def b512encode(string, user_key, use_master: bool = True):
        user_key = basefwx._resolve_password(user_key, use_master=use_master)
        if not user_key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            user_key,
            use_master,
            mask_info=b'basefwx.b512.mask.v1',
            require_password=False,
            aad=b'b512'
        )
        plain_bytes = string.encode('utf-8')
        masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.b512.stream.v1')
        # Use bytearray for efficient buffer construction
        # Payload format: [version(1)] [length(4)] [masked_data(n)]
        payload = bytearray(1 + 4 + len(masked))
        payload[0] = 0x02  # Version 2 format with length prefix
        payload[1:5] = len(plain_bytes).to_bytes(4, 'big')
        payload[5:] = masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, bytes(payload))
        result = basefwx.base64.b64encode(blob).decode('utf-8')
        result = basefwx._maybe_obfuscate_codecs(result)
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def b512decode(enc, key="", use_master: bool = True):
        key = basefwx._resolve_password(key, use_master=use_master)
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            enc = basefwx._maybe_deobfuscate_codecs(enc)
            raw = basefwx.base64.b64decode(enc)
        except Exception as exc:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Invalid b512 payload encoding") from exc
        try:
            user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
        except ValueError:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise
        mask_key = basefwx._recover_mask_key_from_blob(
            user_blob,
            master_blob,
            key,
            use_master,
            mask_info=b'basefwx.b512.mask.v1',
            aad=b'b512'
        )
        if not payload or payload[0] != 0x02:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Unsupported b512 payload format")
        if len(payload) < 5:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Malformed b512 payload")
        expected_len = int.from_bytes(payload[1:5], 'big')
        masked = payload[5:]
        if expected_len != len(masked):
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("b512 payload length mismatch")
        clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.b512.stream.v1')
        result = clear.decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('clear')
        basefwx._del('masked')
        return result

    @staticmethod
    def _b512decode_legacy(enc, key="", use_master: bool = True) -> str:
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")

        def rc(buf, offset):
            length = int.from_bytes(buf[offset:offset + 4], 'big')
            offset += 4
            part = buf[offset:offset + length]
            offset += length
            return part, offset

        raw = basefwx.base64.b64decode(enc)
        offset = 0
        epu, offset = rc(raw, offset)
        epm, offset = rc(raw, offset)
        ec, offset = rc(raw, offset)

        master_blob_present = len(epm) > 0
        if not use_master and master_blob_present:
            raise ValueError("Master key required to decode this payload")

        def mdcode(s):
            parts = []
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                parts.append(str(len(x)))
                parts.append(x)
            return "".join(parts)

        def decrypt_chunks_from_string(e, n):
            c = len(n)
            kx = int(n)
            x = 10 ** c
            l = int(e[-10:])
            e2 = e[:-10]
            z = []
            for i in range(0, len(e2), c):
                d = int(e2[i:i + c])
                f = (d - kx) % x
                z.append(str(f).zfill(c))
            return ''.join(z)[:l]

        def mcode(s):
            chars = []
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for xx in arr:
                h += 1
                if xx != "":
                    if h == 1:
                        L = int(xx)
                        chars.append(chr(int(s[h:h + L])))
                        o = h
                    elif L + o + 1 == h:
                        L = int(xx)
                        chars.append(chr(int(s[h:h + L])))
                        o = h
            return "".join(chars)

        if master_blob_present:
            private_key = basefwx._load_master_pq_private()
            kem_shared = basefwx.ml_kem_768.decrypt(private_key, epm)
            ep_str = basefwx._kem_shared_to_digits(kem_shared, 16)
            ep = ep_str.encode('utf-8')
        else:
            min_len = basefwx.USER_KDF_SALT_SIZE + 16
            if len(epu) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or IV")
            salt = epu[:basefwx.USER_KDF_SALT_SIZE]
            iv = epu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
            cf = epu[basefwx.USER_KDF_SALT_SIZE + 16:]
            uk, _ = basefwx._derive_user_key(key, salt=salt, kdf="pbkdf2")
            dec = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            out = dec.update(cf) + dec.finalize()
            up = basefwx.padding.PKCS7(128).unpadder()
            ep = basefwx.base64.b64decode(up.update(out) + up.finalize())

        def b512decode_chunk(txt, code):
            st = txt.replace("4G5tRA", "=")
            x = basefwx.fwx256unbin(st)
            if x and x[0] == "0":
                x = "-" + x[1:]
            return mcode(decrypt_chunks_from_string(x, mdcode(code)))

        return b512decode_chunk(ec.decode('utf-8'), ep.decode('utf-8'))

    @staticmethod
    def _b512_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            pack_flag: str = "",
            output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            keep_input: bool = False
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        display_path = display_path or path
        output_path = output_path or path.with_suffix('.fwx')
        input_size = path.stat().st_size
        approx_b64_len = ((input_size + 2) // 3) * 4
        force_stream = approx_b64_len > basefwx.HKDF_MAX_LEN
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", display_path)

        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        obfuscate_payload = input_size <= basefwx.STREAM_THRESHOLD
        if basefwx.ENABLE_B512_AEAD and (input_size >= basefwx.STREAM_THRESHOLD or force_stream):
            return basefwx._b512_encode_path_stream(
                path,
                password,
                reporter,
                file_index,
                total_files,
                strip_metadata,
                use_master,
                master_pubkey,
                pack_flag=pack_flag,
                output_path=output_path,
                display_path=display_path,
                input_size=input_size,
                keep_input=keep_input
            )
        if force_stream:
            raise ValueError("b512file payload too large for non-AEAD mode; enable AEAD or use file streaming")
        data = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", display_path)

        b64_payload = basefwx.base64.b64encode(data).decode('utf-8')
        ext_token = basefwx.b512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
        if reporter:
            reporter.update(file_index, 0.65, "b256", display_path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        use_aead = basefwx.ENABLE_B512_AEAD
        metadata_blob = basefwx._build_metadata(
            "FWX512R",
            strip_metadata,
            use_master_effective,
            aead="AESGCM" if use_aead else "NONE",
            kdf=kdf_used,
            pack=pack_flag or None
        )
        body = f"{ext_token}{basefwx.FWX_DELIM}{data_token}"
        payload = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        payload_bytes = payload.encode('utf-8')

        mask_key = None
        aead_key = None
        ct_blob = None
        user_blob: bytes = b""
        master_blob: bytes = b""
        if use_aead:
            mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
                password,
                use_master_effective,
                mask_info=basefwx.B512_FILE_MASK_INFO,
                require_password=not use_master_effective,
                aad=b'b512file'
            )
            aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
            ct_blob = basefwx._aead_encrypt(aead_key, payload_bytes, basefwx.B512_AEAD_INFO)
            output_bytes = basefwx._pack_length_prefixed(user_blob, master_blob, ct_blob)
        else:
            output_bytes = payload_bytes

        with open(output_path, 'wb') as handle:
            handle.write(output_bytes)

        approx_size = len(output_bytes)
        size_hint = (input_size, approx_size)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx._remove_input(path, keep_input, output_path)

        if reporter:
            reporter.update(file_index, 1.0, "done", output_path, size_hint=size_hint)
            reporter.finalize_file(file_index, output_path, size_hint=size_hint)

        basefwx._del('mask_key')
        basefwx._del('aead_key')
        basefwx._del('ct_blob')
        basefwx._del('payload_bytes')
        basefwx._del('output_bytes')
        basefwx._del('user_blob')
        basefwx._del('master_blob')

        return output_path, approx_size
    @staticmethod
    def _b512_encode_path_stream(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            pack_flag: str = "",
            output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            *,
            input_size: "basefwx.typing.Optional[int]" = None,
            keep_input: bool = False
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        display_path = display_path or path
        output_path = output_path or path.with_suffix('.fwx')
        input_size = input_size if input_size is not None else path.stat().st_size
        if reporter:
            reporter.update(file_index, 0.05, "prepare", display_path)
        if not basefwx.ENABLE_B512_AEAD:
            raise RuntimeError("Streaming b512 encode requires AEAD mode")

        chunk_size = basefwx.STREAM_CHUNK_SIZE
        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        stream_salt = basefwx._StreamObfuscator.generate_salt()
        ext_bytes = (path.suffix or "").encode('utf-8')

        fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(input_size)
        obf_mode = "fast" if fast_obf else "yes"
        metadata_blob = basefwx._build_metadata(
            "FWX512R",
            strip_metadata,
            use_master_effective,
            mode="STREAM",
            obfuscation=obf_mode,
            pack=pack_flag or None
        )
        metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b""
        metadata_len = len(metadata_bytes)
        prefix_bytes = metadata_bytes + basefwx.META_DELIM.encode('utf-8') if metadata_blob else b""
        stream_header = bytearray()
        stream_header.extend(basefwx.STREAM_MAGIC)
        stream_header.extend(chunk_size.to_bytes(4, 'big'))
        stream_header.extend(input_size.to_bytes(8, 'big'))
        stream_header.extend(stream_salt)
        stream_header.extend(len(ext_bytes).to_bytes(2, 'big'))
        stream_header.extend(ext_bytes)
        stream_header_bytes = bytes(stream_header)
        plaintext_len = len(prefix_bytes) + len(stream_header_bytes) + input_size

        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            password,
            use_master_effective,
            mask_info=basefwx.B512_FILE_MASK_INFO,
            require_password=not use_master_effective,
            aad=b'b512file'
        )
        aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        len_user = len(user_blob)
        len_master = len(master_blob)
        estimated_payload_len = 4 + metadata_len + basefwx.AEAD_NONCE_LEN + plaintext_len + basefwx.AEAD_TAG_LEN
        estimated_total_len = 4 + len_user + 4 + len_master + 4 + estimated_payload_len
        estimated_hint = (input_size, estimated_total_len)
        if reporter:
            reporter.update(file_index, 0.12, "stream-setup", display_path, size_hint=estimated_hint)

        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-b512-stream-")
        cleanup_paths: "basefwx.typing.List[str]" = []
        processed_plain = 0

        def _seal_progress(done_plain: int) -> None:
            if not reporter:
                return
            fraction = 0.55 + 0.44 * (done_plain / plaintext_len if plaintext_len else 0.0)
            reporter.update(file_index, fraction, "seal", display_path, size_hint=estimated_hint)

        def _obf_progress(done_bytes: int, total_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.2 + 0.70 * (done_bytes / total_bytes if total_bytes else 0.0)
            reporter.update(file_index, fraction, "pb512-stream", display_path, size_hint=estimated_hint)

        result: "basefwx.typing.Optional[basefwx.typing.Tuple[basefwx.pathlib.Path, int]]" = None
        try:
            payload_len = estimated_payload_len
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as final_tmp:
                cleanup_paths.append(final_tmp.name)
                final_tmp.write(len_user.to_bytes(4, 'big'))
                final_tmp.write(user_blob)
                final_tmp.write(len_master.to_bytes(4, 'big'))
                final_tmp.write(master_blob)
                final_tmp.write(payload_len.to_bytes(4, 'big'))
                final_tmp.write(metadata_len.to_bytes(4, 'big'))
                if metadata_bytes:
                    final_tmp.write(metadata_bytes)
                nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
                final_tmp.write(nonce)
                encryptor = basefwx.Cipher(
                    basefwx.algorithms.AES(aead_key),
                    basefwx.modes.GCM(nonce)
                ).encryptor()
                if metadata_bytes:
                    encryptor.authenticate_additional_data(metadata_bytes)

                def _write_plain(data: bytes) -> None:
                    nonlocal processed_plain
                    if not data:
                        return
                    ct = encryptor.update(data)
                    if ct:
                        final_tmp.write(ct)
                    processed_plain += len(data)
                    _seal_progress(processed_plain)

                if prefix_bytes:
                    _write_plain(prefix_bytes)
                _write_plain(stream_header_bytes)
                basefwx._StreamObfuscator.encode_file(
                    path,
                    None,
                    password,
                    stream_salt,
                    chunk_size=chunk_size,
                    fast=fast_obf,
                    forward_chunk=_write_plain,
                    progress_cb=_obf_progress
                )
                tail = encryptor.finalize()
                if tail:
                    final_tmp.write(tail)
                final_tmp.write(encryptor.tag)
                final_tmp.flush()
                final_tmp_path = final_tmp.name

            actual_size = basefwx.os.path.getsize(final_tmp_path)
            actual_hint = (input_size, actual_size)
            basefwx.os.replace(final_tmp_path, output_path)
            cleanup_paths.remove(final_tmp_path)
            if strip_metadata:
                basefwx._apply_strip_attributes(output_path)
                basefwx.os.chmod(output_path, 0)
            basefwx._remove_input(path, keep_input, output_path)
            if reporter:
                reporter.update(file_index, 1.0, "done", output_path, size_hint=actual_hint)
                reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
            else:
                # Only print size info if no progress reporter (to avoid corrupting progress display)
                human = basefwx._human_readable_size(actual_size)
                if not basefwx._SILENT_MODE:
                    print(f"{output_path.name}: approx output size {human}")
            result = (output_path, actual_size)
        finally:
            for temp_path in cleanup_paths:
                try:
                    basefwx.os.remove(temp_path)
                except FileNotFoundError:
                    pass
            temp_dir.cleanup()
        basefwx._del('mask_key')
        basefwx._del('aead_key')
        basefwx._del('user_blob')
        basefwx._del('master_blob')
        if result is None:
            raise RuntimeError("Streaming b512 encode failed")
        return result
    @staticmethod
    def _aes_heavy_encode_path_stream(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            pack_flag: str = "",
            output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            *,
            input_size: "basefwx.typing.Optional[int]" = None,
            keep_input: bool = False
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        display_path = display_path or path
        output_path = output_path or path.with_suffix('.fwx')
        input_size = input_size if input_size is not None else path.stat().st_size
        if password == "":
            raise ValueError("Password required for AES heavy streaming mode")
        if reporter:
            reporter.update(file_index, 0.05, "prepare", display_path)
        chunk_size = basefwx.STREAM_CHUNK_SIZE
        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        stream_salt = basefwx._StreamObfuscator.generate_salt()
        fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(input_size)
        obf_mode = "fast" if fast_obf else "yes"
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            mode="STREAM",
            obfuscation=obf_mode,
            kdf_iters=heavy_iters,
            argon2_time_cost=heavy_argon_time,
            argon2_memory_cost=heavy_argon_mem,
            argon2_parallelism=heavy_argon_par,
            pack=pack_flag or None
        )
        metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b""
        aad = metadata_bytes if metadata_bytes else b""
        prefix_bytes = b""
        if metadata_blob:
            prefix_bytes = metadata_bytes + basefwx.META_DELIM.encode('utf-8')
        ext_bytes = (path.suffix or "").encode('utf-8')
        stream_header = bytearray()
        stream_header.extend(basefwx.STREAM_MAGIC)
        stream_header.extend(chunk_size.to_bytes(4, 'big'))
        stream_header.extend(input_size.to_bytes(8, 'big'))
        stream_header.extend(stream_salt)
        stream_header.extend(len(ext_bytes).to_bytes(2, 'big'))
        stream_header.extend(ext_bytes)
        stream_header_bytes = bytes(stream_header)
        plaintext_len = len(prefix_bytes) + len(stream_header_bytes) + input_size
        metadata_len = len(metadata_bytes)
        estimated_len = basefwx._estimate_aead_blob_size(
            plaintext_len,
            metadata_len,
            include_user=bool(password),
            include_master=use_master_effective
        )
        estimated_hint = (input_size, estimated_len)
        if reporter:
            reporter.update(file_index, 0.12, "stream-setup", display_path, size_hint=estimated_hint)
        if use_master_effective:
            kem_ciphertext, kem_shared = basefwx.ml_kem_768.encrypt(pubkey_bytes)
            master_payload = kem_ciphertext
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        else:
            master_payload = b""
            ephemeral_key = basefwx.os.urandom(32)
        user_derived_key = None
        user_salt = b""
        if password:
            user_derived_key, user_salt = basefwx._derive_user_key(
                password,
                salt=None,
                iterations=heavy_iters,
                kdf=kdf_used,
                argon2_time_cost=heavy_argon_time,
                argon2_memory_cost=heavy_argon_mem,
                argon2_parallelism=heavy_argon_par
            )
            wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
            ephemeral_enc_user = user_salt + wrapped_ephemeral
        else:
            ephemeral_enc_user = b""
        nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
        encryptor = basefwx.Cipher(
            basefwx.algorithms.AES(ephemeral_key),
            basefwx.modes.GCM(nonce)
        ).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-stream-")
        cleanup_paths: "basefwx.typing.List[str]" = []
        processed_plain = 0
        total_plain = plaintext_len
        def _aes_progress(done_plain: int, total_plain_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.55 + 0.44 * (done_plain / total_plain_bytes if total_plain_bytes else 0.0)
            reporter.update(file_index, fraction, "AES512", display_path, size_hint=estimated_hint)

        def _obf_progress(done_bytes: int, total_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.2 + 0.70 * (done_bytes / total_bytes if total_bytes else 0.0)
            reporter.update(file_index, fraction, "pb512-stream", display_path, size_hint=estimated_hint)

        try:
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as cipher_tmp:
                cleanup_paths.append(cipher_tmp.name)
                len_user = len(ephemeral_enc_user)
                len_master = len(master_payload)
                cipher_tmp.write(len_user.to_bytes(4, 'big'))
                cipher_tmp.write(ephemeral_enc_user)
                cipher_tmp.write(len_master.to_bytes(4, 'big'))
                cipher_tmp.write(master_payload)
                payload_len_pos = cipher_tmp.tell()
                cipher_tmp.write(b'\x00\x00\x00\x00')
                payload_start = cipher_tmp.tell()
                cipher_tmp.write(metadata_len.to_bytes(4, 'big'))
                if metadata_bytes:
                    cipher_tmp.write(metadata_bytes)
                cipher_tmp.write(nonce)

                def _write_plain(data: bytes) -> None:
                    nonlocal processed_plain
                    if not data:
                        return
                    ct = encryptor.update(data)
                    if ct:
                        cipher_tmp.write(ct)
                    processed_plain += len(data)
                    _aes_progress(processed_plain, total_plain)

                if prefix_bytes:
                    _write_plain(prefix_bytes)
                _write_plain(stream_header_bytes)
                basefwx._StreamObfuscator.encode_file(
                    path,
                    None,
                    password,
                    stream_salt,
                    chunk_size=chunk_size,
                    fast=fast_obf,
                    forward_chunk=_write_plain,
                    progress_cb=lambda done, total: (
                        _obf_progress(done, total)
                    )
                )
                tail = encryptor.finalize()
                if tail:
                    cipher_tmp.write(tail)
                cipher_tmp.write(encryptor.tag)
                payload_end = cipher_tmp.tell()
                payload_len = payload_end - payload_start
                cipher_tmp.seek(payload_len_pos)
                cipher_tmp.write(payload_len.to_bytes(4, 'big'))
                cipher_tmp.flush()
                cipher_tmp_path = cipher_tmp.name
            actual_size = basefwx.os.path.getsize(cipher_tmp_path)
            actual_hint = (input_size, actual_size)
            basefwx.os.replace(cipher_tmp_path, output_path)
            cleanup_paths.remove(cipher_tmp_path)
            if strip_metadata:
                basefwx._apply_strip_attributes(output_path)
                basefwx.os.chmod(output_path, 0)
            basefwx._remove_input(path, keep_input, output_path)
            if reporter:
                reporter.update(file_index, 1.0, "done", output_path, size_hint=actual_hint)
                reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
            else:
                # Only print size info if no progress reporter (to avoid corrupting progress display)
                human = basefwx._human_readable_size(actual_size)
                if not basefwx._SILENT_MODE:
                    print(f"{output_path.name}: approx output size {human}")
            return output_path, actual_size
        finally:
            basefwx._del('ephemeral_key')
            basefwx._del('user_derived_key')
            basefwx._del('kem_shared')
            for temp_path in cleanup_paths:
                try:
                    basefwx.os.remove(temp_path)
                except FileNotFoundError:
                    pass
            temp_dir.cleanup()

    @staticmethod
    def _b512_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.1, "read", path)

        metadata_blob_preview = ""
        meta_preview: "basefwx.typing.Dict[str, basefwx.typing.Any]" = {}
        if basefwx.ENABLE_B512_AEAD:
            try:
                with open(path, 'rb') as preview:
                    len_user_bytes = preview.read(4)
                    if len(len_user_bytes) == 4:
                        len_user = int.from_bytes(len_user_bytes, 'big')
                        preview.seek(len_user, basefwx.os.SEEK_CUR)
                        len_master_bytes = preview.read(4)
                        if len(len_master_bytes) == 4:
                            len_master = int.from_bytes(len_master_bytes, 'big')
                            preview.seek(len_master, basefwx.os.SEEK_CUR)
                            len_payload_bytes = preview.read(4)
                            if len(len_payload_bytes) == 4:
                                len_payload = int.from_bytes(len_payload_bytes, 'big')
                                if len_payload >= 4:
                                    metadata_len_bytes = preview.read(4)
                                    if len(metadata_len_bytes) == 4:
                                        metadata_len = int.from_bytes(metadata_len_bytes, 'big')
                                        metadata_bytes_preview = preview.read(metadata_len)
                                        try:
                                            metadata_blob_preview = metadata_bytes_preview.decode('utf-8') if metadata_bytes_preview else ""
                                        except UnicodeDecodeError:
                                            metadata_blob_preview = ""
                                        meta_preview = basefwx._decode_metadata(metadata_blob_preview)
            except Exception:
                meta_preview = {}
        if (meta_preview.get("ENC-MODE") or "").lower() == "stream":
            return basefwx._b512_decode_path_stream(
                path,
                password,
                reporter,
                file_index,
                strip_metadata,
                use_master,
                meta_preview,
                metadata_blob_preview,
                input_size=input_size
            )

        raw_bytes = path.read_bytes()

        user_blob: bytes = b""
        master_blob: bytes = b""
        ct_blob: bytes = b""
        use_master_effective = use_master and not strip_metadata
        binary_mode = False
        try:
            user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(raw_bytes, 3)
            binary_mode = True
        except ValueError:
            binary_mode = False

        if binary_mode:
            mask_key = None
            aead_key = None
            payload_bytes = None
            try:
                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    password,
                    use_master_effective,
                    mask_info=basefwx.B512_FILE_MASK_INFO,
                    aad=b'b512file'
                )
                aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
                payload_bytes = basefwx._aead_decrypt(aead_key, ct_blob, basefwx.B512_AEAD_INFO)
                content = payload_bytes.decode('utf-8')
            finally:
                basefwx._del('mask_key')
                basefwx._del('aead_key')
                basefwx._del('payload_bytes')
        else:
            content = raw_bytes.decode('utf-8')

        basefwx._del('user_blob')
        basefwx._del('master_blob')
        basefwx._del('ct_blob')

        metadata_blob, content_core = basefwx._split_metadata(content)
        meta = basefwx._decode_metadata(metadata_blob)
        master_hint = meta.get("ENC-MASTER") if meta else None
        if master_hint == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "FWX512R")

        header, payload = basefwx._split_with_delims(
            content_core,
            (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM),
            "FWX container"
        )

        if reporter:
            reporter.update(file_index, 0.35, "b256", path)

        ext = basefwx.b512decode(header, password, use_master=use_master_effective)
        data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.65, "base64", path)

        decoded_bytes = basefwx.base64.b64decode(data_b64)
        pack_flag = basefwx._pack_flag_from_meta(meta, ext)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(decoded_bytes)

        basefwx.os.remove(path)

        if pack_flag:
            target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
        elif strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(decoded_bytes)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 1.0, "done", target, size_hint=size_hint)
            reporter.finalize_file(file_index, target, size_hint=size_hint)

        basefwx._del('content')
        basefwx._del('decoded_bytes')

        return target, output_len
    @staticmethod
    def _b512_decode_path_stream(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            meta_preview: "basefwx.typing.Optional[basefwx.typing.Dict[str, basefwx.typing.Any]]" = None,
            metadata_blob_preview: str = "",
            *,
            input_size: "basefwx.typing.Optional[int]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        if not basefwx.ENABLE_B512_AEAD:
            raise RuntimeError("Streaming b512 decode requires AEAD mode")
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        input_size = input_size if input_size is not None else path.stat().st_size
        meta = meta_preview or {}
        metadata_blob = metadata_blob_preview or ""
        use_master_effective = use_master and not strip_metadata
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-b512-dec-")
        cleanup_paths: "basefwx.typing.List[str]" = []
        plaintext_path: "basefwx.typing.Optional[str]" = None
        decoded_path: "basefwx.typing.Optional[str]" = None
        chunk_size = basefwx.STREAM_CHUNK_SIZE
        try:
            with open(path, 'rb') as handle:
                len_user_bytes = handle.read(4)
                if len(len_user_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_user = int.from_bytes(len_user_bytes, 'big')
                user_blob = handle.read(len_user)
                if len(user_blob) != len_user:
                    raise ValueError("Ciphertext payload truncated")
                len_master_bytes = handle.read(4)
                if len(len_master_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_master = int.from_bytes(len_master_bytes, 'big')
                master_blob = handle.read(len_master)
                if len(master_blob) != len_master:
                    raise ValueError("Ciphertext payload truncated")
                len_payload_bytes = handle.read(4)
                if len(len_payload_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_payload = int.from_bytes(len_payload_bytes, 'big')
                if len_payload < 4 + basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN:
                    raise ValueError("Ciphertext payload truncated")
                metadata_len_bytes = handle.read(4)
                if len(metadata_len_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                metadata_len = int.from_bytes(metadata_len_bytes, 'big')
                metadata_bytes = handle.read(metadata_len)
                if len(metadata_bytes) != metadata_len:
                    raise ValueError("Ciphertext payload truncated")
                if metadata_blob:
                    if metadata_bytes != metadata_blob.encode('utf-8'):
                        raise ValueError("Metadata integrity mismatch detected")
                else:
                    try:
                        metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ""
                    except UnicodeDecodeError:
                        metadata_blob = ""
                    meta = basefwx._decode_metadata(metadata_blob)
                nonce = handle.read(basefwx.AEAD_NONCE_LEN)
                if len(nonce) != basefwx.AEAD_NONCE_LEN:
                    raise ValueError("Ciphertext payload truncated")
                cipher_body_len = len_payload - 4 - metadata_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                if cipher_body_len < 0:
                    raise ValueError("Ciphertext payload truncated")
                cipher_body_start = handle.tell()
                handle.seek(cipher_body_len, basefwx.os.SEEK_CUR)
                tag = handle.read(basefwx.AEAD_TAG_LEN)
                if len(tag) != basefwx.AEAD_TAG_LEN:
                    raise ValueError("Ciphertext payload truncated")
                handle.seek(cipher_body_start)

                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    password,
                    use_master_effective,
                    mask_info=basefwx.B512_FILE_MASK_INFO,
                    aad=b'b512file'
                )
                aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
                decryptor = basefwx.Cipher(
                    basefwx.algorithms.AES(aead_key),
                    basefwx.modes.GCM(nonce, tag)
                ).decryptor()
                if metadata_bytes:
                    decryptor.authenticate_additional_data(metadata_bytes)
                if reporter:
                    reporter.update(file_index, 0.35, "seal", path)
                with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as plain_tmp:
                    cleanup_paths.append(plain_tmp.name)
                    plaintext_path = plain_tmp.name
                    remaining = cipher_body_len
                    processed = 0
                    while remaining > 0:
                        take = min(chunk_size, remaining)
                        chunk = handle.read(take)
                        if len(chunk) != take:
                            raise ValueError("Ciphertext truncated")
                        plain_chunk = decryptor.update(chunk)
                        if plain_chunk:
                            plain_tmp.write(plain_chunk)
                        remaining -= take
                        processed += take
                        if reporter:
                            fraction = 0.35 + 0.25 * (processed / cipher_body_len if cipher_body_len else 1.0)
                            reporter.update(file_index, fraction, "seal", path)
                    final_chunk = decryptor.finalize()
                    if final_chunk:
                        plain_tmp.write(final_chunk)

            basefwx._del('mask_key')
            basefwx._del('aead_key')
            basefwx._del('user_blob')
            basefwx._del('master_blob')

            if plaintext_path is None:
                raise RuntimeError("Streaming b512 decode failed to produce plaintext")

            with open(plaintext_path, 'rb') as plain_handle:
                if metadata_bytes:
                    expected_prefix = metadata_bytes
                    prefix = plain_handle.read(len(expected_prefix))
                    if prefix != expected_prefix:
                        raise ValueError("Metadata integrity mismatch detected")
                    delim_bytes = basefwx.META_DELIM.encode('utf-8')
                    delim = plain_handle.read(len(delim_bytes))
                    if delim != delim_bytes:
                        raise ValueError("Malformed streaming payload: missing metadata delimiter")
                stream_magic = plain_handle.read(len(basefwx.STREAM_MAGIC))
                if stream_magic != basefwx.STREAM_MAGIC:
                    raise ValueError("Malformed streaming payload: magic mismatch")
                chunk_size_bytes = plain_handle.read(4)
                if len(chunk_size_bytes) != 4:
                    raise ValueError("Malformed streaming payload: missing chunk size")
                chunk_size_value = int.from_bytes(chunk_size_bytes, 'big')
                if chunk_size_value <= 0 or chunk_size_value > (16 << 20):
                    chunk_size_value = basefwx.STREAM_CHUNK_SIZE
                original_size_bytes = plain_handle.read(8)
                if len(original_size_bytes) != 8:
                    raise ValueError("Malformed streaming payload: missing original size")
                original_size = int.from_bytes(original_size_bytes, 'big')
                stream_salt = plain_handle.read(basefwx._StreamObfuscator._SALT_LEN)
                if len(stream_salt) != basefwx._StreamObfuscator._SALT_LEN:
                    raise ValueError("Malformed streaming payload: missing salt")
                ext_len_bytes = plain_handle.read(2)
                if len(ext_len_bytes) != 2:
                    raise ValueError("Malformed streaming payload: missing extension length")
                ext_len = int.from_bytes(ext_len_bytes, 'big')
                ext_bytes = plain_handle.read(ext_len)
                if len(ext_bytes) != ext_len:
                    raise ValueError("Malformed streaming payload: truncated extension")

                if not password and not use_master_effective:
                    raise ValueError("Password required for streaming b512 decode")

                obf_hint = (meta.get("ENC-OBF") or "yes").lower()
                fast_obf = obf_hint == "fast"
                decoder = basefwx._StreamObfuscator.for_password(password, stream_salt, fast=fast_obf)
                with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as clear_tmp:
                    cleanup_paths.append(clear_tmp.name)
                    decoded_path = clear_tmp.name
                    processed = 0
                    while processed < original_size:
                        to_read = min(chunk_size_value, original_size - processed)
                        chunk = plain_handle.read(to_read)
                        if len(chunk) != to_read:
                            raise ValueError("Streaming payload truncated")
                        plain_chunk = decoder.decode_chunk(chunk)
                        clear_tmp.write(plain_chunk)
                        processed += len(plain_chunk)
                        if reporter:
                            fraction = 0.7 + 0.2 * (processed / original_size if original_size else 1.0)
                            reporter.update(file_index, fraction, "deobfuscate", path)
                    leftover = plain_handle.read(1)
                    if leftover:
                        raise ValueError("Streaming payload contained unexpected trailing data")

            target = path.with_suffix('')
            ext_text = ""
            if ext_bytes:
                try:
                    ext_text = ext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    ext_text = ""
                if ext_text:
                    target = target.with_suffix(ext_text)
            pack_flag = basefwx._pack_flag_from_meta(meta, ext_text)

            if decoded_path is None:
                raise RuntimeError("Missing decoded payload")
            basefwx.os.replace(decoded_path, target)
            cleanup_paths.remove(decoded_path)
            basefwx.os.remove(path)
            if plaintext_path and plaintext_path in cleanup_paths:
                basefwx.os.remove(plaintext_path)
                cleanup_paths.remove(plaintext_path)
            if pack_flag:
                target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
            elif strip_metadata:
                basefwx._apply_strip_attributes(target)
            output_len = original_size
            size_hint = (input_size, output_len)
            if reporter:
                reporter.update(file_index, 1.0, "done", target, size_hint=size_hint)
                reporter.finalize_file(file_index, target, size_hint=size_hint)
            return target, output_len
        finally:
            for temp_path in cleanup_paths:
                try:
                    basefwx.os.remove(temp_path)
                except FileNotFoundError:
                    pass
            temp_dir.cleanup()

    @staticmethod
    def b512file_encode(
        file: str,
        code: str,
        strip_metadata: bool = False,
        use_master: bool = True,
        keep_input: bool = False
    ):
        try:
            pubkey_bytes, master_available = basefwx._resolve_master_usage(
                use_master and not strip_metadata,
                None,
                create_if_missing=True
            )
            effective_use_master = (use_master and not strip_metadata) and master_available
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_encode_path(
                path,
                password,
                strip_metadata=strip_metadata,
                use_master=effective_use_master,
                master_pubkey=pubkey_bytes,
                keep_input=keep_input
            )
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to encode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def b512file(
            files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]",
            password: str,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            silent: bool = False,
            compress: bool = False,
            keep_input: bool = False
    ):
        paths = basefwx._coerce_file_list(files)
        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        encode_use_master = (use_master and not strip_metadata) and master_available
        decode_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=encode_use_master)
        except Exception as exc:
            if not silent:
                print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        previous_silent = basefwx._SILENT_MODE
        basefwx._SILENT_MODE = silent
        try:
            reporter = basefwx._ProgressReporter(len(paths)) if not silent else None
            results: dict[str, str] = {}

            def _process_with_reporter(idx: int, path: "basefwx.pathlib.Path") -> tuple[str, str]:
                try:
                    if not path.exists():
                        if reporter:
                            reporter.update(idx, 0.0, "missing", path)
                            reporter.finalize_file(idx, path)
                        return str(path), "FAIL!"
                    if path.suffix.lower() == ".fwx" and path.is_file():
                        basefwx._b512_decode_path(
                            path,
                            resolved_password,
                            reporter,
                            idx,
                            len(paths),
                            strip_metadata,
                            decode_use_master
                        )
                    else:
                        pack_ctx = basefwx._pack_input_to_archive(path, compress, reporter, idx)
                        pack_flag = pack_ctx[1] if pack_ctx else ""
                        pack_temp = pack_ctx[2] if pack_ctx else None
                        source_path = pack_ctx[0] if pack_ctx else path
                        try:
                            basefwx._b512_encode_path(
                                source_path,
                                resolved_password,
                                reporter,
                                idx,
                                len(paths),
                                strip_metadata,
                                encode_use_master,
                                pubkey_bytes,
                                pack_flag=pack_flag,
                                output_path=path.with_suffix('.fwx'),
                                display_path=path,
                                keep_input=keep_input
                            )
                            if pack_ctx:
                                basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                        finally:
                            if pack_temp is not None:
                                pack_temp.cleanup()
                    return str(path), "SUCCESS!"
                except Exception as exc:
                    if reporter:
                        reporter.update(idx, 0.0, f"error: {exc}", path)
                        reporter.finalize_file(idx, path)
                    return str(path), "FAIL!"

            def _process_without_reporter(path: "basefwx.pathlib.Path") -> tuple[str, str]:
                try:
                    if not path.exists():
                        return str(path), "FAIL!"
                    if path.suffix.lower() == ".fwx" and path.is_file():
                        basefwx._b512_decode_path(
                            path,
                            resolved_password,
                            None,
                            0,
                            len(paths),
                            strip_metadata,
                            decode_use_master
                        )
                    else:
                        pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
                        pack_flag = pack_ctx[1] if pack_ctx else ""
                        pack_temp = pack_ctx[2] if pack_ctx else None
                        source_path = pack_ctx[0] if pack_ctx else path
                        try:
                            basefwx._b512_encode_path(
                                source_path,
                                resolved_password,
                                None,
                                0,
                                len(paths),
                                strip_metadata,
                                encode_use_master,
                                pubkey_bytes,
                                pack_flag=pack_flag,
                                output_path=path.with_suffix('.fwx'),
                                display_path=path,
                                keep_input=keep_input
                            )
                            if pack_ctx:
                                basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                        finally:
                            if pack_temp is not None:
                                pack_temp.cleanup()
                    return str(path), "SUCCESS!"
                except Exception:
                    return str(path), "FAIL!"

            use_parallel = len(paths) > 1 and basefwx._CPU_COUNT > 1
            if use_parallel:
                max_workers = min(len(paths), basefwx._CPU_COUNT)
                if reporter:
                    items = list(enumerate(paths))

                    def _dispatch(item: "tuple[int, basefwx.pathlib.Path]") -> tuple[str, str]:
                        idx, path = item
                        return _process_with_reporter(idx, path)

                    with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        for file_id, status in executor.map(_dispatch, items):
                            results[file_id] = status
                else:
                    with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        for file_id, status in executor.map(_process_without_reporter, paths):
                            results[file_id] = status
            else:
                for idx, path in enumerate(paths):
                    file_id, status = _process_with_reporter(idx, path)
                    results[file_id] = status

            # Reset the terminal state before returning results
            if reporter:
                reporter.reset_terminal_state()
                
            if len(paths) == 1:
                final_result = next(iter(results.values()))
            else:
                final_result = results
        finally:
            basefwx._SILENT_MODE = previous_silent

        return final_result

    class ImageCipher:
        """Deterministic image cipher that keeps data inside regular image formats."""

        @staticmethod
        def _default_encrypted_path(path: "basefwx.pathlib.Path") -> "basefwx.pathlib.Path":
            return path

        @staticmethod
        def _default_decrypted_path(path: "basefwx.pathlib.Path") -> "basefwx.pathlib.Path":
            return path

        @staticmethod
        def _load_image(path: "basefwx.pathlib.Path", data: bytes | None = None) -> "basefwx.typing.Tuple[basefwx.np.ndarray, str, str]":
            basefwx._require_pil()
            stream = basefwx.BytesIO(data) if data is not None else None
            with basefwx.Image.open(stream or path) as img:
                format_name = img.format or path.suffix.lstrip('.').upper()
                bands = len(img.getbands())
                if bands == 1:
                    work_mode = 'L'
                elif bands >= 4:
                    work_mode = 'RGBA'
                else:
                    work_mode = 'RGB'
                work_img = img.convert(work_mode)
                arr = basefwx.np.array(work_img, dtype=basefwx.np.uint8, copy=True)
            return arr, work_mode, format_name

        @staticmethod
        def _image_primitives(
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            num_pixels: int,
            channels: int,
            material: bytes | None = None
        ) -> "basefwx.typing.Tuple[basefwx.np.ndarray, basefwx.typing.Optional[basefwx.np.ndarray], basefwx.np.ndarray, bytes]":
            if material is None:
                if not password:
                    raise ValueError('Password is required for image encryption')
                material = basefwx._derive_key_material(
                    password,
                    basefwx.IMAGECIPHER_STREAM_INFO,
                    length=64,
                    iterations=max(200_000, basefwx.USER_KDF_ITERATIONS)
                )
            aes_key = material[:32]
            nonce = material[32:48]
            seed_bytes = material[48:]
            seed = int.from_bytes(seed_bytes, 'big') or 1
            cipher = basefwx.Cipher(basefwx.algorithms.AES(aes_key), basefwx.modes.CTR(nonce))
            encryptor = cipher.encryptor()
            total = num_pixels * channels
            mask_bytes = encryptor.update(bytes(total)) + encryptor.finalize()
            mask = basefwx.np.frombuffer(mask_bytes, dtype=basefwx.np.uint8).reshape(num_pixels, channels).copy()
            rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed))
            rotations = None
            if channels > 1:
                rotations = rng.integers(0, channels, size=num_pixels, dtype=basefwx.np.uint8)
            perm = rng.permutation(num_pixels)
            return mask, rotations, perm, material

        @staticmethod
        def encrypt_image_inv(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None,
            *,
            include_trailer: bool = True,
            archive_original: bool = True
        ) -> str:
            path_obj = basefwx.pathlib.Path(path)
            basefwx._ensure_existing_file(path_obj)
            password = basefwx._resolve_password(password, use_master=True)
            if not include_trailer:
                if basefwx.os.getenv("BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION") != "1":
                    raise ValueError(
                        "Image encryption without trailer is deterministic and insecure; "
                        "set BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION=1 to allow or enable trailer"
                    )
                if not password:
                    raise ValueError("Password is required for image encryption without trailer")
            output_path = basefwx.pathlib.Path(output) if output else basefwx.ImageCipher._default_encrypted_path(path_obj)
            original_bytes = path_obj.read_bytes()
            arr, mode, fmt = basefwx.ImageCipher._load_image(path_obj, original_bytes)
            shape = arr.shape
            if arr.ndim == 2:
                channels = 1
                flat = arr.reshape(-1, 1).astype(basefwx.np.uint8, copy=True)
            else:
                channels = shape[2]
                flat = arr.reshape(-1, channels).astype(basefwx.np.uint8, copy=True)
            num_pixels = flat.shape[0]
            material_override = None
            archive_key = None
            trailer_header = b""
            if include_trailer:
                _, archive_key, material_override, trailer_header = basefwx._jmg_prepare_keys(
                    password,
                    use_master=True,
                    security_profile=basefwx.JMG_SECURITY_PROFILE_MAX
                )
            mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(
                password,
                num_pixels,
                channels,
                material=material_override
            )
            basefwx.np.bitwise_xor(flat, mask, out=flat)
            if rotations is not None:
                rows = basefwx.np.arange(num_pixels, dtype=basefwx.np.intp)[:, None]
                base_idx = basefwx.np.arange(channels, dtype=basefwx.np.intp)
                idx = (base_idx + rotations[:, None]) % channels
                flat = flat[rows, idx]
            flat = flat.take(perm, axis=0)
            scrambled = flat.reshape(shape)
            image = basefwx.Image.fromarray(scrambled.astype(basefwx.np.uint8), mode)
            save_kwargs: dict[str, basefwx.typing.Any] = {}
            if fmt:
                save_kwargs['format'] = fmt
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = output_path.with_name(f"{output_path.stem}._tmp{output_path.suffix}")
            image.save(temp_path, **save_kwargs)
            image.close()
            basefwx.os.replace(temp_path, output_path)
            if include_trailer:
                if archive_original:
                    archive_blob = basefwx._aead_encrypt(
                        archive_key,
                        original_bytes,
                        basefwx._jmg_archive_info_for_profile(basefwx.JMG_SECURITY_PROFILE_MAX),
                    )
                    trailer_blob = trailer_header + archive_blob
                    basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_TRAILER_MAGIC, trailer_blob)
                else:
                    basefwx._append_balanced_trailer(
                        output_path,
                        basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC,
                        trailer_header
                    )

            basefwx._del('mask')
            basefwx._del('rotations')
            basefwx._del('perm')
            basefwx._del('flat')
            basefwx._del('arr')
            basefwx._del('material')
            basefwx._del('archive_key')
            basefwx._del('archive_blob')
            basefwx._del('trailer_header')
            basefwx._del('material_override')
            basefwx._del('original_bytes')
            print(f"🔥 Encrypted image → {output_path}")
            return str(output_path)

        @staticmethod
        def decrypt_image_inv(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None
        ) -> str:
            path_obj = basefwx.pathlib.Path(path)
            basefwx._ensure_existing_file(path_obj)
            password = basefwx._resolve_password(password, use_master=True)
            output_path = basefwx.pathlib.Path(output) if output else basefwx.ImageCipher._default_decrypted_path(path_obj)
            file_bytes = path_obj.read_bytes()
            orig_blob = None
            key_blob = None
            payload_bytes = file_bytes
            trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_TRAILER_MAGIC)
            if trailer is not None:
                orig_blob, payload_bytes = trailer
            else:
                key_trailer = basefwx._extract_balanced_trailer_from_bytes(
                    file_bytes,
                    basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC
                )
                if key_trailer is not None:
                    key_blob, payload_bytes = key_trailer
            arr, mode, fmt = basefwx.ImageCipher._load_image(path_obj, payload_bytes)
            shape = arr.shape
            if arr.ndim == 2:
                channels = 1
                flat = arr.reshape(-1, 1).astype(basefwx.np.uint8, copy=True)
            else:
                channels = shape[2]
                flat = arr.reshape(-1, channels).astype(basefwx.np.uint8, copy=True)
            num_pixels = flat.shape[0]
            material_override = None
            if orig_blob is not None:
                header = basefwx._jmg_parse_key_header(orig_blob, password, use_master=True)
                if header is not None:
                    header_len, _, archive_key, material_override, profile_id = header
                    archive_blob = orig_blob[header_len:]
                    archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
                else:
                    if not password:
                        raise ValueError("Password required for legacy image trailer decryption")
                    material_legacy = basefwx._derive_key_material(
                        password,
                        basefwx.IMAGECIPHER_STREAM_INFO,
                        length=64,
                        iterations=max(200_000, basefwx.USER_KDF_ITERATIONS)
                    )
                    archive_key = basefwx._hkdf_sha256(material_legacy, info=basefwx.IMAGECIPHER_ARCHIVE_INFO)
                    archive_blob = orig_blob
                    archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
                try:
                    original_bytes = basefwx._aead_decrypt(archive_key, archive_blob, archive_info)
                    output_path.write_bytes(original_bytes)
                    basefwx._del('mask')
                    basefwx._del('rotations')
                    basefwx._del('perm')
                    basefwx._del('flat')
                    basefwx._del('arr')
                    basefwx._del('archive_key')
                    basefwx._del('archive_blob')
                    basefwx._del('material_legacy')
                    print(f"✅ Decrypted image → {output_path}")
                    return str(output_path)
                except Exception:
                    pass
            if key_blob is not None:
                header = basefwx._jmg_parse_key_header(key_blob, password, use_master=True)
                if header is None:
                    raise ValueError("Invalid JMG key trailer")
                header_len, _, _, material_override, _ = header
                if header_len != len(key_blob):
                    raise ValueError("Invalid JMG key trailer payload")
                _warnings_module.warn(
                    "jMG no-archive payload detected; restored media may not be byte-identical "
                    "to the original input.",
                    UserWarning
                )
            mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(
                password,
                num_pixels,
                channels,
                material=material_override
            )
            inv_perm = basefwx.np.empty_like(perm)
            inv_perm[perm] = basefwx.np.arange(num_pixels, dtype=perm.dtype)
            flat = flat.take(inv_perm, axis=0)
            if rotations is not None:
                rows = basefwx.np.arange(num_pixels, dtype=basefwx.np.intp)[:, None]
                base_idx = basefwx.np.arange(channels, dtype=basefwx.np.intp)
                idx = (base_idx - rotations[:, None]) % channels
                flat = flat[rows, idx]
            basefwx.np.bitwise_xor(flat, mask, out=flat)
            recovered = flat.reshape(shape)
            image = basefwx.Image.fromarray(recovered.astype(basefwx.np.uint8), mode)
            save_kwargs: dict[str, basefwx.typing.Any] = {}
            if fmt:
                save_kwargs['format'] = fmt
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = output_path.with_name(f"{output_path.stem}._tmp{output_path.suffix}")
            image.save(temp_path, **save_kwargs)
            image.close()
            basefwx.os.replace(temp_path, output_path)
            basefwx._del('mask')
            basefwx._del('rotations')
            basefwx._del('perm')
            basefwx._del('flat')
            basefwx._del('arr')
            basefwx._del('material')
            basefwx._del('archive_key')
            print(f"✅ Decrypted image → {output_path}")
            return str(output_path)

    class MediaCipher:
        """Media cipher for images/videos/audio with deterministic shuffling + AES-CTR masking."""

        VIDEO_GROUP_SECONDS = 1.0
        VIDEO_GROUP_MAX_FRAMES = 12
        VIDEO_BLOCK_SIZE = 2
        VIDEO_MASK_BITS = 6
        VIDEO_MASK_BITS_MAX = 8
        AUDIO_BLOCK_SECONDS = 0.15
        AUDIO_GROUP_SECONDS = 1.0
        AUDIO_MASK_BITS = 13
        AUDIO_MASK_BITS_MAX = 16
        DEFAULT_SECURITY_PROFILE = 1
        JMG_TARGET_GROWTH = 1.1
        JMG_MAX_GROWTH = 2.0
        JMG_MIN_AUDIO_BPS = 64_000
        JMG_MIN_VIDEO_BPS = 200_000
        TRAILER_FALLBACK_MAX = 64 * 1024 * 1024
        WORKSPACE_RESERVE_BYTES = 64 * 1024 * 1024

        IMAGE_EXTS = {
            ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".gif", ".webp",
            ".tif", ".tiff", ".heic", ".heif", ".avif", ".ico"
        }
        VIDEO_EXTS = {
            ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".flv", ".wmv",
            ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".m2ts"
        }
        AUDIO_EXTS = {
            ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac"
        }
        HWACCEL_ENV = "BASEFWX_HWACCEL"
        HWACCEL_STRICT_ENV = "BASEFWX_HWACCEL_STRICT"
        GPU_PIXELS_ENV = "BASEFWX_GPU_PIXELS"
        GPU_PIXELS_MIN_BYTES_ENV = "BASEFWX_GPU_PIXELS_MIN_BYTES"
        GPU_PIXELS_MIN_BYTES_DEFAULT = 1_000_000
        GPU_PIXELS_AUTO_MIN_BYTES = 8 * 1024 * 1024
        _HWACCEL_CACHE: "basefwx.typing.Optional[str]" = None
        _HWACCEL_READY = False
        _HWACCEL_ENV_CACHE: "basefwx.typing.Optional[str]" = None
        _ENCODER_CACHE: "basefwx.typing.Optional[set[str]]" = None
        _HWACCELS_CACHE: "basefwx.typing.Optional[set[str]]" = None
        _CUDA_RUNTIME_READY: "basefwx.typing.Optional[bool]" = None
        _CUDA_RUNTIME_ERROR: str = ""
        _CUDA_RUNTIME_ENV_CACHE: "basefwx.typing.Optional[str]" = None

        @staticmethod
        def _ensure_ffmpeg() -> None:
            if basefwx.shutil.which("ffmpeg") and basefwx.shutil.which("ffprobe"):
                return
            raise RuntimeError("ffmpeg/ffprobe are required for audio/video processing")

        @staticmethod
        def _ffmpeg_encoder_set() -> "set[str]":
            cached = basefwx.MediaCipher._ENCODER_CACHE
            if cached is not None:
                return cached
            encoders: set[str] = set()
            try:
                result = basefwx.subprocess.run(
                    ["ffmpeg", "-hide_banner", "-encoders"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in (result.stdout or "").splitlines():
                        line = line.strip()
                        if not line or line.startswith("--"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            encoders.add(parts[1])
            except Exception:
                encoders = set()
            basefwx.MediaCipher._ENCODER_CACHE = encoders
            return encoders

        @staticmethod
        def _ffmpeg_hwaccel_set() -> "set[str]":
            cached = basefwx.MediaCipher._HWACCELS_CACHE
            if cached is not None:
                return cached
            hwaccels: set[str] = set()
            try:
                result = basefwx.subprocess.run(
                    ["ffmpeg", "-hide_banner", "-hwaccels"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in (result.stdout or "").splitlines():
                        line = line.strip().lower()
                        if not line or line.startswith("hardware acceleration methods"):
                            continue
                        hwaccels.add(line)
            except Exception:
                hwaccels = set()
            basefwx.MediaCipher._HWACCELS_CACHE = hwaccels
            return hwaccels

        @staticmethod
        def _cuda_runtime_env_key() -> str:
            return (
                f"CUDA_PATH={basefwx.os.getenv('CUDA_PATH', '')}|"
                f"LD_LIBRARY_PATH={basefwx.os.getenv('LD_LIBRARY_PATH', '')}"
            )

        @classmethod
        def _set_cuda_runtime_state(cls, ready: bool, error: str) -> None:
            cls._CUDA_RUNTIME_READY = ready
            cls._CUDA_RUNTIME_ERROR = error

        @staticmethod
        def _format_cuda_error(exc: Exception) -> str:
            msg = str(exc).strip().replace("\n", " ")
            if len(msg) > 220:
                msg = msg[:220] + "..."
            if "cudaErrorInsufficientDriver" in msg:
                msg += " (driver/runtime mismatch; install a CuPy build matching your NVIDIA driver/CUDA runtime)"
            if "cuda_fp16.h" in msg:
                msg = (
                    "CUDA headers missing for CuPy JIT (cuda_fp16.h not found). "
                    "Set CUDA_PATH to your toolkit root (for example /usr or /usr/local/cuda) "
                    "and ensure include/cuda_fp16.h is present."
                )
            return msg or exc.__class__.__name__

        @classmethod
        def _cuda_runtime_status(cls) -> "tuple[bool, str]":
            env_key = cls._cuda_runtime_env_key()
            if cls._CUDA_RUNTIME_ENV_CACHE == env_key and cls._CUDA_RUNTIME_READY is not None:
                return bool(cls._CUDA_RUNTIME_READY), cls._CUDA_RUNTIME_ERROR
            cls._CUDA_RUNTIME_ENV_CACHE = env_key
            if basefwx.cp is None:
                cls._set_cuda_runtime_state(False, "CuPy is unavailable")
                return False, cls._CUDA_RUNTIME_ERROR
            try:
                count = int(basefwx.cp.cuda.runtime.getDeviceCount())
            except Exception as exc:
                cls._set_cuda_runtime_state(False, cls._format_cuda_error(exc))
                return False, cls._CUDA_RUNTIME_ERROR
            if count <= 0:
                cls._set_cuda_runtime_state(False, "CUDA runtime reports no available devices")
                return False, cls._CUDA_RUNTIME_ERROR
            try:
                # Probe one tiny ufunc so we fail early on incomplete CUDA toolkit/header setups.
                probe = basefwx.cp.asarray([1], dtype=basefwx.cp.uint8)
                probe ^= basefwx.cp.asarray([1], dtype=basefwx.cp.uint8)
                _ = probe.get()
            except Exception as exc:
                cls._set_cuda_runtime_state(False, cls._format_cuda_error(exc))
                return False, cls._CUDA_RUNTIME_ERROR
            cls._set_cuda_runtime_state(True, "")
            return True, ""

        @staticmethod
        def _hwaccel_strict() -> bool:
            raw = basefwx.os.getenv(basefwx.MediaCipher.HWACCEL_STRICT_ENV, "").strip().lower()
            return raw in {"1", "true", "yes", "on"}

        @staticmethod
        def _has_nvidia_hint() -> bool:
            if basefwx.shutil.which("nvidia-smi") is None:
                return False
            try:
                result = basefwx.subprocess.run(
                    ["nvidia-smi", "-L"],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0 and bool((result.stdout or "").strip())
            except Exception:
                return False

        @staticmethod
        def _has_qsv_hint() -> bool:
            if basefwx.sys.platform.startswith("linux"):
                return basefwx.os.path.exists("/dev/dri/renderD128")
            if basefwx.sys.platform.startswith("win"):
                return True
            return True

        @staticmethod
        def _has_vaapi_hint() -> bool:
            device = basefwx.os.getenv("BASEFWX_VAAPI_DEVICE", "/dev/dri/renderD128")
            return basefwx.os.path.exists(device)

        @classmethod
        def _select_hwaccel(
            cls,
            reasons: "basefwx.typing.Optional[list[str]]" = None
        ) -> "basefwx.typing.Optional[str]":
            raw = basefwx.os.getenv(cls.HWACCEL_ENV, "auto").strip().lower()
            strict = cls._hwaccel_strict()
            vaapi_device = basefwx.os.getenv("BASEFWX_VAAPI_DEVICE", "/dev/dri/renderD128")
            cache_key = f"{raw}|strict={1 if strict else 0}|vaapi={vaapi_device}"
            if cls._HWACCEL_READY and cache_key == (cls._HWACCEL_ENV_CACHE or ""):
                if reasons is not None:
                    cached = cls._HWACCEL_CACHE or "cpu"
                    reasons.append(f"cached selection reused ({cached})")
                return cls._HWACCEL_CACHE
            cls._HWACCEL_READY = True
            cls._HWACCEL_ENV_CACHE = cache_key
            if raw in {"0", "off", "false", "no"}:
                if reasons is not None:
                    reasons.append(f"{cls.HWACCEL_ENV} requested CPU-only mode")
                cls._HWACCEL_CACHE = None
                return None
            if raw in {"1", "true", "yes", ""}:
                raw = "auto"
            encoders = cls._ffmpeg_encoder_set()
            hwaccels = cls._ffmpeg_hwaccel_set()

            def _available(mode: str) -> bool:
                if mode == "nvenc":
                    return (
                        "h264_nvenc" in encoders
                        and "cuda" in hwaccels
                        and cls._has_nvidia_hint()
                    )
                if mode == "qsv":
                    return (
                        "h264_qsv" in encoders
                        and "qsv" in hwaccels
                        and cls._has_qsv_hint()
                    )
                if mode == "vaapi":
                    return (
                        "h264_vaapi" in encoders
                        and "vaapi" in hwaccels
                        and cls._has_vaapi_hint()
                    )
                return False

            prefer = None
            if raw in {"cuda", "nvenc", "nvidia"}:
                prefer = "nvenc"
            elif raw in {"qsv", "intel"}:
                prefer = "qsv"
            elif raw in {"vaapi"}:
                prefer = "vaapi"
            elif raw in {"cpu"}:
                if reasons is not None:
                    reasons.append(f"{cls.HWACCEL_ENV}=cpu forces CPU-only encode/decode")
                prefer = None
            elif raw != "auto":
                if reasons is not None:
                    reasons.append(f"unrecognized {cls.HWACCEL_ENV} value '{raw}', falling back to auto")
                raw = "auto"

            if prefer:
                if _available(prefer):
                    if reasons is not None:
                        reasons.append(f"{cls.HWACCEL_ENV} explicitly requested {prefer}")
                    cls._HWACCEL_CACHE = prefer
                    return prefer
                cls._HWACCEL_CACHE = None
                if reasons is not None:
                    reasons.append(f"{cls.HWACCEL_ENV} requested {prefer} but it is unavailable")
                if strict:
                    raise RuntimeError(
                        f"{cls.HWACCEL_ENV}={prefer} requested but unavailable; "
                        "set BASEFWX_HWACCEL=auto or disable strict mode"
                    )
                if reasons is not None:
                    reasons.append("strict mode disabled, falling back to CPU")
                return None
            if raw == "auto":
                if _available("nvenc"):
                    if reasons is not None:
                        reasons.append("auto selected nvenc (NVIDIA preferred)")
                    cls._HWACCEL_CACHE = "nvenc"
                    return "nvenc"
                if _available("qsv"):
                    if reasons is not None:
                        reasons.append("auto selected qsv (Intel fallback)")
                    cls._HWACCEL_CACHE = "qsv"
                    return "qsv"
                if _available("vaapi"):
                    if reasons is not None:
                        reasons.append("auto selected vaapi (generic GPU fallback)")
                    cls._HWACCEL_CACHE = "vaapi"
                    return "vaapi"
                if reasons is not None:
                    reasons.append("auto could not find usable GPU acceleration")
            cls._HWACCEL_CACHE = None
            return None

        @staticmethod
        def _ffmpeg_video_decode_args(
            hwaccel: "basefwx.typing.Optional[str]"
        ) -> "list[str]":
            if hwaccel == "nvenc":
                return ["-hwaccel", "cuda", "-hwaccel_output_format", "cuda"]
            if hwaccel == "qsv":
                return ["-hwaccel", "qsv"]
            if hwaccel == "vaapi":
                device = basefwx.os.getenv("BASEFWX_VAAPI_DEVICE", "/dev/dri/renderD128")
                return ["-hwaccel", "vaapi", "-hwaccel_device", device]
            return []

        @staticmethod
        def _detect_aes_accel_state() -> str:
            # Detection is informational only: crypto stays on CPU regardless.
            try:
                if basefwx.sys.platform.startswith("linux"):
                    with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as handle:
                        data = handle.read().lower()
                    return "aesni" if " aes " in f" {data.replace(chr(10), ' ')} " else "unknown"
                if basefwx.sys.platform == "darwin":
                    cmd = ["sysctl", "-n", "machdep.cpu.features"]
                    result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
                    features = (result.stdout or "").upper()
                    if "AES" in features:
                        return "aesni"
                    cmd = ["sysctl", "-n", "machdep.cpu.leaf7_features"]
                    result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
                    if "AES" in (result.stdout or "").upper():
                        return "aesni"
                    return "unknown"
                if basefwx.sys.platform.startswith("win"):
                    return "unknown"
            except Exception:
                return "unknown"
            return "unknown"

        @classmethod
        def _gpu_pixels_policy(cls) -> "tuple[str, int]":
            mode = basefwx.os.getenv(cls.GPU_PIXELS_ENV, "auto").strip().lower()
            if mode in {"", "1", "true", "yes", "on"}:
                mode = "auto"
            elif mode in {"0", "off", "false", "no"}:
                mode = "cpu"
            elif mode not in {"auto", "cuda", "cpu"}:
                mode = "auto"
            raw_min = basefwx.os.getenv(cls.GPU_PIXELS_MIN_BYTES_ENV, "").strip()
            min_bytes = cls.GPU_PIXELS_MIN_BYTES_DEFAULT
            if raw_min:
                try:
                    min_bytes = max(1, int(raw_min))
                except Exception:
                    min_bytes = cls.GPU_PIXELS_MIN_BYTES_DEFAULT
            return mode, min_bytes

        @classmethod
        def _build_hw_execution_plan(
            cls,
            op_name: str,
            *,
            stream_type: str = "bytes",
            frame_bytes: int = 0,
            allow_pixel_gpu: bool = False,
            prefer_cpu_decode: bool = True,
        ) -> "dict[str, basefwx.typing.Any]":
            reasons: "list[str]" = []
            selected_accel: "basefwx.typing.Optional[str]" = None
            if stream_type in {"video", "live"}:
                selected_accel = cls._select_hwaccel(reasons=reasons)
            else:
                reasons.append("non-video pipeline uses CPU-only media path")
            encode_device = selected_accel or "cpu"
            decode_device = "cpu" if prefer_cpu_decode else encode_device
            pixel_backend = "cpu"
            gpu_pixels_strict = False
            pixel_workers = cls._media_workers()
            gpu_pixels_mode = "cpu"
            if allow_pixel_gpu:
                mode, min_bytes = cls._gpu_pixels_policy()
                gpu_pixels_mode = mode
                if mode == "cuda":
                    min_bytes = 0
                if mode == "cpu":
                    reasons.append(f"{cls.GPU_PIXELS_ENV}=cpu forces CPU pixel transforms")
                elif selected_accel != "nvenc":
                    reasons.append("CUDA pixel path disabled because NVIDIA backend is unavailable")
                    if mode == "cuda" and cls._hwaccel_strict():
                        raise RuntimeError(
                            "BASEFWX_GPU_PIXELS=cuda requested but NVIDIA/CUDA hwaccel is unavailable"
                        )
                elif mode == "auto" and frame_bytes < max(min_bytes, cls.GPU_PIXELS_AUTO_MIN_BYTES):
                    reasons.append(
                        "CUDA pixel path skipped in auto mode "
                        f"(frame={frame_bytes}B below auto threshold={max(min_bytes, cls.GPU_PIXELS_AUTO_MIN_BYTES)}B)"
                    )
                elif frame_bytes < min_bytes:
                    reasons.append(
                        f"CUDA pixel path skipped (frame={frame_bytes}B < threshold={min_bytes}B)"
                    )
                else:
                    cuda_ready, cuda_error = cls._cuda_runtime_status()
                    if not cuda_ready:
                        reasons.append(f"CUDA pixel path skipped because {cuda_error}")
                        if mode == "cuda" and cls._hwaccel_strict():
                            raise RuntimeError(
                                "BASEFWX_GPU_PIXELS=cuda requested but CUDA runtime is unavailable: "
                                f"{cuda_error}"
                            )
                    else:
                        pixel_backend = "cuda"
                        if pixel_workers > 1:
                            # One GPU context with many Python worker threads usually hurts throughput
                            # and makes Ctrl+C shutdown noisy; pin CUDA masking to one worker.
                            pixel_workers = 1
                            reasons.append("CUDA pixel path forces single worker to avoid GPU thread contention")
                        reasons.append("CUDA pixel path enabled for large-frame masking")
                if mode == "cuda" and cls._hwaccel_strict() and pixel_backend != "cuda":
                    # Keep strict behavior explicit when forced CUDA could not be enabled.
                    raise RuntimeError(
                        "BASEFWX_GPU_PIXELS=cuda requested but CUDA pixel backend could not be enabled"
                    )
                gpu_pixels_strict = bool(mode == "cuda" and cls._hwaccel_strict())
            if prefer_cpu_decode and selected_accel and stream_type == "video":
                reasons.append("decode pinned to CPU to avoid hwdownload for CPU-side transforms")
            aes_accel_state = cls._detect_aes_accel_state()
            reasons.append("AES operations remain on CPU (OpenSSL/cryptography path)")
            if stream_type == "live":
                reasons.append("live stream helpers keep crypto on CPU; codec hwaccel is delegated to ffmpeg command")
            return {
                "op_name": op_name,
                "stream_type": stream_type,
                "selected_accel": selected_accel,
                "encode_device": encode_device,
                "decode_device": decode_device,
                "pixel_backend": pixel_backend,
                "gpu_pixels_strict": gpu_pixels_strict,
                "pixel_workers": pixel_workers,
                "crypto_device": "cpu",
                "aes_accel_state": aes_accel_state,
                "reasons": reasons,
            }

        @staticmethod
        def _hw_log_color_enabled() -> bool:
            if basefwx.os.getenv("NO_COLOR"):
                return False
            stream = getattr(basefwx.sys, "stderr", None)
            return bool(stream and hasattr(stream, "isatty") and stream.isatty())

        @staticmethod
        def _hw_color(text: str, code: str) -> str:
            if not basefwx.MediaCipher._hw_log_color_enabled():
                return text
            return f"\033[{code}m{text}\033[0m"

        @staticmethod
        def _hw_verbose_enabled() -> bool:
            raw = basefwx.os.getenv("BASEFWX_VERBOSE", "").strip().lower()
            return raw in {"1", "true", "yes", "on"}

        @staticmethod
        def _log_hw_execution_plan(plan: "dict[str, basefwx.typing.Any]") -> None:
            reason = "; ".join(plan.get("reasons", []))
            encode = str(plan.get("encode_device", "cpu")).upper()
            decode = str(plan.get("decode_device", "cpu")).upper()
            pixels = str(plan.get("pixel_backend", "cpu")).upper()
            crypto = str(plan.get("crypto_device", "cpu")).upper()
            aes = str(plan.get("aes_accel_state", "unknown"))
            header = (
                f"🎛️ [basefwx.hw] op={plan.get('op_name', 'unknown')} "
                f"encode={encode} decode={decode} pixels={pixels} crypto={crypto} aes_accel={aes}"
            )
            detail = f"   reason: {reason or 'n/a'}"
            if basefwx.MediaCipher._hw_log_color_enabled():
                header = (
                    f"🎛️ {basefwx.MediaCipher._hw_color('[basefwx.hw]', '36;1')} "
                    f"op={basefwx.MediaCipher._hw_color(str(plan.get('op_name', 'unknown')), '1')} "
                    f"encode={basefwx.MediaCipher._hw_color(encode, '32;1')} "
                    f"decode={basefwx.MediaCipher._hw_color(decode, '33;1')} "
                    f"pixels={basefwx.MediaCipher._hw_color(pixels, '35;1')} "
                    f"crypto={basefwx.MediaCipher._hw_color(crypto, '34;1')} "
                    f"aes_accel={basefwx.MediaCipher._hw_color(aes, '36')}"
                )
                detail = f"   {basefwx.MediaCipher._hw_color('reason:', '2')} {reason or 'n/a'}"
            if basefwx.MediaCipher._hw_verbose_enabled():
                msg = f"{header}\n{detail}"
            else:
                msg = header
            try:
                print(msg, file=basefwx.sys.stderr)
            except Exception:
                pass

        @staticmethod
        def _parse_rate(rate: str) -> float:
            if not rate or rate == "0/0":
                return 0.0
            if "/" in rate:
                num, den = rate.split("/", 1)
                try:
                    return float(num) / float(den)
                except Exception:
                    return 0.0
            try:
                return float(rate)
            except Exception:
                return 0.0

        @staticmethod
        def _probe_streams(path: "basefwx.pathlib.Path") -> "dict[str, basefwx.typing.Any]":
            basefwx.MediaCipher._ensure_ffmpeg()
            cmd = [
                "ffprobe",
                "-v", "error",
                "-show_entries",
                "stream=codec_type,width,height,avg_frame_rate,r_frame_rate,sample_rate,channels,bit_rate"
                ":format=duration,bit_rate",
                "-of", "json",
                str(path)
            ]
            result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"ffprobe failed: {result.stderr.strip() or 'unknown error'}")
            data = basefwx.json.loads(result.stdout or "{}")
            streams = data.get("streams", []) or []
            video = None
            audio = None
            for stream in streams:
                if stream.get("codec_type") == "video" and video is None:
                    video = stream
                elif stream.get("codec_type") == "audio" and audio is None:
                    audio = stream
            info: dict[str, basefwx.typing.Any] = {}
            fmt = data.get("format", {}) or {}
            try:
                info["duration"] = float(fmt.get("duration") or 0.0)
            except Exception:
                info["duration"] = 0.0
            try:
                info["bit_rate"] = int(float(fmt.get("bit_rate") or 0.0))
            except Exception:
                info["bit_rate"] = 0
            if video:
                fps = basefwx.MediaCipher._parse_rate(
                    video.get("avg_frame_rate") or video.get("r_frame_rate") or ""
                )
                try:
                    video_bps = int(float(video.get("bit_rate") or 0.0))
                except Exception:
                    video_bps = 0
                info["video"] = {
                    "width": int(video.get("width") or 0),
                    "height": int(video.get("height") or 0),
                    "fps": fps,
                    "bit_rate": video_bps
                }
            if audio:
                try:
                    audio_bps = int(float(audio.get("bit_rate") or 0.0))
                except Exception:
                    audio_bps = 0
                info["audio"] = {
                    "sample_rate": int(audio.get("sample_rate") or 0),
                    "channels": int(audio.get("channels") or 0),
                    "bit_rate": audio_bps
                }
            return info

        @staticmethod
        def _estimate_bitrates(
            path: "basefwx.pathlib.Path",
            info: "dict[str, basefwx.typing.Any]"
        ) -> "tuple[int | None, int | None]":
            total_bps = int(info.get("bit_rate") or 0)
            duration = float(info.get("duration") or 0.0)
            if total_bps <= 0 and duration > 0:
                try:
                    total_bps = int(path.stat().st_size * 8 / duration)
                except Exception:
                    total_bps = 0
            video_bps = int((info.get("video") or {}).get("bit_rate") or 0)
            audio_bps = int((info.get("audio") or {}).get("bit_rate") or 0)
            if total_bps > 0:
                target_total = int(total_bps * basefwx.MediaCipher.JMG_TARGET_GROWTH)
                max_total = int(total_bps * basefwx.MediaCipher.JMG_MAX_GROWTH)
                if target_total <= 0:
                    target_total = total_bps
                if target_total > max_total:
                    target_total = max_total
                if info.get("video") and video_bps <= 0:
                    if audio_bps > 0:
                        video_bps = max(1, target_total - audio_bps)
                    else:
                        video_bps = max(basefwx.MediaCipher.JMG_MIN_VIDEO_BPS, int(target_total * 0.85))
                if info.get("audio") and audio_bps <= 0:
                    audio_bps = max(basefwx.MediaCipher.JMG_MIN_AUDIO_BPS, int(target_total * 0.15))
                if video_bps > 0:
                    video_bps = min(video_bps, max_total)
                if audio_bps > 0:
                    audio_bps = min(audio_bps, max_total)
            return (video_bps or None), (audio_bps or None)

        @staticmethod
        def _format_bytes(value: int) -> str:
            units = ("B", "KiB", "MiB", "GiB", "TiB")
            amount = float(max(0, int(value)))
            for unit in units:
                if amount < 1024.0 or unit == units[-1]:
                    if unit == "B":
                        return f"{int(amount)}{unit}"
                    return f"{amount:.1f}{unit}"
                amount /= 1024.0
            return f"{int(value)}B"

        @staticmethod
        def _workspace_free_bytes(path: "basefwx.pathlib.Path") -> int:
            try:
                return int(basefwx.shutil.disk_usage(path).free)
            except Exception:
                return -1

        @classmethod
        def _ensure_workspace_free(
            cls,
            workspace: "basefwx.pathlib.Path",
            required: int,
            stage: str
        ) -> None:
            if required <= 0:
                return
            free = cls._workspace_free_bytes(workspace)
            if free < 0 or free >= required:
                return
            raise RuntimeError(
                f"Insufficient temp workspace for {stage}: "
                f"need about {cls._format_bytes(required)}, have {cls._format_bytes(free)} free at '{workspace}'. "
                "This jMG pipeline uses raw media scratch files; reduce input duration/resolution, free disk space, "
                "or point TMPDIR to a larger filesystem."
            )

        @classmethod
        def _estimate_video_workspace_need(
            cls,
            info: "dict[str, basefwx.typing.Any]"
        ) -> int:
            video = info.get("video") or {}
            audio = info.get("audio") or {}
            width = int(video.get("width") or 0)
            height = int(video.get("height") or 0)
            fps = float(video.get("fps") or 0.0)
            duration = float(info.get("duration") or 0.0)
            if width <= 0 or height <= 0 or fps <= 0.0 or duration <= 0.0:
                return 0
            frame_size = width * height * 3
            frame_count = max(1, int((duration * fps) + 0.999))
            video_raw = frame_size * frame_count
            audio_raw = 0
            sample_rate = int(audio.get("sample_rate") or 0)
            channels = int(audio.get("channels") or 0)
            if sample_rate > 0 and channels > 0:
                audio_raw = int(duration * sample_rate * channels * 2)
            # Worst-case concurrent raw scratch:
            # source raw video+audio + scrambled raw video+audio + reserve.
            return (2 * video_raw) + (2 * audio_raw) + cls.WORKSPACE_RESERVE_BYTES

        @classmethod
        def _estimate_audio_workspace_need(
            cls,
            info: "dict[str, basefwx.typing.Any]"
        ) -> int:
            audio = info.get("audio") or {}
            duration = float(info.get("duration") or 0.0)
            sample_rate = int(audio.get("sample_rate") or 0)
            channels = int(audio.get("channels") or 0)
            if duration <= 0.0 or sample_rate <= 0 or channels <= 0:
                return cls.WORKSPACE_RESERVE_BYTES
            audio_raw = int(duration * sample_rate * channels * 2)
            return (2 * audio_raw) + cls.WORKSPACE_RESERVE_BYTES

        @staticmethod
        def _probe_metadata(path: "basefwx.pathlib.Path") -> "dict[str, str]":
            basefwx.MediaCipher._ensure_ffmpeg()
            cmd = [
                "ffprobe",
                "-v", "error",
                "-show_entries", "format_tags",
                "-of", "json",
                str(path)
            ]
            result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return {}
            data = basefwx.json.loads(result.stdout or "{}")
            tags = (data.get("format", {}) or {}).get("tags", {}) or {}
            clean: dict[str, str] = {}
            for key, value in tags.items():
                if isinstance(value, str) and value:
                    clean[str(key)] = value
            return clean

        @staticmethod
        def _derive_base_key(
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            *,
            security_profile: int = 0
        ) -> bytes:
            material = basefwx.MediaCipher._derive_media_material(
                password,
                security_profile=security_profile,
            )
            return material[:32]

        @staticmethod
        def _derive_media_material(
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            *,
            security_profile: int = 0
        ) -> bytes:
            return basefwx._derive_key_material(
                basefwx._coerce_password_bytes(password),
                basefwx._jmg_stream_info_for_profile(security_profile),
                length=64,
                iterations=max(200_000, basefwx.USER_KDF_ITERATIONS)
            )

        @staticmethod
        def _unit_material(base_key: bytes, label: bytes, index: int, length: int) -> bytes:
            info = label + index.to_bytes(8, "big")
            return basefwx._hkdf_sha256(base_key, info=info, length=length)

        @staticmethod
        def _permute_indices(count: int, seed: int) -> "list[int]":
            order = list(range(count))
            st = seed & ((1 << 64) - 1)
            for i in range(count - 1, 0, -1):
                st, rnd = basefwx._splitmix64(st)
                j = rnd % (i + 1)
                if j != i:
                    order[i], order[j] = order[j], order[i]
            return order

        @staticmethod
        def _aes_ctr_transform(data: bytes, key: bytes, iv: bytes) -> bytes:
            cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()

        @staticmethod
        def _audio_mask_transform(
            data: bytes,
            key: bytes,
            iv: bytes,
            *,
            mask_bits: int | None = None
        ) -> bytes:
            if not data:
                return b""
            # Obfuscation-only: masks low bits to preserve audio fidelity, not confidentiality.
            tail = b""
            if len(data) % 2:
                tail = data[-1:]
                data = data[:-1]
            cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
            encryptor = cipher.encryptor()
            keystream = encryptor.update(bytes(len(data))) + encryptor.finalize()
            bits = basefwx.MediaCipher.AUDIO_MASK_BITS if mask_bits is None else max(1, min(16, int(mask_bits)))
            mask = (1 << bits) - 1
            out = bytearray(len(data))
            if basefwx.np is not None and len(data) >= 2:
                try:
                    np_samples = basefwx.np.frombuffer(data, dtype=basefwx.np.dtype("<u2")).copy()
                    np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.dtype("<u2"))
                    basefwx.np.bitwise_xor(
                        np_samples,
                        basefwx.np.bitwise_and(np_keystream, mask),
                        out=np_samples,
                    )
                    return np_samples.tobytes() + tail
                except Exception:
                    pass
            for i in range(0, len(data), 2):
                sample = int.from_bytes(data[i:i + 2], "little", signed=False)
                ks = keystream[i] | (keystream[i + 1] << 8)
                sample ^= (ks & mask)
                out[i:i + 2] = sample.to_bytes(2, "little", signed=False)
            return bytes(out) + tail

        @staticmethod
        def _video_mask_transform(
            data: bytes,
            key: bytes,
            iv: bytes,
            *,
            mask_bits: int | None = None,
            use_cuda: bool = False,
            cuda_strict: bool = False,
        ) -> bytes:
            if not data:
                return b""
            # Obfuscation-only: masks low bits to preserve video quality, not confidentiality.
            cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
            encryptor = cipher.encryptor()
            keystream = encryptor.update(bytes(len(data))) + encryptor.finalize()
            bits = basefwx.MediaCipher.VIDEO_MASK_BITS if mask_bits is None else max(1, min(8, int(mask_bits)))
            mask = (1 << bits) - 1
            if use_cuda:
                if basefwx.cp is None or basefwx.np is None:
                    if cuda_strict:
                        raise RuntimeError("CUDA pixel path requested but CuPy/NumPy is unavailable")
                else:
                    ready, reason = basefwx.MediaCipher._cuda_runtime_status()
                    if not ready:
                        if cuda_strict:
                            raise RuntimeError(
                                "CUDA pixel path requested but CUDA runtime is unavailable: "
                                f"{reason}"
                            )
                        use_cuda = False
                    if use_cuda:
                        try:
                            np_data = basefwx.np.frombuffer(data, dtype=basefwx.np.uint8).copy()
                            np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.uint8)
                            gpu_data = basefwx.cp.asarray(np_data)
                            gpu_keystream = basefwx.cp.asarray(np_keystream)
                            gpu_data ^= (gpu_keystream & mask)
                            return basefwx.cp.asnumpy(gpu_data).tobytes()
                        except Exception as exc:
                            err = str(exc).strip().replace("\n", " ")
                            if len(err) > 220:
                                err = err[:220] + "..."
                            basefwx.MediaCipher._set_cuda_runtime_state(
                                False,
                                err or exc.__class__.__name__,
                            )
                            if cuda_strict:
                                raise RuntimeError(
                                    "CUDA pixel path failed during frame transform: "
                                    f"{err or exc.__class__.__name__}"
                                ) from None
            if basefwx.np is not None:
                try:
                    np_data = basefwx.np.frombuffer(data, dtype=basefwx.np.uint8).copy()
                    np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.uint8)
                    basefwx.np.bitwise_xor(
                        np_data,
                        basefwx.np.bitwise_and(np_keystream, mask),
                        out=np_data,
                    )
                    return np_data.tobytes()
                except Exception:
                    pass
            out = bytearray(data)
            for i in range(len(out)):
                out[i] ^= keystream[i] & mask
            return bytes(out)

        @staticmethod
        def _ffmpeg_video_codec_args(
            output_path: "basefwx.pathlib.Path",
            target_bitrate: int | None = None,
            hwaccel: "basefwx.typing.Optional[str]" = None
        ) -> "list[str]":
            ext = output_path.suffix.lower()
            if target_bitrate and target_bitrate > 0:
                kbps = max(100, target_bitrate // 1000)
                if ext == ".webm":
                    return ["-c:v", "libvpx-vp9", "-b:v", f"{kbps}k", "-crf", "33", "-pix_fmt", "yuv420p"]
                if hwaccel == "nvenc":
                    return [
                        "-c:v", "h264_nvenc",
                        "-preset", "p4",
                        "-b:v", f"{kbps}k",
                        "-maxrate", f"{kbps}k",
                        "-bufsize", f"{kbps * 2}k",
                        "-pix_fmt", "yuv420p"
                    ]
                if hwaccel == "qsv":
                    return [
                        "-c:v", "h264_qsv",
                        "-b:v", f"{kbps}k",
                        "-maxrate", f"{kbps}k",
                        "-bufsize", f"{kbps * 2}k",
                        "-pix_fmt", "yuv420p"
                    ]
                if hwaccel == "vaapi":
                    device = basefwx.os.getenv("BASEFWX_VAAPI_DEVICE", "/dev/dri/renderD128")
                    return [
                        "-vaapi_device", device,
                        "-vf", "format=nv12,hwupload",
                        "-c:v", "h264_vaapi",
                        "-b:v", f"{kbps}k",
                        "-maxrate", f"{kbps}k",
                        "-bufsize", f"{kbps * 2}k"
                    ]
                return [
                    "-c:v", "libx264",
                    "-preset", "veryfast",
                    "-b:v", f"{kbps}k",
                    "-maxrate", f"{kbps}k",
                    "-bufsize", f"{kbps * 2}k",
                    "-pix_fmt", "yuv420p"
                ]
            if ext == ".webm":
                return ["-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "32", "-pix_fmt", "yuv420p"]
            if hwaccel == "nvenc":
                return ["-c:v", "h264_nvenc", "-preset", "p4", "-cq", "23", "-pix_fmt", "yuv420p"]
            if hwaccel == "qsv":
                return ["-c:v", "h264_qsv", "-global_quality", "23", "-pix_fmt", "yuv420p"]
            if hwaccel == "vaapi":
                device = basefwx.os.getenv("BASEFWX_VAAPI_DEVICE", "/dev/dri/renderD128")
                return ["-vaapi_device", device, "-vf", "format=nv12,hwupload", "-c:v", "h264_vaapi", "-qp", "23"]
            return ["-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p"]

        @staticmethod
        def _ffmpeg_audio_codec_args(
            output_path: "basefwx.pathlib.Path",
            target_bitrate: int | None = None
        ) -> "list[str]":
            ext = output_path.suffix.lower()
            if target_bitrate and target_bitrate > 0:
                kbps = max(48, target_bitrate // 1000)
            else:
                kbps = 0
            if ext == ".mp3":
                return ["-c:a", "libmp3lame", "-b:a", f"{kbps or 192}k"]
            if ext in {".flac"}:
                return ["-c:a", "flac"]
            if ext in {".wav", ".aiff", ".aif"}:
                return ["-c:a", "pcm_s16le"]
            if ext in {".ogg", ".opus", ".webm"}:
                return ["-c:a", "libopus", "-b:a", f"{kbps or 96}k"]
            if ext in {".m4a", ".aac"}:
                return ["-c:a", "aac", "-b:a", f"{kbps or 160}k"]
            return ["-c:a", "aac", "-b:a", f"{kbps or 160}k"]

        @staticmethod
        def _ffmpeg_container_args(output_path: "basefwx.pathlib.Path") -> "list[str]":
            if output_path.suffix.lower() in {".mp4", ".m4v", ".mov", ".m4a"}:
                return ["-movflags", "+faststart"]
            return []

        @staticmethod
        def _media_workers() -> int:
            raw = basefwx.os.getenv("BASEFWX_MEDIA_WORKERS")
            if raw:
                try:
                    value = int(raw)
                    return max(1, value)
                except Exception:
                    pass
            return max(1, basefwx.os.cpu_count() or 1)

        @staticmethod
        def _jmg_profile_label(
            label: bytes,
            security_profile: int
        ) -> bytes:
            if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
                return label + b".max"
            return label

        @staticmethod
        def _jmg_video_mask_bits(security_profile: int) -> int:
            if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
                return basefwx.MediaCipher.VIDEO_MASK_BITS_MAX
            return basefwx.MediaCipher.VIDEO_MASK_BITS

        @staticmethod
        def _jmg_audio_mask_bits(security_profile: int) -> int:
            if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
                return basefwx.MediaCipher.AUDIO_MASK_BITS_MAX
            return basefwx.MediaCipher.AUDIO_MASK_BITS
        @staticmethod
        def _shuffle_frame_blocks(
            frame: bytes,
            width: int,
            height: int,
            channels: int,
            seed: int,
            block_size: int
        ) -> bytes:
            blocks_x = (width + block_size - 1) // block_size
            blocks_y = (height + block_size - 1) // block_size
            total_blocks = blocks_x * blocks_y
            perm = basefwx.MediaCipher._permute_indices(total_blocks, seed)
            if (
                basefwx.np is not None
                and channels > 0
                and len(frame) == width * height * channels
                and width % block_size == 0
                and height % block_size == 0
            ):
                try:
                    arr = basefwx.np.frombuffer(frame, dtype=basefwx.np.uint8).reshape(height, width, channels)
                    blocks = (
                        arr.reshape(blocks_y, block_size, blocks_x, block_size, channels)
                        .transpose(0, 2, 1, 3, 4)
                        .reshape(total_blocks, block_size, block_size, channels)
                    )
                    perm_arr = basefwx.np.asarray(perm, dtype=basefwx.np.intp)
                    shuffled = blocks[perm_arr]
                    out_arr = (
                        shuffled.reshape(blocks_y, blocks_x, block_size, block_size, channels)
                        .transpose(0, 2, 1, 3, 4)
                        .reshape(height, width, channels)
                    )
                    return out_arr.tobytes()
                except Exception:
                    pass
            out = bytearray(len(frame))
            for dest_idx in range(total_blocks):
                src_idx = perm[dest_idx]
                dx = (dest_idx % blocks_x) * block_size
                dy = (dest_idx // blocks_x) * block_size
                sx = (src_idx % blocks_x) * block_size
                sy = (src_idx // blocks_x) * block_size
                copy_w = min(block_size, width - dx, width - sx)
                copy_h = min(block_size, height - dy, height - sy)
                for row in range(copy_h):
                    src_off = ((sy + row) * width + sx) * channels
                    dst_off = ((dy + row) * width + dx) * channels
                    end = src_off + copy_w * channels
                    out[dst_off:dst_off + copy_w * channels] = frame[src_off:end]
            return bytes(out)

        @staticmethod
        def _unshuffle_frame_blocks(
            frame: bytes,
            width: int,
            height: int,
            channels: int,
            seed: int,
            block_size: int
        ) -> bytes:
            blocks_x = (width + block_size - 1) // block_size
            blocks_y = (height + block_size - 1) // block_size
            total_blocks = blocks_x * blocks_y
            perm = basefwx.MediaCipher._permute_indices(total_blocks, seed)
            if (
                basefwx.np is not None
                and channels > 0
                and len(frame) == width * height * channels
                and width % block_size == 0
                and height % block_size == 0
            ):
                try:
                    arr = basefwx.np.frombuffer(frame, dtype=basefwx.np.uint8).reshape(height, width, channels)
                    blocks = (
                        arr.reshape(blocks_y, block_size, blocks_x, block_size, channels)
                        .transpose(0, 2, 1, 3, 4)
                        .reshape(total_blocks, block_size, block_size, channels)
                    )
                    inv = basefwx.np.empty(total_blocks, dtype=basefwx.np.intp)
                    inv[basefwx.np.asarray(perm, dtype=basefwx.np.intp)] = basefwx.np.arange(
                        total_blocks, dtype=basefwx.np.intp
                    )
                    restored = blocks[inv]
                    out_arr = (
                        restored.reshape(blocks_y, blocks_x, block_size, block_size, channels)
                        .transpose(0, 2, 1, 3, 4)
                        .reshape(height, width, channels)
                    )
                    return out_arr.tobytes()
                except Exception:
                    pass
            out = bytearray(len(frame))
            for dest_idx in range(total_blocks):
                src_idx = perm[dest_idx]
                dx = (dest_idx % blocks_x) * block_size
                dy = (dest_idx // blocks_x) * block_size
                sx = (src_idx % blocks_x) * block_size
                sy = (src_idx // blocks_x) * block_size
                copy_w = min(block_size, width - dx, width - sx)
                copy_h = min(block_size, height - dy, height - sy)
                for row in range(copy_h):
                    src_off = ((dy + row) * width + dx) * channels
                    dst_off = ((sy + row) * width + sx) * channels
                    end = src_off + copy_w * channels
                    out[dst_off:dst_off + copy_w * channels] = frame[src_off:end]
            return bytes(out)

        @staticmethod
        def _shuffle_audio_samples(block: bytes, seed: int) -> bytes:
            if not block:
                return block
            tail = b""
            if len(block) % 2:
                tail = block[-1:]
                block = block[:-1]
            samples = len(block) // 2
            if samples <= 1:
                return block + tail
            perm = basefwx.MediaCipher._permute_indices(samples, seed)
            if basefwx.np is not None:
                try:
                    arr = basefwx.np.frombuffer(block, dtype=basefwx.np.dtype("<u2"))
                    shuffled = arr[basefwx.np.asarray(perm, dtype=basefwx.np.intp)]
                    return shuffled.tobytes() + tail
                except Exception:
                    pass
            out = bytearray(len(block))
            for dest_idx, src_idx in enumerate(perm):
                src_off = src_idx * 2
                dst_off = dest_idx * 2
                out[dst_off:dst_off + 2] = block[src_off:src_off + 2]
            return bytes(out) + tail

        @staticmethod
        def _unshuffle_audio_samples(block: bytes, seed: int) -> bytes:
            if not block:
                return block
            tail = b""
            if len(block) % 2:
                tail = block[-1:]
                block = block[:-1]
            samples = len(block) // 2
            if samples <= 1:
                return block + tail
            perm = basefwx.MediaCipher._permute_indices(samples, seed)
            if basefwx.np is not None:
                try:
                    arr = basefwx.np.frombuffer(block, dtype=basefwx.np.dtype("<u2"))
                    out_arr = basefwx.np.empty(samples, dtype=basefwx.np.dtype("<u2"))
                    out_arr[basefwx.np.asarray(perm, dtype=basefwx.np.intp)] = arr
                    return out_arr.tobytes() + tail
                except Exception:
                    pass
            out = bytearray(len(block))
            for dest_idx, src_idx in enumerate(perm):
                src_off = src_idx * 2
                dst_off = dest_idx * 2
                out[src_off:src_off + 2] = block[dst_off:dst_off + 2]
            return bytes(out) + tail

        @staticmethod
        def _video_group_frames(fps: float) -> int:
            group_frames = max(2, int(round((fps or 30.0) * basefwx.MediaCipher.VIDEO_GROUP_SECONDS)))
            max_frames = basefwx.MediaCipher.VIDEO_GROUP_MAX_FRAMES
            raw = basefwx.os.getenv("BASEFWX_VIDEO_GROUP_MAX_FRAMES", "").strip()
            if raw:
                try:
                    max_frames = max(2, min(240, int(raw)))
                except Exception:
                    max_frames = basefwx.MediaCipher.VIDEO_GROUP_MAX_FRAMES
            return min(group_frames, max_frames)

        @staticmethod
        def _scramble_video_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            width: int,
            height: int,
            fps: float,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None,
            use_gpu_pixels: bool = False,
            gpu_pixels_strict: bool = False,
        ) -> None:
            frame_size = width * height * 3
            if frame_size <= 0:
                raise ValueError("Invalid video dimensions")
            group_frames = basefwx.MediaCipher._video_group_frames(fps)
            total_frames = 0
            if progress_cb:
                try:
                    total_frames = raw_in.stat().st_size // frame_size
                except Exception:
                    total_frames = 0
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_frames)
                )
            processed_frames = 0
            cancelled = False
            frame_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-frame", security_profile)
            frame_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fblk", security_profile)
            frame_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fgrp", security_profile)
            video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
            try:
                with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                    frame_index = 0
                    group_index = 0
                    while True:
                        group_start_index = frame_index
                        raw_frames: "list[bytes]" = []
                        for _ in range(group_frames):
                            data = src.read(frame_size)
                            if not data or len(data) < frame_size:
                                break
                            raw_frames.append(data)
                        if not raw_frames:
                            break

                        def _process(item: tuple[int, bytes]) -> bytes:
                            idx, frame = item
                            frame_id = group_start_index + idx
                            material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                            key = material[:32]
                            iv = material[32:48]
                            masked = basefwx.MediaCipher._video_mask_transform(
                                frame,
                                key,
                                iv,
                                mask_bits=video_mask_bits,
                                use_cuda=use_gpu_pixels,
                                cuda_strict=gpu_pixels_strict,
                            )
                            seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                            seed = int.from_bytes(seed_bytes, "big")
                            return basefwx.MediaCipher._shuffle_frame_blocks(
                                masked,
                                width,
                                height,
                                3,
                                seed,
                                basefwx.MediaCipher.VIDEO_BLOCK_SIZE
                            )

                        if executor:
                            frames = list(executor.map(_process, enumerate(raw_frames)))
                        else:
                            frames = [_process(item) for item in enumerate(raw_frames)]

                        seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                        seed_index &= (1 << 64) - 1
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        perm = basefwx.MediaCipher._permute_indices(len(frames), seed)
                        for idx in perm:
                            dst.write(frames[idx])
                        processed_frames += len(frames)
                        if progress_cb and total_frames:
                            progress_cb(min(1.0, processed_frames / total_frames))
                        frame_index += len(frames)
                        group_index += 1
            except OSError as exc:
                if getattr(exc, "errno", None) == 28:
                    free = basefwx.MediaCipher._workspace_free_bytes(raw_out.parent)
                    raise RuntimeError(
                        "No space left on device while writing video scratch data "
                        f"('{raw_out.parent}', free={basefwx.MediaCipher._format_bytes(max(0, free))}). "
                        "jMG currently needs room for both decoded and transformed raw streams."
                    ) from None
                raise
            except KeyboardInterrupt:
                cancelled = True
                if executor:
                    executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)

        @staticmethod
        def _unscramble_video_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            width: int,
            height: int,
            fps: float,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None,
            use_gpu_pixels: bool = False,
            gpu_pixels_strict: bool = False,
        ) -> None:
            frame_size = width * height * 3
            if frame_size <= 0:
                raise ValueError("Invalid video dimensions")
            group_frames = basefwx.MediaCipher._video_group_frames(fps)
            total_frames = 0
            if progress_cb:
                try:
                    total_frames = raw_in.stat().st_size // frame_size
                except Exception:
                    total_frames = 0
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_frames)
                )
            processed_frames = 0
            cancelled = False
            frame_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-frame", security_profile)
            frame_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fblk", security_profile)
            frame_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fgrp", security_profile)
            video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
            try:
                with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                    frame_index = 0
                    group_index = 0
                    while True:
                        group_start_index = frame_index
                        scrambled_frames: "list[bytes]" = []
                        for _ in range(group_frames):
                            data = src.read(frame_size)
                            if not data or len(data) < frame_size:
                                break
                            scrambled_frames.append(data)
                        if not scrambled_frames:
                            break

                        seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                        seed_index &= (1 << 64) - 1
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        perm = basefwx.MediaCipher._permute_indices(len(scrambled_frames), seed)
                        ordered: "list[bytes]" = [b""] * len(scrambled_frames)
                        for dest_idx, src_idx in enumerate(perm):
                            ordered[src_idx] = scrambled_frames[dest_idx]

                        def _process(item: tuple[int, bytes]) -> bytes:
                            idx, frame = item
                            frame_id = group_start_index + idx
                            seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                            seed_local = int.from_bytes(seed_bytes, "big")
                            unshuffled = basefwx.MediaCipher._unshuffle_frame_blocks(
                                frame,
                                width,
                                height,
                                3,
                                seed_local,
                                basefwx.MediaCipher.VIDEO_BLOCK_SIZE
                            )
                            material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                            key = material[:32]
                            iv = material[32:48]
                            return basefwx.MediaCipher._video_mask_transform(
                                unshuffled,
                                key,
                                iv,
                                mask_bits=video_mask_bits,
                                use_cuda=use_gpu_pixels,
                                cuda_strict=gpu_pixels_strict,
                            )

                        if executor:
                            restored = list(executor.map(_process, enumerate(ordered)))
                        else:
                            restored = [_process(item) for item in enumerate(ordered)]
                        for frame in restored:
                            dst.write(frame)
                        processed_frames += len(restored)
                        if progress_cb and total_frames:
                            progress_cb(min(1.0, processed_frames / total_frames))
                        frame_index += len(restored)
                        group_index += 1
            except OSError as exc:
                if getattr(exc, "errno", None) == 28:
                    free = basefwx.MediaCipher._workspace_free_bytes(raw_out.parent)
                    raise RuntimeError(
                        "No space left on device while writing video scratch data "
                        f"('{raw_out.parent}', free={basefwx.MediaCipher._format_bytes(max(0, free))}). "
                        "jMG currently needs room for both decoded and transformed raw streams."
                    ) from None
                raise
            except KeyboardInterrupt:
                cancelled = True
                if executor:
                    executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)

        @staticmethod
        def _read_exact(stream: "basefwx.typing.BinaryIO", size: int) -> bytes:
            if size <= 0:
                return b""
            out = bytearray()
            while len(out) < size:
                chunk = stream.read(size - len(out))
                if not chunk:
                    break
                out.extend(chunk)
            return bytes(out)

        @staticmethod
        def _drain_process_stderr(proc: "basefwx.subprocess.Popen[bytes]") -> str:
            try:
                if proc.stderr is None:
                    return ""
                data = proc.stderr.read()
                if not data:
                    return ""
                return data.decode("utf-8", "replace")
            except Exception:
                return ""

        @staticmethod
        def _scramble_video_stream(
            decode_cmd: "list[str]",
            encode_cmd: "list[str]",
            width: int,
            height: int,
            fps: float,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None,
            use_gpu_pixels: bool = False,
            gpu_pixels_strict: bool = False,
            total_frames_hint: int = 0,
        ) -> None:
            frame_size = width * height * 3
            if frame_size <= 0:
                raise ValueError("Invalid video dimensions")
            group_frames = basefwx.MediaCipher._video_group_frames(fps)
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_frames)
                )
            frame_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-frame", security_profile)
            frame_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fblk", security_profile)
            frame_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fgrp", security_profile)
            video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
            decode_proc = basefwx.subprocess.Popen(
                [str(part) for part in decode_cmd],
                stdout=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            encode_proc = basefwx.subprocess.Popen(
                [str(part) for part in encode_cmd],
                stdin=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            cancelled = False
            try:
                frame_index = 0
                group_index = 0
                processed_frames = 0
                while True:
                    group_start_index = frame_index
                    raw_frames: "list[bytes]" = []
                    for _ in range(group_frames):
                        if decode_proc.stdout is None:
                            break
                        data = basefwx.MediaCipher._read_exact(decode_proc.stdout, frame_size)
                        if not data:
                            break
                        if len(data) < frame_size:
                            raise RuntimeError("ffmpeg produced a truncated raw video frame")
                        raw_frames.append(data)
                    if not raw_frames:
                        break

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, frame = item
                        frame_id = group_start_index + idx
                        material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        masked = basefwx.MediaCipher._video_mask_transform(
                            frame,
                            key,
                            iv,
                            mask_bits=video_mask_bits,
                            use_cuda=use_gpu_pixels,
                            cuda_strict=gpu_pixels_strict,
                        )
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        return basefwx.MediaCipher._shuffle_frame_blocks(
                            masked,
                            width,
                            height,
                            3,
                            seed,
                            basefwx.MediaCipher.VIDEO_BLOCK_SIZE
                        )

                    if executor:
                        frames = list(executor.map(_process, enumerate(raw_frames)))
                    else:
                        frames = [_process(item) for item in enumerate(raw_frames)]

                    seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, "big")
                    perm = basefwx.MediaCipher._permute_indices(len(frames), seed)
                    if encode_proc.stdin is None:
                        raise RuntimeError("ffmpeg encode pipe is unavailable")
                    for idx in perm:
                        try:
                            encode_proc.stdin.write(frames[idx])
                        except (BrokenPipeError, OSError) as exc:
                            if isinstance(exc, BrokenPipeError) or getattr(exc, "errno", None) == 32:
                                encode_rc = encode_proc.wait()
                                encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                                raise RuntimeError(
                                    encode_err.strip()
                                    or f"ffmpeg video encode pipe closed unexpectedly (rc={encode_rc})"
                                ) from None
                            raise
                    processed_frames += len(frames)
                    if progress_cb and total_frames_hint > 0:
                        progress_cb(min(1.0, processed_frames / total_frames_hint))
                    frame_index += len(frames)
                    group_index += 1
                if encode_proc.stdin is not None:
                    encode_proc.stdin.close()
                decode_rc = decode_proc.wait()
                encode_rc = encode_proc.wait()
                decode_err = basefwx.MediaCipher._drain_process_stderr(decode_proc)
                encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                if decode_rc != 0:
                    raise RuntimeError(decode_err.strip() or "ffmpeg video decode failed")
                if encode_rc != 0:
                    raise RuntimeError(encode_err.strip() or "ffmpeg video encode failed")
            except OSError as exc:
                if getattr(exc, "errno", None) == 28:
                    raise RuntimeError(
                        "No space left on device while streaming jMG video transform output."
                    ) from None
                raise
            except KeyboardInterrupt:
                cancelled = True
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)
                if executor and cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                with basefwx.contextlib.suppress(Exception):
                    if decode_proc.poll() is None:
                        decode_proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    if encode_proc.poll() is None:
                        encode_proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    if decode_proc.poll() is None:
                        decode_proc.kill()
                with basefwx.contextlib.suppress(Exception):
                    if encode_proc.poll() is None:
                        encode_proc.kill()

        @staticmethod
        def _unscramble_video_stream(
            decode_cmd: "list[str]",
            encode_cmd: "list[str]",
            width: int,
            height: int,
            fps: float,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None,
            use_gpu_pixels: bool = False,
            gpu_pixels_strict: bool = False,
            total_frames_hint: int = 0,
        ) -> None:
            frame_size = width * height * 3
            if frame_size <= 0:
                raise ValueError("Invalid video dimensions")
            group_frames = basefwx.MediaCipher._video_group_frames(fps)
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_frames)
                )
            frame_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-frame", security_profile)
            frame_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fblk", security_profile)
            frame_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-fgrp", security_profile)
            video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
            decode_proc = basefwx.subprocess.Popen(
                [str(part) for part in decode_cmd],
                stdout=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            encode_proc = basefwx.subprocess.Popen(
                [str(part) for part in encode_cmd],
                stdin=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            cancelled = False
            try:
                frame_index = 0
                group_index = 0
                processed_frames = 0
                while True:
                    group_start_index = frame_index
                    scrambled_frames: "list[bytes]" = []
                    for _ in range(group_frames):
                        if decode_proc.stdout is None:
                            break
                        data = basefwx.MediaCipher._read_exact(decode_proc.stdout, frame_size)
                        if not data:
                            break
                        if len(data) < frame_size:
                            raise RuntimeError("ffmpeg produced a truncated raw video frame")
                        scrambled_frames.append(data)
                    if not scrambled_frames:
                        break

                    seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, "big")
                    perm = basefwx.MediaCipher._permute_indices(len(scrambled_frames), seed)
                    ordered: "list[bytes]" = [b""] * len(scrambled_frames)
                    for dest_idx, src_idx in enumerate(perm):
                        ordered[src_idx] = scrambled_frames[dest_idx]

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, frame = item
                        frame_id = group_start_index + idx
                        seed_bytes_local = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                        seed_local = int.from_bytes(seed_bytes_local, "big")
                        unshuffled = basefwx.MediaCipher._unshuffle_frame_blocks(
                            frame,
                            width,
                            height,
                            3,
                            seed_local,
                            basefwx.MediaCipher.VIDEO_BLOCK_SIZE
                        )
                        material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        return basefwx.MediaCipher._video_mask_transform(
                            unshuffled,
                            key,
                            iv,
                            mask_bits=video_mask_bits,
                            use_cuda=use_gpu_pixels,
                            cuda_strict=gpu_pixels_strict,
                        )

                    if executor:
                        restored = list(executor.map(_process, enumerate(ordered)))
                    else:
                        restored = [_process(item) for item in enumerate(ordered)]
                    if encode_proc.stdin is None:
                        raise RuntimeError("ffmpeg encode pipe is unavailable")
                    for frame in restored:
                        try:
                            encode_proc.stdin.write(frame)
                        except (BrokenPipeError, OSError) as exc:
                            if isinstance(exc, BrokenPipeError) or getattr(exc, "errno", None) == 32:
                                encode_rc = encode_proc.wait()
                                encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                                raise RuntimeError(
                                    encode_err.strip()
                                    or f"ffmpeg video encode pipe closed unexpectedly (rc={encode_rc})"
                                ) from None
                            raise
                    processed_frames += len(restored)
                    if progress_cb and total_frames_hint > 0:
                        progress_cb(min(1.0, processed_frames / total_frames_hint))
                    frame_index += len(restored)
                    group_index += 1
                if encode_proc.stdin is not None:
                    encode_proc.stdin.close()
                decode_rc = decode_proc.wait()
                encode_rc = encode_proc.wait()
                decode_err = basefwx.MediaCipher._drain_process_stderr(decode_proc)
                encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                if decode_rc != 0:
                    raise RuntimeError(decode_err.strip() or "ffmpeg video decode failed")
                if encode_rc != 0:
                    raise RuntimeError(encode_err.strip() or "ffmpeg video encode failed")
            except OSError as exc:
                if getattr(exc, "errno", None) == 28:
                    raise RuntimeError(
                        "No space left on device while streaming jMG video transform output."
                    ) from None
                raise
            except KeyboardInterrupt:
                cancelled = True
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)
                if executor and cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                with basefwx.contextlib.suppress(Exception):
                    if decode_proc.poll() is None:
                        decode_proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    if encode_proc.poll() is None:
                        encode_proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    if decode_proc.poll() is None:
                        decode_proc.kill()
                with basefwx.contextlib.suppress(Exception):
                    if encode_proc.poll() is None:
                        encode_proc.kill()

        @staticmethod
        def _scramble_audio_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            sample_rate: int,
            channels: int,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None
        ) -> None:
            if sample_rate <= 0 or channels <= 0:
                raise ValueError("Invalid audio stream parameters")
            samples_per_block = max(1, int(round(sample_rate * basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            block_size = samples_per_block * channels * 2
            group_blocks = max(2, int(round(basefwx.MediaCipher.AUDIO_GROUP_SECONDS / basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            total_blocks = 0
            if progress_cb:
                try:
                    total_blocks = (raw_in.stat().st_size + block_size - 1) // block_size
                except Exception:
                    total_blocks = 0
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_blocks)
                )
            processed_blocks = 0
            cancelled = False
            audio_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-ablock", security_profile)
            audio_sample_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-asamp", security_profile)
            audio_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-agrp", security_profile)
            audio_mask_bits = basefwx.MediaCipher._jmg_audio_mask_bits(security_profile)
            try:
                with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                    block_index = 0
                    group_index = 0
                    while True:
                        group_start_index = block_index
                        raw_blocks: "list[bytes]" = []
                        for _ in range(group_blocks):
                            data = src.read(block_size)
                            if not data:
                                break
                            raw_blocks.append(data)
                        if not raw_blocks:
                            break

                        def _process(item: tuple[int, bytes]) -> bytes:
                            idx, block = item
                            block_id = group_start_index + idx
                            material = basefwx.MediaCipher._unit_material(base_key, audio_block_label, block_id, 48)
                            key = material[:32]
                            iv = material[32:48]
                            masked = basefwx.MediaCipher._audio_mask_transform(
                                block,
                                key,
                                iv,
                                mask_bits=audio_mask_bits,
                            )
                            seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_sample_label, block_id, 16)
                            seed = int.from_bytes(seed_bytes, "big")
                            return basefwx.MediaCipher._shuffle_audio_samples(masked, seed)

                        if executor:
                            blocks = list(executor.map(_process, enumerate(raw_blocks)))
                        else:
                            blocks = [_process(item) for item in enumerate(raw_blocks)]

                        seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                        seed_index &= (1 << 64) - 1
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_group_label, seed_index, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        perm = basefwx.MediaCipher._permute_indices(len(blocks), seed)
                        for idx in perm:
                            dst.write(blocks[idx])
                        processed_blocks += len(blocks)
                        if progress_cb and total_blocks:
                            progress_cb(min(1.0, processed_blocks / total_blocks))
                        block_index += len(blocks)
                        group_index += 1
            except KeyboardInterrupt:
                cancelled = True
                if executor:
                    executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)

        @staticmethod
        def _unscramble_audio_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            sample_rate: int,
            channels: int,
            base_key: bytes,
            *,
            security_profile: int = 0,
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            workers: "basefwx.typing.Optional[int]" = None
        ) -> None:
            if sample_rate <= 0 or channels <= 0:
                raise ValueError("Invalid audio stream parameters")
            samples_per_block = max(1, int(round(sample_rate * basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            block_size = samples_per_block * channels * 2
            group_blocks = max(2, int(round(basefwx.MediaCipher.AUDIO_GROUP_SECONDS / basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            total_blocks = 0
            if progress_cb:
                try:
                    total_blocks = (raw_in.stat().st_size + block_size - 1) // block_size
                except Exception:
                    total_blocks = 0
            use_workers = workers or basefwx.MediaCipher._media_workers()
            executor = None
            if use_workers > 1:
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(use_workers, group_blocks)
                )
            processed_blocks = 0
            cancelled = False
            audio_block_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-ablock", security_profile)
            audio_sample_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-asamp", security_profile)
            audio_group_label = basefwx.MediaCipher._jmg_profile_label(b"jmg-agrp", security_profile)
            audio_mask_bits = basefwx.MediaCipher._jmg_audio_mask_bits(security_profile)
            try:
                with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                    block_index = 0
                    group_index = 0
                    while True:
                        group_start_index = block_index
                        scrambled_blocks: "list[bytes]" = []
                        for _ in range(group_blocks):
                            data = src.read(block_size)
                            if not data:
                                break
                            scrambled_blocks.append(data)
                        if not scrambled_blocks:
                            break

                        seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                        seed_index &= (1 << 64) - 1
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_group_label, seed_index, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        perm = basefwx.MediaCipher._permute_indices(len(scrambled_blocks), seed)
                        ordered: "list[bytes]" = [b""] * len(scrambled_blocks)
                        for dest_idx, src_idx in enumerate(perm):
                            ordered[src_idx] = scrambled_blocks[dest_idx]

                        def _process(item: tuple[int, bytes]) -> bytes:
                            idx, block = item
                            block_id = group_start_index + idx
                            seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_sample_label, block_id, 16)
                            seed_local = int.from_bytes(seed_bytes, "big")
                            unshuffled = basefwx.MediaCipher._unshuffle_audio_samples(block, seed_local)
                            material = basefwx.MediaCipher._unit_material(base_key, audio_block_label, block_id, 48)
                            key = material[:32]
                            iv = material[32:48]
                            return basefwx.MediaCipher._audio_mask_transform(
                                unshuffled,
                                key,
                                iv,
                                mask_bits=audio_mask_bits,
                            )

                        if executor:
                            restored = list(executor.map(_process, enumerate(ordered)))
                        else:
                            restored = [_process(item) for item in enumerate(ordered)]
                        for block in restored:
                            dst.write(block)
                        processed_blocks += len(restored)
                        if progress_cb and total_blocks:
                            progress_cb(min(1.0, processed_blocks / total_blocks))
                        block_index += len(restored)
                        group_index += 1
            except KeyboardInterrupt:
                cancelled = True
                if executor:
                    executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if executor and not cancelled:
                    executor.shutdown(wait=True)

        @staticmethod
        def _encrypt_metadata(
            tags: "dict[str, str]",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "list[str]":
            encoded_args: "list[str]" = []
            for key, value in tags.items():
                try:
                    enc = basefwx.b512encode(value, password, use_master=False)
                except Exception:
                    continue
                encoded_args.append(f"{key}={enc}")
            return encoded_args

        @staticmethod
        def _decrypt_metadata(
            tags: "dict[str, str]",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "list[str]":
            decoded_args: "list[str]" = []
            for key, value in tags.items():
                try:
                    dec = basefwx.b512decode(value, password, use_master=False)
                except Exception:
                    continue
                decoded_args.append(f"{key}={dec}")
            return decoded_args

        @staticmethod
        def _append_trailer(
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            original_bytes: bytes,
            *,
            archive_key: "basefwx.typing.Optional[bytes]" = None,
            key_header: bytes = b""
        ) -> None:
            profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
            if key_header:
                profile_id = basefwx._jmg_profile_from_key_header(key_header)
            archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
            if archive_key is None:
                material = basefwx.MediaCipher._derive_media_material(
                    password,
                    security_profile=profile_id,
                )
                archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
            archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, archive_info)
            trailer_blob = key_header + archive_blob
            basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_TRAILER_MAGIC, trailer_blob)

        @staticmethod
        def _append_trailer_stream(
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            original_path: "basefwx.pathlib.Path",
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None,
            *,
            archive_key: "basefwx.typing.Optional[bytes]" = None,
            key_header: bytes = b""
        ) -> None:
            profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
            if key_header:
                profile_id = basefwx._jmg_profile_from_key_header(key_header)
            archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
            if archive_key is None:
                material = basefwx.MediaCipher._derive_media_material(
                    password,
                    security_profile=profile_id,
                )
                archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
            aad = archive_info
            size = original_path.stat().st_size
            blob_len = len(key_header) + basefwx.AEAD_NONCE_LEN + size + basefwx.AEAD_TAG_LEN
            if blob_len > 0xFFFFFFFF:
                raise ValueError("Trailer too large for 4-byte length field")
            nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
            cipher = basefwx.Cipher(basefwx.algorithms.AES(archive_key), basefwx.modes.GCM(nonce))
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(aad)
            chunk_size = 1024 * 1024
            with open(output_path, "ab") as out_handle, open(original_path, "rb") as src_handle:
                out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
                out_handle.write(blob_len.to_bytes(4, "big"))
                if key_header:
                    out_handle.write(key_header)
                out_handle.write(nonce)
                processed = 0
                while True:
                    chunk = src_handle.read(chunk_size)
                    if not chunk:
                        break
                    out_handle.write(encryptor.update(chunk))
                    processed += len(chunk)
                    if progress_cb and size:
                        progress_cb(min(1.0, processed / size))
                encryptor.finalize()
                out_handle.write(encryptor.tag)
                out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
                out_handle.write(blob_len.to_bytes(4, "big"))

        @staticmethod
        def _append_key_trailer(
            output_path: "basefwx.pathlib.Path",
            key_header: bytes
        ) -> None:
            if not key_header:
                raise ValueError("Missing JMG key header for no-archive mode")
            basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, key_header)

        @staticmethod
        def _load_base_key_from_key_trailer(
            path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "basefwx.typing.Optional[tuple[bytes, int]]":
            info = basefwx._extract_balanced_trailer_info(path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
            if info is None:
                return None
            blob_start, blob_len, _ = info
            with open(path, "rb") as handle:
                handle.seek(blob_start)
                blob = handle.read(blob_len)
            header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
            if header is None:
                raise ValueError("Invalid JMG key trailer")
            header_len, base_key, _, _, profile_id = header
            if header_len != len(blob):
                raise ValueError("Invalid JMG key trailer payload")
            return base_key, profile_id

        @staticmethod
        def _load_base_key_from_key_trailer_bytes(
            file_bytes: bytes,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "basefwx.typing.Optional[tuple[bytes, int]]":
            trailer = basefwx._extract_balanced_trailer_from_bytes(
                file_bytes,
                basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC
            )
            if trailer is None:
                return None
            blob, _ = trailer
            header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
            if header is None:
                raise ValueError("Invalid JMG key trailer")
            header_len, base_key, _, _, profile_id = header
            if header_len != len(blob):
                raise ValueError("Invalid JMG key trailer payload")
            return base_key, profile_id

        @staticmethod
        def _decrypt_trailer(
            file_bytes: bytes,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "basefwx.typing.Optional[bytes]":
            trailer = basefwx._extract_balanced_trailer_from_bytes(
                file_bytes,
                basefwx.IMAGECIPHER_TRAILER_MAGIC
            )
            if trailer is None:
                return None
            blob, _ = trailer
            header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
            if header is not None:
                header_len, _, archive_key, _, profile_id = header
                archive_blob = blob[header_len:]
                archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
            else:
                material = basefwx.MediaCipher._derive_media_material(password)
                archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
                archive_blob = blob
                archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
            return basefwx._aead_decrypt(archive_key, archive_blob, archive_info)

        @staticmethod
        def _decrypt_trailer_stream(
            path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output_path: "basefwx.pathlib.Path",
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]" = None
        ) -> bool:
            header_seen = False
            try:
                magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
                footer_len = len(magic) + 4
                try:
                    size = path.stat().st_size
                except Exception:
                    return False
                if size < footer_len:
                    return False
                with open(path, "rb") as handle:
                    handle.seek(size - footer_len)
                    footer = handle.read(footer_len)
                    if len(footer) != footer_len or footer[:len(magic)] != magic:
                        return False
                    blob_len = int.from_bytes(footer[len(magic):], "big")
                    trailer_start = size - footer_len - blob_len - footer_len
                    if trailer_start < 0:
                        return False
                    handle.seek(trailer_start)
                    header = handle.read(footer_len)
                    if len(header) != footer_len or header[:len(magic)] != magic:
                        return False
                    header_len = int.from_bytes(header[len(magic):], "big")
                    if header_len != blob_len:
                        return False
                    blob_start = trailer_start + footer_len
                    handle.seek(blob_start)
                    header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
                    prefix = handle.read(len(basefwx.JMG_KEY_MAGIC))
                    if len(prefix) != len(basefwx.JMG_KEY_MAGIC):
                        return False
                    archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
                    if prefix == basefwx.JMG_KEY_MAGIC:
                        header_seen = True
                        version = handle.read(1)
                        if len(version) != 1:
                            return False
                        if version[0] not in {basefwx.JMG_KEY_VERSION_LEGACY, basefwx.JMG_KEY_VERSION}:
                            raise ValueError("Unsupported JMG key header version")
                        payload_len_bytes = handle.read(4)
                        if len(payload_len_bytes) != 4:
                            return False
                        payload_len = int.from_bytes(payload_len_bytes, "big")
                        header_len = header_min + payload_len
                        payload = handle.read(payload_len)
                        if len(payload) != payload_len:
                            return False
                        if version[0] == basefwx.JMG_KEY_VERSION_LEGACY:
                            profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
                            key_payload = payload
                        else:
                            if not payload:
                                return False
                            profile_id = basefwx._jmg_security_profile_id(payload[0])
                            key_payload = payload[1:]
                        user_blob, master_blob = basefwx._unpack_length_prefixed(key_payload, 2)
                        mask_key = basefwx._recover_mask_key_from_blob(
                            user_blob,
                            master_blob,
                            password,
                            True,
                            mask_info=basefwx.JMG_MASK_INFO,
                            aad=basefwx.JMG_MASK_AAD
                        )
                        archive_key = basefwx._hkdf_sha256(
                            mask_key,
                            info=basefwx._jmg_archive_info_for_profile(profile_id),
                            length=32
                        )
                        archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
                        nonce = handle.read(basefwx.AEAD_NONCE_LEN)
                        if len(nonce) != basefwx.AEAD_NONCE_LEN:
                            return False
                        cipher_body_len = blob_len - header_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                    else:
                        archive_key = basefwx._hkdf_sha256(
                            basefwx.MediaCipher._derive_media_material(password),
                            info=basefwx.IMAGECIPHER_ARCHIVE_INFO,
                            length=32
                        )
                        nonce = prefix + handle.read(basefwx.AEAD_NONCE_LEN - len(prefix))
                        if len(nonce) != basefwx.AEAD_NONCE_LEN:
                            return False
                        cipher_body_len = blob_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                    if cipher_body_len < 0:
                        return False
                    cipher = basefwx.Cipher(
                        basefwx.algorithms.AES(archive_key),
                        basefwx.modes.GCM(nonce)
                    )
                    decryptor = cipher.decryptor()
                    decryptor.authenticate_additional_data(archive_info)
                    chunk_size = 1024 * 1024
                    with open(output_path, "wb") as out_handle:
                        remaining = cipher_body_len
                        processed = 0
                        while remaining > 0:
                            chunk = handle.read(min(chunk_size, remaining))
                            if not chunk:
                                return False
                            out_handle.write(decryptor.update(chunk))
                            remaining -= len(chunk)
                            processed += len(chunk)
                            if progress_cb and cipher_body_len:
                                progress_cb(min(1.0, processed / cipher_body_len))
                        tag = handle.read(basefwx.AEAD_TAG_LEN)
                        if len(tag) != basefwx.AEAD_TAG_LEN:
                            return False
                        decryptor.finalize_with_tag(tag)
                return True
            except Exception:
                if header_seen:
                    raise
                return False

        @staticmethod
        def _run_ffmpeg(
            cmd: "list[str]",
            fallback_cmd: "basefwx.typing.Optional[list[str]]" = None
        ) -> None:
            def _run_once(run_cmd: "list[str]") -> "tuple[int, str, str]":
                proc = basefwx.subprocess.Popen(
                    [str(part) for part in run_cmd],
                    stdout=basefwx.subprocess.PIPE,
                    stderr=basefwx.subprocess.PIPE,
                    text=True,
                )
                try:
                    stdout, stderr = proc.communicate()
                    return proc.returncode, stdout or "", stderr or ""
                except KeyboardInterrupt:
                    with basefwx.contextlib.suppress(Exception):
                        proc.terminate()
                    with basefwx.contextlib.suppress(Exception):
                        proc.wait(timeout=1.5)
                    with basefwx.contextlib.suppress(Exception):
                        if proc.poll() is None:
                            proc.kill()
                    with basefwx.contextlib.suppress(Exception):
                        proc.wait(timeout=1.0)
                    raise

            code, _stdout, stderr = _run_once(cmd)
            if code != 0:
                if fallback_cmd and not basefwx.MediaCipher._hwaccel_strict():
                    retry_code, _retry_stdout, retry_stderr = _run_once(fallback_cmd)
                    if retry_code != 0:
                        raise RuntimeError(retry_stderr.strip() or "ffmpeg failed")
                    return
                raise RuntimeError(stderr.strip() or "ffmpeg failed")

        @staticmethod
        def _scramble_video(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            keep_meta: bool,
            base_key: "basefwx.typing.Optional[bytes]" = None,
            security_profile: int = 0,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            hw_plan: "basefwx.typing.Optional[dict[str, basefwx.typing.Any]]" = None,
        ) -> None:
            display_path = display_path or path
            info = basefwx.MediaCipher._probe_streams(path)
            video = info.get("video")
            if not video:
                raise ValueError("No video stream found")
            width = int(video.get("width") or 0)
            height = int(video.get("height") or 0)
            fps = float(video.get("fps") or 0.0)
            audio = info.get("audio")
            video_bps, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
            if hw_plan is None:
                frame_bytes = max(0, width * height * 3)
                hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
                    "jMGe",
                    stream_type="video",
                    frame_bytes=frame_bytes,
                    allow_pixel_gpu=True,
                    prefer_cpu_decode=True,
                )
                basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
            selected_accel = hw_plan.get("selected_accel")
            decode_device = hw_plan.get("decode_device", "cpu")
            # jMG transform runs on host memory, so CPU decode avoids avoidable hwdownload copies.
            decode_video_args = basefwx.MediaCipher._ffmpeg_video_decode_args(
                selected_accel if decode_device != "cpu" else None
            )

            if reporter:
                reporter.update(file_index, 0.05, "probe", display_path)
            temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-media-")
            try:
                workspace = basefwx.pathlib.Path(temp_dir.name)
                basefwx.MediaCipher._ensure_workspace_free(
                    workspace,
                    basefwx.MediaCipher._estimate_audio_workspace_need(info),
                    "video audio-scratch preflight",
                )
                raw_audio = None
                raw_audio_out = None
                sample_rate = 0
                channels = 0
                if audio:
                    raw_audio = basefwx.pathlib.Path(temp_dir.name) / "audio.raw"
                    raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / "audio.scr.raw"
                    sample_rate = int(audio.get("sample_rate") or 0)
                    channels = int(audio.get("channels") or 0)
                    cmd_audio = [
                        "ffmpeg", "-y", "-i", str(path),
                        "-map", "0:a:0",
                        "-f", "s16le",
                        "-acodec", "pcm_s16le",
                        "-ar", str(sample_rate or 48000),
                        "-ac", str(channels or 2),
                        str(raw_audio)
                    ]
                    if reporter:
                        reporter.update(file_index, 0.21, "decode-audio", display_path)
                    basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                    sample_rate = sample_rate or 48000
                    channels = channels or 2
                    if reporter:
                        reporter.update(file_index, 0.3, "decode-audio", display_path)
                if raw_audio:
                    required_transform = int(raw_audio.stat().st_size) + basefwx.MediaCipher.WORKSPACE_RESERVE_BYTES
                    basefwx.MediaCipher._ensure_workspace_free(
                        workspace,
                        required_transform,
                        "video audio transform scratch",
                    )

                if base_key is None:
                    base_key = basefwx.MediaCipher._derive_base_key(
                        password,
                        security_profile=security_profile,
                    )
                video_phase = "jmg-video-gpu" if hw_plan.get("pixel_backend") == "cuda" else "jmg-video-cpu"
                def video_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.3 + 0.4 * frac, video_phase, display_path)

                def audio_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.7 + 0.2 * frac, "jmg-audio-cpu", display_path)

                if raw_audio and raw_audio_out:
                    basefwx.MediaCipher._scramble_audio_raw(
                        raw_audio,
                        raw_audio_out,
                        sample_rate,
                        channels,
                        base_key,
                        security_profile=security_profile,
                        progress_cb=audio_cb if reporter else None,
                        workers=basefwx.MediaCipher._media_workers()
                    )

                cmd_base = [
                    "ffmpeg", "-loglevel", "error", "-y",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "-s", f"{width}x{height}",
                    "-r", str(fps or 30),
                    "-i", "pipe:0"
                ]
                if raw_audio_out:
                    cmd_base += [
                        "-f", "s16le",
                        "-ar", str(sample_rate),
                        "-ac", str(channels),
                        "-i", str(raw_audio_out),
                        "-shortest"
                    ]
                if keep_meta:
                    tags = basefwx.MediaCipher._probe_metadata(path)
                    for meta in basefwx.MediaCipher._encrypt_metadata(tags, password):
                        cmd_base += ["-metadata", meta]
                else:
                    cmd_base += ["-map_metadata", "-1"]
                video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, selected_accel)
                cpu_video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, None)
                cmd = cmd_base + video_args
                if raw_audio_out:
                    cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                cmd.append(str(output_path))
                decode_cmd = ["ffmpeg", "-loglevel", "error", "-y"] + decode_video_args + [
                    "-i", str(path),
                    "-map", "0:v:0",
                ]
                if decode_device != "cpu" and selected_accel == "nvenc":
                    decode_cmd += ["-vf", "hwdownload,format=nv12,format=rgb24"]
                decode_cmd += ["-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"]
                decode_cmd_cpu = [
                    "ffmpeg", "-loglevel", "error", "-y",
                    "-i", str(path),
                    "-map", "0:v:0",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "pipe:1",
                ]
                if reporter:
                    reporter.update(file_index, 0.06, "decode-video", display_path)
                total_frames_hint = max(1, int(round((float(info.get("duration") or 0.0) * (fps or 30.0)))))
                fallback_cmd = cmd_base + cpu_video_args
                if raw_audio_out:
                    fallback_cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                fallback_cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                fallback_cmd.append(str(output_path))

                def _run_stream(decode_use: "list[str]", encode_use: "list[str]") -> None:
                    basefwx.MediaCipher._scramble_video_stream(
                        decode_use,
                        encode_use,
                        width,
                        height,
                        fps,
                        base_key,
                        security_profile=security_profile,
                        progress_cb=video_cb if reporter else None,
                        workers=int(hw_plan.get("pixel_workers") or basefwx.MediaCipher._media_workers()),
                        use_gpu_pixels=bool(hw_plan.get("pixel_backend") == "cuda"),
                        gpu_pixels_strict=bool(hw_plan.get("gpu_pixels_strict", False)),
                        total_frames_hint=total_frames_hint,
                    )

                should_try_fallback = bool(selected_accel and video_args != cpu_video_args and not basefwx.MediaCipher._hwaccel_strict())
                try:
                    _run_stream(decode_cmd if decode_video_args else decode_cmd_cpu, cmd)
                except RuntimeError as exc:
                    if should_try_fallback and "No space left on device" not in str(exc):
                        _run_stream(decode_cmd_cpu, fallback_cmd)
                    else:
                        raise
                if reporter:
                    reporter.update(file_index, 0.95, "encode", display_path)
            finally:
                try:
                    temp_dir.cleanup()
                except KeyboardInterrupt:
                    pass

        @staticmethod
        def _scramble_audio(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            keep_meta: bool,
            base_key: "basefwx.typing.Optional[bytes]" = None,
            security_profile: int = 0,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
        ) -> None:
            display_path = display_path or path
            info = basefwx.MediaCipher._probe_streams(path)
            audio = info.get("audio")
            if not audio:
                raise ValueError("No audio stream found")
            sample_rate = int(audio.get("sample_rate") or 0)
            channels = int(audio.get("channels") or 0)
            sample_rate = sample_rate or 48000
            channels = channels or 2
            _, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)

            if reporter:
                reporter.update(file_index, 0.05, "probe", display_path)
            temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-media-")
            try:
                raw_audio = basefwx.pathlib.Path(temp_dir.name) / "audio.raw"
                raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / "audio.scr.raw"
                cmd_audio = [
                    "ffmpeg", "-y", "-i", str(path),
                    "-map", "0:a:0",
                    "-f", "s16le",
                    "-acodec", "pcm_s16le",
                    "-ar", str(sample_rate),
                    "-ac", str(channels),
                    str(raw_audio)
                ]
                basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                if base_key is None:
                    base_key = basefwx.MediaCipher._derive_base_key(
                        password,
                        security_profile=security_profile,
                    )
                if reporter:
                    reporter.update(file_index, 0.2, "decode-audio", display_path)

                def audio_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.2 + 0.65 * frac, "jmg-audio", display_path)

                basefwx.MediaCipher._scramble_audio_raw(
                    raw_audio,
                    raw_audio_out,
                    sample_rate,
                    channels,
                    base_key,
                    security_profile=security_profile,
                    progress_cb=audio_cb if reporter else None,
                    workers=basefwx.MediaCipher._media_workers()
                )

                cmd = [
                    "ffmpeg", "-y",
                    "-f", "s16le",
                    "-ar", str(sample_rate),
                    "-ac", str(channels),
                    "-i", str(raw_audio_out)
                ]
                if keep_meta:
                    tags = basefwx.MediaCipher._probe_metadata(path)
                    for meta in basefwx.MediaCipher._encrypt_metadata(tags, password):
                        cmd += ["-metadata", meta]
                else:
                    cmd += ["-map_metadata", "-1"]
                cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                cmd.append(str(output_path))
                basefwx.MediaCipher._run_ffmpeg(cmd)
                if reporter:
                    reporter.update(file_index, 0.95, "encode", display_path)
            finally:
                try:
                    temp_dir.cleanup()
                except KeyboardInterrupt:
                    pass

        @staticmethod
        def _unscramble_video(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            base_key: "basefwx.typing.Optional[bytes]" = None,
            security_profile: int = 0,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            hw_plan: "basefwx.typing.Optional[dict[str, basefwx.typing.Any]]" = None,
        ) -> None:
            display_path = display_path or path
            info = basefwx.MediaCipher._probe_streams(path)
            video = info.get("video")
            if not video:
                raise ValueError("No video stream found")
            width = int(video.get("width") or 0)
            height = int(video.get("height") or 0)
            fps = float(video.get("fps") or 0.0)
            audio = info.get("audio")
            video_bps, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
            if hw_plan is None:
                frame_bytes = max(0, width * height * 3)
                hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
                    "jMGd",
                    stream_type="video",
                    frame_bytes=frame_bytes,
                    allow_pixel_gpu=True,
                    prefer_cpu_decode=True,
                )
                basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
            selected_accel = hw_plan.get("selected_accel")
            decode_device = hw_plan.get("decode_device", "cpu")
            # jMG transform runs on host memory, so CPU decode avoids avoidable hwdownload copies.
            decode_video_args = basefwx.MediaCipher._ffmpeg_video_decode_args(
                selected_accel if decode_device != "cpu" else None
            )

            if reporter:
                reporter.update(file_index, 0.05, "probe", display_path)
            temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-media-")
            try:
                workspace = basefwx.pathlib.Path(temp_dir.name)
                basefwx.MediaCipher._ensure_workspace_free(
                    workspace,
                    basefwx.MediaCipher._estimate_audio_workspace_need(info),
                    "video audio-scratch preflight",
                )
                raw_audio = None
                raw_audio_out = None
                sample_rate = 0
                channels = 0
                if audio:
                    raw_audio = basefwx.pathlib.Path(temp_dir.name) / "audio.raw"
                    raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / "audio.unscr.raw"
                    sample_rate = int(audio.get("sample_rate") or 0)
                    channels = int(audio.get("channels") or 0)
                    cmd_audio = [
                        "ffmpeg", "-y", "-i", str(path),
                        "-map", "0:a:0",
                        "-f", "s16le",
                        "-acodec", "pcm_s16le",
                        "-ar", str(sample_rate or 48000),
                        "-ac", str(channels or 2),
                        str(raw_audio)
                    ]
                    if reporter:
                        reporter.update(file_index, 0.21, "decode-audio", display_path)
                    basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                    sample_rate = sample_rate or 48000
                    channels = channels or 2
                    if reporter:
                        reporter.update(file_index, 0.3, "decode-audio", display_path)
                if raw_audio:
                    required_transform = int(raw_audio.stat().st_size) + basefwx.MediaCipher.WORKSPACE_RESERVE_BYTES
                    basefwx.MediaCipher._ensure_workspace_free(
                        workspace,
                        required_transform,
                        "video audio transform scratch",
                    )

                if base_key is None:
                    base_key = basefwx.MediaCipher._derive_base_key(
                        password,
                        security_profile=security_profile,
                    )
                video_phase = "unjmg-video-gpu" if hw_plan.get("pixel_backend") == "cuda" else "unjmg-video-cpu"

                def video_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.3 + 0.4 * frac, video_phase, display_path)

                def audio_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.7 + 0.2 * frac, "unjmg-audio-cpu", display_path)

                if raw_audio and raw_audio_out:
                    basefwx.MediaCipher._unscramble_audio_raw(
                        raw_audio,
                        raw_audio_out,
                        sample_rate,
                        channels,
                        base_key,
                        security_profile=security_profile,
                        progress_cb=audio_cb if reporter else None,
                        workers=basefwx.MediaCipher._media_workers()
                    )

                cmd_base = [
                    "ffmpeg", "-loglevel", "error", "-y",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "-s", f"{width}x{height}",
                    "-r", str(fps or 30),
                    "-i", "pipe:0"
                ]
                if raw_audio_out:
                    cmd_base += [
                        "-f", "s16le",
                        "-ar", str(sample_rate),
                        "-ac", str(channels),
                        "-i", str(raw_audio_out),
                        "-shortest"
                    ]
                tags = basefwx.MediaCipher._probe_metadata(path)
                decoded = basefwx.MediaCipher._decrypt_metadata(tags, password)
                if decoded:
                    for meta in decoded:
                        cmd_base += ["-metadata", meta]
                else:
                    cmd_base += ["-map_metadata", "-1"]
                video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, selected_accel)
                cpu_video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, None)
                cmd = cmd_base + video_args
                if raw_audio_out:
                    cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                cmd.append(str(output_path))
                decode_cmd = ["ffmpeg", "-loglevel", "error", "-y"] + decode_video_args + [
                    "-i", str(path),
                    "-map", "0:v:0",
                ]
                if decode_device != "cpu" and selected_accel == "nvenc":
                    decode_cmd += ["-vf", "hwdownload,format=nv12,format=rgb24"]
                decode_cmd += ["-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"]
                decode_cmd_cpu = [
                    "ffmpeg", "-loglevel", "error", "-y",
                    "-i", str(path),
                    "-map", "0:v:0",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "pipe:1",
                ]
                if reporter:
                    reporter.update(file_index, 0.06, "decode-video", display_path)
                total_frames_hint = max(1, int(round((float(info.get("duration") or 0.0) * (fps or 30.0)))))
                fallback_cmd = cmd_base + cpu_video_args
                if raw_audio_out:
                    fallback_cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                fallback_cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                fallback_cmd.append(str(output_path))

                def _run_stream(decode_use: "list[str]", encode_use: "list[str]") -> None:
                    basefwx.MediaCipher._unscramble_video_stream(
                        decode_use,
                        encode_use,
                        width,
                        height,
                        fps,
                        base_key,
                        security_profile=security_profile,
                        progress_cb=video_cb if reporter else None,
                        workers=int(hw_plan.get("pixel_workers") or basefwx.MediaCipher._media_workers()),
                        use_gpu_pixels=bool(hw_plan.get("pixel_backend") == "cuda"),
                        gpu_pixels_strict=bool(hw_plan.get("gpu_pixels_strict", False)),
                        total_frames_hint=total_frames_hint,
                    )

                should_try_fallback = bool(selected_accel and video_args != cpu_video_args and not basefwx.MediaCipher._hwaccel_strict())
                try:
                    _run_stream(decode_cmd if decode_video_args else decode_cmd_cpu, cmd)
                except RuntimeError as exc:
                    if should_try_fallback and "No space left on device" not in str(exc):
                        _run_stream(decode_cmd_cpu, fallback_cmd)
                    else:
                        raise
                if reporter:
                    reporter.update(file_index, 0.95, "encode", display_path)
            finally:
                try:
                    temp_dir.cleanup()
                except KeyboardInterrupt:
                    pass

        @staticmethod
        def _unscramble_audio(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            base_key: "basefwx.typing.Optional[bytes]" = None,
            security_profile: int = 0,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
        ) -> None:
            display_path = display_path or path
            info = basefwx.MediaCipher._probe_streams(path)
            audio = info.get("audio")
            if not audio:
                raise ValueError("No audio stream found")
            _, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
            sample_rate = int(audio.get("sample_rate") or 0)
            channels = int(audio.get("channels") or 0)
            sample_rate = sample_rate or 48000
            channels = channels or 2

            if reporter:
                reporter.update(file_index, 0.05, "probe", display_path)
            temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-media-")
            try:
                raw_audio = basefwx.pathlib.Path(temp_dir.name) / "audio.raw"
                raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / "audio.unscr.raw"
                cmd_audio = [
                    "ffmpeg", "-y", "-i", str(path),
                    "-map", "0:a:0",
                    "-f", "s16le",
                    "-acodec", "pcm_s16le",
                    "-ar", str(sample_rate),
                    "-ac", str(channels),
                    str(raw_audio)
                ]
                basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                if reporter:
                    reporter.update(file_index, 0.2, "decode-audio", display_path)
                if base_key is None:
                    base_key = basefwx.MediaCipher._derive_base_key(
                        password,
                        security_profile=security_profile,
                    )

                def audio_cb(frac: float) -> None:
                    if reporter:
                        reporter.update(file_index, 0.2 + 0.65 * frac, "unjmg-audio", display_path)

                basefwx.MediaCipher._unscramble_audio_raw(
                    raw_audio,
                    raw_audio_out,
                    sample_rate,
                    channels,
                    base_key,
                    security_profile=security_profile,
                    progress_cb=audio_cb if reporter else None,
                    workers=basefwx.MediaCipher._media_workers()
                )

                cmd = [
                    "ffmpeg", "-y",
                    "-f", "s16le",
                    "-ar", str(sample_rate),
                    "-ac", str(channels),
                    "-i", str(raw_audio_out)
                ]
                tags = basefwx.MediaCipher._probe_metadata(path)
                decoded = basefwx.MediaCipher._decrypt_metadata(tags, password)
                if decoded:
                    for meta in decoded:
                        cmd += ["-metadata", meta]
                else:
                    cmd += ["-map_metadata", "-1"]
                cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
                cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
                cmd.append(str(output_path))
                basefwx.MediaCipher._run_ffmpeg(cmd)
                if reporter:
                    reporter.update(file_index, 0.95, "encode", display_path)
            finally:
                try:
                    temp_dir.cleanup()
                except KeyboardInterrupt:
                    pass

        @staticmethod
        def encrypt_media(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None,
            *,
            keep_meta: bool = False,
            archive_original: bool = False,
            keep_input: bool = False,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
        ) -> str:
            password = basefwx._resolve_password(password, use_master=True)
            path_obj = basefwx._normalize_path(path)
            basefwx._ensure_existing_file(path_obj)
            display_path = display_path or path_obj
            output_path = basefwx.pathlib.Path(output) if output else path_obj
            temp_output = output_path
            if basefwx._normalize_path(output_path) == basefwx._normalize_path(path_obj):
                temp_output = output_path.with_name(f"{output_path.stem}._jmg{output_path.suffix}")
            suffix = path_obj.suffix.lower()
            local_reporter = reporter
            created_reporter = False
            if local_reporter is None and not basefwx._SILENT_MODE:
                local_reporter = basefwx._ProgressReporter(1)
                created_reporter = True
            if not archive_original:
                _warnings_module.warn(
                    "jMG archive_original=False omits embedded original payload; "
                    "decrypted output may not be byte-identical to the input.",
                    UserWarning
                )
            try:
                hw_plan: "basefwx.typing.Optional[dict[str, basefwx.typing.Any]]" = None

                def _ensure_hw_plan(
                    stream_type: str,
                    *,
                    frame_bytes: int = 0,
                    allow_pixel_gpu: bool = False,
                    prefer_cpu_decode: bool = True,
                ) -> "dict[str, basefwx.typing.Any]":
                    nonlocal hw_plan
                    if hw_plan is None:
                        hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
                            "jMGe",
                            stream_type=stream_type,
                            frame_bytes=frame_bytes,
                            allow_pixel_gpu=allow_pixel_gpu,
                            prefer_cpu_decode=prefer_cpu_decode,
                        )
                        basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
                    return hw_plan

                append_archive_trailer = False
                append_key_trailer = False
                if suffix in basefwx.MediaCipher.IMAGE_EXTS:
                    _ensure_hw_plan("image")
                    result = basefwx.ImageCipher.encrypt_image_inv(
                        str(path_obj),
                        password,
                        output=str(temp_output),
                        include_trailer=True,
                        archive_original=archive_original
                    )
                else:
                    try:
                        info = basefwx.MediaCipher._probe_streams(path_obj)
                    except Exception:
                        info = {}
                    if info.get("video"):
                        frame_bytes = int((info.get("video") or {}).get("width") or 0) * int(
                            (info.get("video") or {}).get("height") or 0
                        ) * 3
                        plan = _ensure_hw_plan(
                            "video",
                            frame_bytes=frame_bytes,
                            allow_pixel_gpu=True,
                            prefer_cpu_decode=True,
                        )
                        base_key, archive_key, _, trailer_header = basefwx._jmg_prepare_keys(
                            password,
                            use_master=True,
                            security_profile=basefwx.JMG_SECURITY_PROFILE_MAX,
                        )
                        basefwx.MediaCipher._scramble_video(
                            path_obj,
                            temp_output,
                            password,
                            keep_meta,
                            base_key=base_key,
                            security_profile=basefwx.JMG_SECURITY_PROFILE_MAX,
                            reporter=local_reporter,
                            file_index=file_index,
                            display_path=display_path,
                            hw_plan=plan,
                        )
                        result = str(temp_output)
                        if archive_original:
                            append_archive_trailer = True
                        else:
                            append_key_trailer = True
                    elif info.get("audio"):
                        _ensure_hw_plan("audio")
                        base_key, archive_key, _, trailer_header = basefwx._jmg_prepare_keys(
                            password,
                            use_master=True,
                            security_profile=basefwx.JMG_SECURITY_PROFILE_MAX,
                        )
                        basefwx.MediaCipher._scramble_audio(
                            path_obj,
                            temp_output,
                            password,
                            keep_meta,
                            base_key=base_key,
                            security_profile=basefwx.JMG_SECURITY_PROFILE_MAX,
                            reporter=local_reporter,
                            file_index=file_index,
                            display_path=display_path
                        )
                        result = str(temp_output)
                        if archive_original:
                            append_archive_trailer = True
                        else:
                            append_key_trailer = True
                    else:
                        _ensure_hw_plan("bytes")
                        fallback_out = output_path if output else path_obj.with_suffix(".fwx")
                        return basefwx.fwxAES_file(
                            str(path_obj),
                            password,
                            use_master=True,
                            output=str(fallback_out),
                            ignore_media=True,
                            keep_input=keep_input
                        )

                out_path = basefwx._normalize_path(result)
                if out_path != temp_output:
                    temp_output = out_path
                if append_archive_trailer:
                    def trailer_cb(frac: float) -> None:
                        if local_reporter:
                            local_reporter.update(file_index, 0.95 + 0.04 * frac, "archive", display_path)

                    basefwx.MediaCipher._append_trailer_stream(
                        temp_output,
                        password,
                        path_obj,
                        progress_cb=trailer_cb if local_reporter else None,
                        archive_key=archive_key,
                        key_header=trailer_header
                    )
                elif append_key_trailer:
                    basefwx.MediaCipher._append_key_trailer(temp_output, trailer_header)
                if basefwx._normalize_path(output_path) != basefwx._normalize_path(temp_output):
                    basefwx.os.replace(temp_output, output_path)
                    temp_output = output_path
                basefwx._remove_input(path_obj, keep_input, output_path=temp_output)
                if local_reporter:
                    local_reporter.update(file_index, 1.0, "done", display_path)
                return str(temp_output)
            finally:
                if created_reporter and local_reporter:
                    local_reporter.reset_terminal_state()

        @staticmethod
        def decrypt_media(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None,
            *,
            reporter: "basefwx.typing.Optional[basefwx._ProgressReporter]" = None,
            file_index: int = 0,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None
        ) -> str:
            password = basefwx._resolve_password(password, use_master=True)
            path_obj = basefwx._normalize_path(path)
            basefwx._ensure_existing_file(path_obj)
            display_path = display_path or path_obj
            output_path = basefwx.pathlib.Path(output) if output else path_obj
            temp_output = output_path
            if basefwx._normalize_path(output_path) == basefwx._normalize_path(path_obj):
                temp_output = output_path.with_name(f"{output_path.stem}._jmgdec{output_path.suffix}")

            local_reporter = reporter
            created_reporter = False
            if local_reporter is None and not basefwx._SILENT_MODE:
                local_reporter = basefwx._ProgressReporter(1)
                created_reporter = True
            try:
                hw_plan: "basefwx.typing.Optional[dict[str, basefwx.typing.Any]]" = None

                def _ensure_hw_plan(
                    stream_type: str,
                    *,
                    frame_bytes: int = 0,
                    allow_pixel_gpu: bool = False,
                    prefer_cpu_decode: bool = True,
                ) -> "dict[str, basefwx.typing.Any]":
                    nonlocal hw_plan
                    if hw_plan is None:
                        hw_plan = basefwx.MediaCipher._build_hw_execution_plan(
                            "jMGd",
                            stream_type=stream_type,
                            frame_bytes=frame_bytes,
                            allow_pixel_gpu=allow_pixel_gpu,
                            prefer_cpu_decode=prefer_cpu_decode,
                        )
                        basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
                    return hw_plan

                suffix = path_obj.suffix.lower()
                if suffix in basefwx.MediaCipher.IMAGE_EXTS:
                    _ensure_hw_plan("image")
                    result = basefwx.ImageCipher.decrypt_image_inv(
                        str(path_obj),
                        password,
                        output=str(temp_output)
                    )
                else:
                    result = ""
                    fallback_ok = False
                    cached_bytes: "basefwx.typing.Optional[bytes]" = None
                    base_key_from_trailer: "basefwx.typing.Optional[bytes]" = None
                    trailer_profile = basefwx.JMG_SECURITY_PROFILE_LEGACY

                    try:
                        fallback_ok = path_obj.stat().st_size <= basefwx.MediaCipher.TRAILER_FALLBACK_MAX
                    except Exception:
                        fallback_ok = False

                    def _load_cached_bytes() -> bytes:
                        nonlocal cached_bytes
                        if cached_bytes is None:
                            cached_bytes = path_obj.read_bytes()
                        return cached_bytes

                    def trailer_cb(frac: float) -> None:
                        if local_reporter:
                            local_reporter.update(file_index, 0.05 + 0.90 * frac, "archive", display_path)

                    if basefwx.MediaCipher._decrypt_trailer_stream(
                        path_obj,
                        password,
                        temp_output,
                        progress_cb=trailer_cb if local_reporter else None
                    ):
                        result = str(temp_output)
                    elif fallback_ok:
                        plain = basefwx.MediaCipher._decrypt_trailer(_load_cached_bytes(), password)
                        if plain is not None:
                            temp_output.write_bytes(plain)
                            result = str(temp_output)
                    if not result:
                        trailer_key_info = basefwx.MediaCipher._load_base_key_from_key_trailer(path_obj, password)
                        if trailer_key_info is not None:
                            base_key_from_trailer, trailer_profile = trailer_key_info
                        if base_key_from_trailer is None and fallback_ok:
                            trailer_key_info = basefwx.MediaCipher._load_base_key_from_key_trailer_bytes(
                                _load_cached_bytes(),
                                password
                            )
                            if trailer_key_info is not None:
                                base_key_from_trailer, trailer_profile = trailer_key_info
                        if base_key_from_trailer is not None:
                            _warnings_module.warn(
                                "jMG no-archive payload detected; restored media may not be byte-identical "
                                "to the original input.",
                                UserWarning
                            )
                        try:
                            info = basefwx.MediaCipher._probe_streams(path_obj)
                        except Exception:
                            info = {}
                        if info.get("video"):
                            frame_bytes = int((info.get("video") or {}).get("width") or 0) * int(
                                (info.get("video") or {}).get("height") or 0
                            ) * 3
                            plan = _ensure_hw_plan(
                                "video",
                                frame_bytes=frame_bytes,
                                allow_pixel_gpu=True,
                                prefer_cpu_decode=True,
                            )
                            basefwx.MediaCipher._unscramble_video(
                                path_obj,
                                temp_output,
                                password,
                                base_key=base_key_from_trailer,
                                security_profile=trailer_profile,
                                reporter=local_reporter,
                                file_index=file_index,
                                display_path=display_path,
                                hw_plan=plan,
                            )
                            result = str(temp_output)
                        elif info.get("audio"):
                            _ensure_hw_plan("audio")
                            basefwx.MediaCipher._unscramble_audio(
                                path_obj,
                                temp_output,
                                password,
                                base_key=base_key_from_trailer,
                                security_profile=trailer_profile,
                                reporter=local_reporter,
                                file_index=file_index,
                                display_path=display_path
                            )
                            result = str(temp_output)
                        else:
                            _ensure_hw_plan("bytes")
                            fallback_out = output_path if output else path_obj.with_suffix("")
                            can_fwx = path_obj.suffix.lower() == ".fwx"
                            if not can_fwx:
                                try:
                                    with open(path_obj, "rb") as handle:
                                        can_fwx = handle.read(4) == basefwx.FWXAES_MAGIC
                                except Exception:
                                    can_fwx = False
                            if can_fwx:
                                return basefwx.fwxAES_file(
                                    str(path_obj),
                                    password,
                                    use_master=True,
                                    output=str(fallback_out),
                                    ignore_media=True
                                )
                            raise ValueError("Unsupported media format")
                if local_reporter:
                    local_reporter.update(file_index, 1.0, "done", display_path)
            finally:
                if created_reporter and local_reporter:
                    local_reporter.reset_terminal_state()

            if basefwx._normalize_path(output_path) != basefwx._normalize_path(temp_output):
                basefwx.os.replace(temp_output, output_path)
                temp_output = output_path
            return str(temp_output)
    def _aes_light_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            pack_flag: str = "",
            output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            keep_input: bool = False
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        display_path = display_path or path
        output_path = output_path or path.with_suffix('.fwx')
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        obfuscate_payload = input_size <= basefwx.STREAM_THRESHOLD
        chunk_size = max(3, basefwx.STREAM_CHUNK_SIZE)
        buffer = bytearray()
        processed = 0
        total = input_size
        b64_parts: "basefwx.typing.List[str]" = []
        with open(path, 'rb') as src_handle:
            while True:
                chunk = src_handle.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                processed += len(chunk)
                take_len = (len(buffer) // 3) * 3
                if take_len:
                    part = basefwx.base64.b64encode(buffer[:take_len]).decode('ascii')
                    b64_parts.append(part)
                    del buffer[:take_len]
                if reporter and total:
                    fraction = 0.05 + 0.20 * (processed / total)
                    reporter.update(file_index, fraction, "base64", display_path)
        if buffer:
            b64_parts.append(basefwx.base64.b64encode(buffer).decode('ascii'))
        b64_payload = ''.join(b64_parts)
        basefwx._del('b64_parts')
        basefwx._del('buffer')
        if reporter:
            reporter.update(file_index, 0.25, "base64", display_path)
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        fast_obf = obfuscate_payload and not strip_metadata and basefwx._use_fast_obfuscation(input_size)
        obf_mode = "fast" if fast_obf else ("yes" if obfuscate_payload else "no")
        metadata_blob = basefwx._build_metadata(
            "AES-LIGHT",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            obfuscation=obf_mode,
            pack=pack_flag or None
        )
        body = (path.suffix or "") + basefwx.FWX_DELIM + b64_payload
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body

        plain_bytes_len = len(plaintext.encode('utf-8'))
        est_cipher_len = basefwx.AEAD_NONCE_LEN + plain_bytes_len + basefwx.AEAD_TAG_LEN
        progress_cb = None
        if reporter:
            enc_hint = (input_size, est_cipher_len)

            def _enc_progress(done: int, total: int) -> None:
                fraction = 0.55 + 0.41 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", display_path, size_hint=enc_hint)

            progress_cb = _enc_progress

        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used,
            progress_callback=progress_cb,
            obfuscate=obfuscate_payload,
            fast_obfuscation=fast_obf
        )
        compressor = basefwx.zlib.compressobj()
        compressed_parts: "basefwx.typing.List[bytes]" = []
        total_cipher = len(ciphertext)
        processed_cipher = 0
        chunk_size_enc = basefwx.STREAM_CHUNK_SIZE
        for offset in range(0, total_cipher, chunk_size_enc):
            chunk = ciphertext[offset:offset + chunk_size_enc]
            comp = compressor.compress(chunk)
            if comp:
                compressed_parts.append(comp)
            processed_cipher += len(chunk)
            if reporter and total_cipher:
                fraction = 0.8 + 0.12 * (processed_cipher / total_cipher)
                reporter.update(file_index, min(fraction, 0.92), "compress", display_path)
        tail = compressor.flush()
        if tail:
            compressed_parts.append(tail)
        compressed = b"".join(compressed_parts)
        basefwx._del('compressed_parts')
        output_len = len(compressed)
        size_hint = (input_size, output_len)

        if reporter:
            reporter.update(file_index, 0.92, "compress", display_path, size_hint=size_hint)
        with open(output_path, 'wb') as handle:
            handle.write(compressed)
        basefwx._del('ciphertext')
        basefwx._del('compressed')

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx._remove_input(path, keep_input, output_path)

        if reporter:
            reporter.update(file_index, 1.0, "done", output_path, size_hint=size_hint)
            reporter.finalize_file(file_index, output_path, size_hint=size_hint)

        return output_path, output_len

    @staticmethod
    def _aes_light_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        compressed = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "decompress", path)

        try:
            ciphertext = basefwx.zlib.decompress(compressed)
        except basefwx.zlib.error as exc:
            raise ValueError("Compressed FWX payload is corrupted") from exc

        decrypt_progress = None
        if reporter:
            def _dec_progress(done: int, total: int) -> None:
                fraction = 0.55 + 0.20 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", path)

            decrypt_progress = _dec_progress

        use_master_effective = use_master and not strip_metadata
        plaintext = basefwx.decryptAES(
            ciphertext,
            password,
            use_master=use_master_effective,
            progress_callback=decrypt_progress
        )
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        meta = basefwx._decode_metadata(metadata_blob)
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "AES-LIGHT")
        basefwx._warn_on_metadata(meta, "AES-LIGHT")

        try:
            ext, b64_payload = basefwx._split_with_delims(
                payload,
                (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM),
                "FWX payload"
            )
        except ValueError as exc:
            raise ValueError("Malformed FWX light payload") from exc

        if reporter:
            reporter.update(file_index, 0.75, "base64", path)

        raw = basefwx.base64.b64decode(b64_payload)
        pack_flag = basefwx._pack_flag_from_meta(meta, ext)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if pack_flag:
            target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
        elif strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(raw)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 1.0, "done", target, size_hint=size_hint)
            reporter.finalize_file(file_index, target, size_hint=size_hint)

        return target, output_len
    @staticmethod
    def _aes_heavy_decode_path_stream(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            meta_preview: "basefwx.typing.Optional[basefwx.typing.Dict[str, basefwx.typing.Any]]" = None,
            metadata_blob_preview: str = "",
            *,
            input_size: "basefwx.typing.Optional[int]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        if not password:
            raise ValueError("Password required for AES heavy streaming mode")
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        input_size = input_size if input_size is not None else path.stat().st_size
        meta = meta_preview or {}
        metadata_blob = metadata_blob_preview or ""
        use_master_effective = use_master and not strip_metadata
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "AES-HEAVY")

        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-stream-dec-")
        cleanup_paths: "basefwx.typing.List[str]" = []
        plaintext_path: "basefwx.typing.Optional[str]" = None
        decoded_path: "basefwx.typing.Optional[str]" = None
        metadata_bytes: bytes = metadata_blob.encode('utf-8') if metadata_blob else b""
        aad = metadata_bytes if metadata_bytes else b""
        def _parse_int(value: "basefwx.typing.Any", default: "basefwx.typing.Optional[int]") -> "basefwx.typing.Optional[int]":
            if value is None:
                return default
            try:
                return int(value)
            except (TypeError, ValueError):
                return default
        kdf_hint = (meta.get("ENC-KDF") or basefwx.USER_KDF or "argon2id").lower()
        kdf_iter_hint = _parse_int(meta.get("ENC-KDF-ITER"), basefwx.USER_KDF_ITERATIONS)
        argon2_time_hint = _parse_int(meta.get("ENC-ARGON2-TC"), None)
        argon2_mem_hint = _parse_int(meta.get("ENC-ARGON2-MEM"), None)
        argon2_par_hint = _parse_int(meta.get("ENC-ARGON2-PAR"), None)
        try:
            with open(path, 'rb') as handle:
                len_user_bytes = handle.read(4)
                if len(len_user_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_user = int.from_bytes(len_user_bytes, 'big')
                user_blob = handle.read(len_user)
                if len(user_blob) != len_user:
                    raise ValueError("Ciphertext payload truncated")
                len_master_bytes = handle.read(4)
                if len(len_master_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_master = int.from_bytes(len_master_bytes, 'big')
                master_blob = handle.read(len_master)
                if len(master_blob) != len_master:
                    raise ValueError("Ciphertext payload truncated")
                len_payload_bytes = handle.read(4)
                if len(len_payload_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                len_payload = int.from_bytes(len_payload_bytes, 'big')
                if len_payload < 4 + basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN:
                    raise ValueError("Ciphertext payload truncated")
                metadata_len_bytes = handle.read(4)
                if len(metadata_len_bytes) < 4:
                    raise ValueError("Ciphertext payload truncated")
                metadata_len = int.from_bytes(metadata_len_bytes, 'big')
                metadata_bytes_disk = handle.read(metadata_len)
                if len(metadata_bytes_disk) != metadata_len:
                    raise ValueError("Ciphertext payload truncated")
                if metadata_bytes:
                    if metadata_bytes_disk != metadata_bytes:
                        raise ValueError("Metadata integrity mismatch detected")
                else:
                    metadata_bytes = metadata_bytes_disk
                    aad = metadata_bytes if metadata_bytes else b""
                nonce = handle.read(basefwx.AEAD_NONCE_LEN)
                if len(nonce) != basefwx.AEAD_NONCE_LEN:
                    raise ValueError("Ciphertext payload truncated")
                cipher_body_len = len_payload - 4 - len(metadata_bytes) - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                if cipher_body_len < 0:
                    raise ValueError("Ciphertext payload truncated")
                cipher_body_start = handle.tell()
                handle.seek(cipher_body_len, basefwx.os.SEEK_CUR)
                tag = handle.read(basefwx.AEAD_TAG_LEN)
                if len(tag) != basefwx.AEAD_TAG_LEN:
                    raise ValueError("Ciphertext payload truncated")
                handle.seek(cipher_body_start)

                if len(master_blob) > 0:
                    if not use_master_effective:
                        raise ValueError("Master key required to decrypt this payload")
                    private_key = basefwx._load_master_pq_private()
                    kem_shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
                    ephemeral_key = basefwx._kem_derive_key(kem_shared)
                elif len(user_blob) > 0:
                    if not password:
                        raise ValueError("User password required to decrypt this payload")
                    min_len = basefwx.USER_KDF_SALT_SIZE + 13
                    if len(user_blob) < min_len:
                        raise ValueError("Corrupted user key blob: missing salt or AEAD data")
                    user_salt = user_blob[:basefwx.USER_KDF_SALT_SIZE]
                    wrapped_ephemeral = user_blob[basefwx.USER_KDF_SALT_SIZE:]
                    user_derived_key, _ = basefwx._derive_user_key(
                        password,
                        salt=user_salt,
                        iterations=kdf_iter_hint or basefwx.USER_KDF_ITERATIONS,
                        kdf=kdf_hint,
                        argon2_time_cost=argon2_time_hint,
                        argon2_memory_cost=argon2_mem_hint,
                        argon2_parallelism=argon2_par_hint
                    )
                    ephemeral_key = basefwx._aead_decrypt(user_derived_key, wrapped_ephemeral, aad)
                else:
                    raise ValueError("Ciphertext missing key transport data")

                decryptor = basefwx.Cipher(
                    basefwx.algorithms.AES(ephemeral_key),
                    basefwx.modes.GCM(nonce, tag)
                ).decryptor()
                if aad:
                    decryptor.authenticate_additional_data(aad)
                if reporter:
                    reporter.update(file_index, 0.35, "AES512", path)
                with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as plain_tmp:
                    cleanup_paths.append(plain_tmp.name)
                    plaintext_path = plain_tmp.name
                    remaining = cipher_body_len
                    chunk_size = basefwx.STREAM_CHUNK_SIZE
                    processed = 0
                    while remaining > 0:
                        take = min(chunk_size, remaining)
                        chunk = handle.read(take)
                        if len(chunk) != take:
                            raise ValueError("Ciphertext truncated")
                        plain_chunk = decryptor.update(chunk)
                        if plain_chunk:
                            plain_tmp.write(plain_chunk)
                        remaining -= take
                        processed += take
                        if reporter:
                            fraction = 0.35 + 0.25 * (processed / cipher_body_len if cipher_body_len else 1.0)
                            reporter.update(file_index, fraction, "AES512", path)
                    final_chunk = decryptor.finalize()
                    if final_chunk:
                        plain_tmp.write(final_chunk)

            basefwx._del('ephemeral_key')
            basefwx._del('user_derived_key')
            basefwx._del('kem_shared')

            if plaintext_path is None:
                raise RuntimeError("Streaming decrypt failed to produce plaintext")

            with open(plaintext_path, 'rb') as plain_handle:
                if metadata_bytes:
                    expected_prefix = metadata_bytes
                    prefix = plain_handle.read(len(expected_prefix))
                    if prefix != expected_prefix:
                        raise ValueError("Metadata integrity mismatch detected")
                    delim_bytes = basefwx.META_DELIM.encode('utf-8')
                    delim = plain_handle.read(len(delim_bytes))
                    if delim != delim_bytes:
                        raise ValueError("Malformed streaming payload: missing metadata delimiter")
                stream_magic = plain_handle.read(len(basefwx.STREAM_MAGIC))
                if stream_magic != basefwx.STREAM_MAGIC:
                    raise ValueError("Malformed streaming payload: magic mismatch")
                chunk_size_bytes = plain_handle.read(4)
                if len(chunk_size_bytes) != 4:
                    raise ValueError("Malformed streaming payload: missing chunk size")
                chunk_size_value = int.from_bytes(chunk_size_bytes, 'big')
                if chunk_size_value <= 0 or chunk_size_value > (16 << 20):
                    chunk_size_value = basefwx.STREAM_CHUNK_SIZE
                original_size_bytes = plain_handle.read(8)
                if len(original_size_bytes) != 8:
                    raise ValueError("Malformed streaming payload: missing original size")
                original_size = int.from_bytes(original_size_bytes, 'big')
                stream_salt = plain_handle.read(basefwx._StreamObfuscator._SALT_LEN)
                if len(stream_salt) != basefwx._StreamObfuscator._SALT_LEN:
                    raise ValueError("Malformed streaming payload: missing salt")
                ext_len_bytes = plain_handle.read(2)
                if len(ext_len_bytes) != 2:
                    raise ValueError("Malformed streaming payload: missing extension length")
                ext_len = int.from_bytes(ext_len_bytes, 'big')
                ext_bytes = plain_handle.read(ext_len)
                if len(ext_bytes) != ext_len:
                    raise ValueError("Malformed streaming payload: truncated extension")
                data_start = plain_handle.tell()

                with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as clear_tmp:
                    cleanup_paths.append(clear_tmp.name)
                    decoded_path = clear_tmp.name
                    processed = 0
                    obf_hint = (meta.get("ENC-OBF") or "yes").lower()
                    fast_obf = obf_hint == "fast"
                    decoder = basefwx._StreamObfuscator.for_password(password, stream_salt, fast=fast_obf)
                    while processed < original_size:
                        to_read = min(chunk_size_value, original_size - processed)
                        chunk = plain_handle.read(to_read)
                        if len(chunk) != to_read:
                            raise ValueError("Streaming payload truncated")
                        clear_chunk = decoder.decode_chunk(chunk)
                        clear_tmp.write(clear_chunk)
                        processed += len(clear_chunk)
                        if reporter:
                            fraction = 0.7 + 0.2 * (processed / original_size if original_size else 1.0)
                            reporter.update(file_index, fraction, "deobfuscate", path)
                    leftover = plain_handle.read(1)
                    if leftover:
                        raise ValueError("Streaming payload contained unexpected trailing data")

            target = path.with_suffix('')
            ext_text = ""
            if ext_bytes:
                try:
                    ext_text = ext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    ext_text = ""
                if ext_text:
                    target = target.with_suffix(ext_text)
            pack_flag = basefwx._pack_flag_from_meta(meta, ext_text)

            if decoded_path is None:
                raise RuntimeError("Missing decoded payload")
            basefwx.os.replace(decoded_path, target)
            cleanup_paths.remove(decoded_path)
            basefwx.os.remove(path)
            if plaintext_path and plaintext_path in cleanup_paths:
                basefwx.os.remove(plaintext_path)
                cleanup_paths.remove(plaintext_path)
            if pack_flag:
                target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
            elif strip_metadata:
                basefwx._apply_strip_attributes(target)
            output_len = original_size
            size_hint = (input_size, output_len)
            if reporter:
                reporter.update(file_index, 1.0, "done", target, size_hint=size_hint)
                reporter.finalize_file(file_index, target, size_hint=size_hint)
            return target, output_len
        finally:
            for temp_path in cleanup_paths:
                try:
                    basefwx.os.remove(temp_path)
                except FileNotFoundError:
                    pass
            temp_dir.cleanup()

    @staticmethod
    def _aes_heavy_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            pack_flag: str = "",
            output_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            display_path: "basefwx.typing.Optional[basefwx.pathlib.Path]" = None,
            keep_input: bool = False
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        display_path = display_path or path
        output_path = output_path or path.with_suffix('.fwx')
        input_size = path.stat().st_size
        approx_b64_len = ((input_size + 2) // 3) * 4
        if input_size >= basefwx.STREAM_THRESHOLD or approx_b64_len > basefwx.HKDF_MAX_LEN:
            return basefwx._aes_heavy_encode_path_stream(
                path,
                password,
                reporter,
                file_index,
                strip_metadata,
                use_master,
                master_pubkey,
                pack_flag=pack_flag,
                output_path=output_path,
                display_path=display_path,
                input_size=input_size,
                keep_input=keep_input
            )
        estimated_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", display_path)

        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", display_path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        ext_token = basefwx.pb512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.55, "pb512", display_path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(input_size)
        obf_mode = "fast" if fast_obf else "yes"
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            obfuscation=obf_mode,
            kdf_iters=heavy_iters,
            argon2_time_cost=heavy_argon_time,
            argon2_memory_cost=heavy_argon_mem,
            argon2_parallelism=heavy_argon_par,
            pack=pack_flag or None
        )
        body = f"{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}"
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        metadata_bytes_len = len(metadata_blob.encode('utf-8')) if metadata_blob else 0
        plaintext_bytes_len = len(plaintext.encode('utf-8'))
        estimated_len = basefwx._estimate_aead_blob_size(
            plaintext_bytes_len,
            metadata_bytes_len,
            include_user=bool(password),
            include_master=use_master_effective
        )
        estimated_hint = (input_size, estimated_len)
        progress_cb = None
        if reporter:

            def _enc_progress(done: int, total: int) -> None:
                fraction = 0.55 + 0.40 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", display_path, size_hint=estimated_hint)

            progress_cb = _enc_progress
        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used,
            progress_callback=progress_cb,
            kdf_iterations=heavy_iters,
            argon2_time_cost=heavy_argon_time,
            argon2_memory_cost=heavy_argon_mem,
            argon2_parallelism=heavy_argon_par,
            fast_obfuscation=fast_obf
        )
        approx_size = len(ciphertext)
        actual_hint = (input_size, approx_size)

        with open(output_path, 'wb') as handle:
            handle.write(ciphertext)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx._remove_input(path, keep_input, output_path)

        if reporter:
            reporter.update(file_index, 1.0, "done", output_path, size_hint=actual_hint)
            reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
        else:
            # Only print size info if no progress reporter (to avoid corrupting progress display)
            human = basefwx._human_readable_size(approx_size)
            if not basefwx._SILENT_MODE:
                print(f"{output_path.name}: approx output size {human}")

        return output_path, approx_size

    @staticmethod
    def _aes_heavy_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        metadata_blob_preview = ""
        meta_preview: "basefwx.typing.Dict[str, basefwx.typing.Any]" = {}
        with open(path, 'rb') as preview:
            len_user_bytes = preview.read(4)
            if len(len_user_bytes) < 4:
                raise ValueError("Ciphertext payload truncated")
            len_user = int.from_bytes(len_user_bytes, 'big')
            preview.seek(len_user, basefwx.os.SEEK_CUR)
            len_master_bytes = preview.read(4)
            if len(len_master_bytes) < 4:
                raise ValueError("Ciphertext payload truncated")
            len_master = int.from_bytes(len_master_bytes, 'big')
            preview.seek(len_master, basefwx.os.SEEK_CUR)
            len_payload_bytes = preview.read(4)
            if len(len_payload_bytes) < 4:
                raise ValueError("Ciphertext payload truncated")
            len_payload = int.from_bytes(len_payload_bytes, 'big')
            if len_payload < 4:
                raise ValueError("Ciphertext payload truncated")
            metadata_len_bytes = preview.read(4)
            if len(metadata_len_bytes) < 4:
                raise ValueError("Ciphertext payload truncated")
            metadata_len = int.from_bytes(metadata_len_bytes, 'big')
            metadata_bytes_preview = preview.read(metadata_len)
            try:
                metadata_blob_preview = metadata_bytes_preview.decode('utf-8') if metadata_bytes_preview else ""
            except UnicodeDecodeError:
                metadata_blob_preview = ""
            meta_preview = basefwx._decode_metadata(metadata_blob_preview)
        mode_hint = (meta_preview.get("ENC-MODE") or "").lower()
        if mode_hint == "stream":
            return basefwx._aes_heavy_decode_path_stream(
                path,
                password,
                reporter,
                file_index,
                strip_metadata,
                use_master,
                meta_preview,
                metadata_blob_preview,
                input_size=input_size
            )

        ciphertext = path.read_bytes()

        use_master_effective = use_master and not strip_metadata
        decrypt_progress = None
        if reporter:
            def _dec_progress(done: int, total: int) -> None:
                fraction = 0.35 + 0.25 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", path)

            decrypt_progress = _dec_progress
        plaintext = basefwx.decryptAES(
            ciphertext,
            password,
            use_master=use_master_effective,
            progress_callback=decrypt_progress
        )
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        meta = basefwx._decode_metadata(metadata_blob)
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "AES-HEAVY")

        ext_token, data_token = basefwx._split_with_delims(
            payload,
            (basefwx.FWX_HEAVY_DELIM, basefwx.LEGACY_FWX_HEAVY_DELIM),
            "FWX heavy"
        )

        if reporter:
            reporter.update(file_index, 0.6, "pb512", path)

        ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
        data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.8, "base64", path)

        raw = basefwx.base64.b64decode(data_b64)
        pack_flag = basefwx._pack_flag_from_meta(meta, ext)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if pack_flag:
            target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
        elif strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(raw)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 1.0, "done", target, size_hint=size_hint)
            reporter.finalize_file(file_index, target, size_hint=size_hint)

        return target, output_len

    @staticmethod
    def AESfile(
            files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]",
            password: str = "",
            light: bool = True,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None,
            silent: bool = False,
            compress: bool = False,
            keep_input: bool = False
    ):
        basefwx.sys.set_int_max_str_digits(2000000000)
        paths = basefwx._coerce_file_list(files)

        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            master_pubkey,
            create_if_missing=True
        )
        encode_use_master = (use_master and not strip_metadata) and master_available
        decode_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=encode_use_master)
        except Exception as exc:
            if not silent:
                print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        previous_silent = basefwx._SILENT_MODE
        basefwx._SILENT_MODE = silent
        try:
            reporter = basefwx._ProgressReporter(len(paths)) if not silent else None
            results: dict[str, str] = {}

            def _process_with_reporter(idx: int, path: "basefwx.pathlib.Path") -> tuple[str, str]:
                try:
                    if not path.exists():
                        if reporter:
                            reporter.update(idx, 0.0, "missing", path)
                            reporter.finalize_file(idx, path)
                        return str(path), "FAIL!"
                    if path.suffix.lower() == ".fwx" and path.is_file():
                        if light:
                            basefwx._aes_light_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                        else:
                            basefwx._aes_heavy_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                    else:
                        pack_ctx = basefwx._pack_input_to_archive(path, compress, reporter, idx)
                        pack_flag = pack_ctx[1] if pack_ctx else ""
                        pack_temp = pack_ctx[2] if pack_ctx else None
                        source_path = pack_ctx[0] if pack_ctx else path
                        try:
                            if light:
                                basefwx._aes_light_encode_path(
                                    source_path,
                                    resolved_password,
                                    reporter,
                                    idx,
                                    strip_metadata,
                                    encode_use_master,
                                    pubkey_bytes,
                                    pack_flag=pack_flag,
                                    output_path=path.with_suffix('.fwx'),
                                    display_path=path,
                                    keep_input=keep_input
                                )
                            else:
                                basefwx._aes_heavy_encode_path(
                                    source_path,
                                    resolved_password,
                                    reporter,
                                    idx,
                                    strip_metadata,
                                    encode_use_master,
                                    pubkey_bytes,
                                    pack_flag=pack_flag,
                                    output_path=path.with_suffix('.fwx'),
                                    display_path=path,
                                    keep_input=keep_input
                                )
                            if pack_ctx:
                                basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                        finally:
                            if pack_temp is not None:
                                pack_temp.cleanup()
                    return str(path), "SUCCESS!"
                except KeyboardInterrupt:
                    if reporter:
                        reporter.update(idx, 0.0, "cancelled", path)
                        reporter.finalize_file(idx, path)
                    raise
                except Exception as exc:
                    if reporter:
                        reporter.update(idx, 0.0, f"error: {exc}", path)
                        reporter.finalize_file(idx, path)
                    return str(path), "FAIL!"

            def _process_without_reporter(path: "basefwx.pathlib.Path") -> tuple[str, str]:
                try:
                    if not path.exists():
                        return str(path), "FAIL!"
                    if path.suffix.lower() == ".fwx" and path.is_file():
                        if light:
                            basefwx._aes_light_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                        else:
                            basefwx._aes_heavy_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                    else:
                        pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
                        pack_flag = pack_ctx[1] if pack_ctx else ""
                        pack_temp = pack_ctx[2] if pack_ctx else None
                        source_path = pack_ctx[0] if pack_ctx else path
                        try:
                            if light:
                                basefwx._aes_light_encode_path(
                                    source_path,
                                    resolved_password,
                                    None,
                                    0,
                                    strip_metadata,
                                    encode_use_master,
                                    pubkey_bytes,
                                    pack_flag=pack_flag,
                                    output_path=path.with_suffix('.fwx'),
                                    display_path=path,
                                    keep_input=keep_input
                                )
                            else:
                                basefwx._aes_heavy_encode_path(
                                    source_path,
                                    resolved_password,
                                    None,
                                    0,
                                    strip_metadata,
                                    encode_use_master,
                                    pubkey_bytes,
                                    pack_flag=pack_flag,
                                    output_path=path.with_suffix('.fwx'),
                                    display_path=path,
                                    keep_input=keep_input
                                )
                            if pack_ctx:
                                basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                        finally:
                            if pack_temp is not None:
                                pack_temp.cleanup()
                    return str(path), "SUCCESS!"
                except KeyboardInterrupt:
                    raise
                except Exception:
                    return str(path), "FAIL!"

            use_parallel = len(paths) > 1 and basefwx._CPU_COUNT > 1
            if use_parallel:
                max_workers = min(len(paths), basefwx._CPU_COUNT)
                executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
                futures: "dict[basefwx.concurrent.futures.Future, tuple[int | None, basefwx.pathlib.Path]]" = {}
                shutdown_now = False
                try:
                    if reporter:
                        for idx, path in enumerate(paths):
                            futures[executor.submit(_process_with_reporter, idx, path)] = (idx, path)
                    else:
                        for path in paths:
                            futures[executor.submit(_process_without_reporter, path)] = (None, path)
                    try:
                        for future in basefwx.concurrent.futures.as_completed(futures):
                            file_id, status = future.result()
                            results[file_id] = status
                    except KeyboardInterrupt:
                        shutdown_now = True
                        for future, meta in futures.items():
                            if not future.done():
                                future.cancel()
                                idx, rest_path = meta
                                if reporter and idx is not None:
                                    reporter.update(idx, 0.0, "cancelled", rest_path)
                                    reporter.finalize_file(idx, rest_path)
                                results[str(rest_path)] = "CANCELLED"
                        executor.shutdown(wait=False, cancel_futures=True)
                        if len(paths) == 1:
                            return "CANCELLED"
                        return results
                finally:
                    executor.shutdown(wait=not shutdown_now, cancel_futures=True)
            else:
                try:
                    for idx, path in enumerate(paths):
                        try:
                            file_id, status = _process_with_reporter(idx, path)
                            results[file_id] = status
                        except KeyboardInterrupt:
                            results[str(path)] = "CANCELLED"
                            raise
                except KeyboardInterrupt:
                    for idx, rest_path in enumerate(paths):
                        key = str(rest_path)
                        if key not in results:
                            if reporter:
                                reporter.update(idx, 0.0, "cancelled", rest_path)
                                reporter.finalize_file(idx, rest_path)
                            results[key] = "CANCELLED"
                    if len(paths) == 1:
                        return "CANCELLED"
                    return results

            # Reset the terminal state before returning results
            if reporter:
                reporter.reset_terminal_state()
                
            if len(paths) == 1:
                return next(iter(results.values()))
            return results
        finally:
            basefwx._SILENT_MODE = previous_silent

    @classmethod
    def _code_chunk(cls, chunk: str) -> str:
        if chunk.isascii():
            return chunk.translate(cls._CODE_TRANSLATION_TABLE)
        return chunk.translate(cls._CODE_TRANSLATION)

    @classmethod
    def code(cls, string: str) -> str:
        if not string:
            return string
        return cls._code_chunk(string)

    @classmethod
    def fwx256bin(cls, string: str) -> str:
        raw = cls.code(string).encode('utf-8')
        padding_count = cls._b32_padding_count(len(raw))
        # Use fast NumPy encoder for large data
        if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
            encoded = cls._fast_b32hexencode(raw)
        else:
            encoded = cls.base64.b32hexencode(raw)
        if padding_count:
            encoded = encoded[:-padding_count]
        return encoded.decode('utf-8') + str(padding_count)

    @classmethod
    def _fwx256bin_bytes(cls, string: str) -> bytes:
        raw = cls.code(string).encode('utf-8')
        padding_count = cls._b32_padding_count(len(raw))
        # Use fast NumPy encoder for large data
        if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
            encoded = cls._fast_b32hexencode(raw)
        else:
            encoded = cls.base64.b32hexencode(raw)
        if padding_count:
            encoded = encoded[:-padding_count]
        return encoded + str(padding_count).encode('ascii')

    @staticmethod
    def _b32_padding_count(length: int) -> int:
        if length <= 0:
            return 0
        rem = length % 5
        if rem == 0:
            return 0
        if rem == 1:
            return 6
        if rem == 2:
            return 4
        if rem == 3:
            return 3
        return 1

    @staticmethod
    def _strip_leading_zeros(number: str) -> str:
        if not number:
            return "0"
        stripped = number.lstrip("0")
        return stripped if stripped else "0"

    @staticmethod
    def _compare_magnitude(a: str, b: str) -> int:
        aa = basefwx._strip_leading_zeros(a)
        bb = basefwx._strip_leading_zeros(b)
        if len(aa) != len(bb):
            return -1 if len(aa) < len(bb) else 1
        if aa == bb:
            return 0
        return -1 if aa < bb else 1

    @staticmethod
    def _decimal_diff(a: str, b: str) -> str:
        # For large decimal strings, string-based arithmetic is O(n) while
        # int conversion + str() is O(n²) due to Python's division algorithm.
        # Use native int only for small numbers where the constant factor wins.
        if len(a) <= 1000 and len(b) <= 1000:
            try:
                ai = int(a)
                bi = int(b)
                if ai >= bi:
                    return str(ai - bi)
                return "0" + str(bi - ai)
            except (ValueError, OverflowError, MemoryError):
                pass
        # O(n) string-based subtraction for large numbers
        cmp = basefwx._compare_magnitude(a, b)
        if cmp >= 0:
            return basefwx._subtract_magnitude(a, b)
        return "0" + basefwx._subtract_magnitude(b, a)

    @staticmethod
    def _add_magnitude(a: str, b: str) -> str:
        # Convert to bytes once to avoid per-character ord() calls
        ab = a.encode('ascii')
        bb = b.encode('ascii')
        ia = len(ab) - 1
        ib = len(bb) - 1
        carry = 0
        max_len = max(len(ab), len(bb)) + 1
        out = bytearray(max_len)
        pos = max_len - 1
        while ia >= 0 or ib >= 0 or carry:
            da = ab[ia] - 48 if ia >= 0 else 0
            db = bb[ib] - 48 if ib >= 0 else 0
            total = da + db + carry
            out[pos] = 48 + (total % 10)
            carry = total // 10
            ia -= 1
            ib -= 1
            pos -= 1
        idx = pos + 1
        while idx < max_len and out[idx] == 48:
            idx += 1
        if idx == max_len:
            return "0"
        return out[idx:].decode('ascii')

    @staticmethod
    def _subtract_magnitude(a: str, b: str) -> str:
        """Decimal string subtraction (a >= b assumed). Uses NumPy for large inputs."""
        len_a = len(a)
        len_b = len(b)

        # Use NumPy for large numbers (90x faster)
        if basefwx.np is not None and len_a >= 1000:
            np = basefwx.np
            arr_a = np.frombuffer(a.encode('ascii'), dtype=np.uint8).astype(np.int16) - 48
            arr_b = np.zeros(len_a, dtype=np.int16)
            if len_b > 0:
                arr_b[-len_b:] = np.frombuffer(b.encode('ascii'), dtype=np.uint8) - 48

            result = arr_a - arr_b

            # Vectorized borrow propagation
            while True:
                mask = result < 0
                if not np.any(mask):
                    break
                borrow_from = np.where(mask)[0] - 1
                borrow_from = borrow_from[borrow_from >= 0]
                result[mask] += 10
                np.subtract.at(result, borrow_from, 1)

            out = (result.astype(np.uint8) + 48).tobytes()
            idx = 0
            while idx < len_a - 1 and out[idx] == 48:
                idx += 1
            return out[idx:].decode('ascii')

        # Original byte-based loop for small numbers
        ab = a.encode('ascii')
        bb = b.encode('ascii')
        ia = len_a - 1
        ib = len_b - 1
        borrow = 0
        out = bytearray(len_a)
        pos = len_a - 1
        while ia >= 0:
            da = ab[ia] - 48 - borrow
            db = bb[ib] - 48 if ib >= 0 else 0
            if da < db:
                da += 10
                borrow = 1
            else:
                borrow = 0
            out[pos] = 48 + (da - db)
            ia -= 1
            ib -= 1
            pos -= 1
        idx = 0
        while idx < len_a and out[idx] == 48:
            idx += 1
        if idx == len_a:
            return "0"
        return out[idx:].decode('ascii')

    @staticmethod
    def _add_signed(a: str, b: str) -> str:
        def parse_signed(value: str) -> tuple[bool, str]:
            if not value:
                return False, "0"
            negative = value[0] == "-"
            digits = value[1:] if negative else value
            digits = basefwx._strip_leading_zeros(digits)
            if digits == "0":
                negative = False
            return negative, digits

        neg_a, da = parse_signed(a)
        neg_b, db = parse_signed(b)
        if neg_a == neg_b:
            total = basefwx._add_magnitude(da, db)
            return ("-" + total) if neg_a and total != "0" else total
        cmp = basefwx._compare_magnitude(da, db)
        if cmp == 0:
            return "0"
        if cmp > 0:
            diff = basefwx._subtract_magnitude(da, db)
            return ("-" + diff) if neg_a else diff
        diff = basefwx._subtract_magnitude(db, da)
        return ("-" + diff) if neg_b else diff

    @classmethod
    def decode(cls, sttr: str) -> str:
        if not sttr:
            return sttr
        return cls._DECODE_PATTERN.sub(lambda match: cls._DECODE_MAP[match.group(0)], sttr)

    @classmethod
    def fwx256unbin(cls, string: str) -> str:
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        data = base32text.encode('utf-8')
        # Use fast NumPy decoder for large data
        if cls.np is not None and len(data) >= cls._B32_FAST_THRESHOLD:
            decoded = cls._fast_b32hexdecode(data).decode('utf-8')
        else:
            decoded = cls.base64.b32hexdecode(data).decode('utf-8')
        return cls.decode(decoded)

    @staticmethod
    def b512file_decode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
        try:
            effective_use_master = use_master and not strip_metadata
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_decode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master)
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to decode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def b512file_encode_bytes(
        data: bytes,
        ext: str,
        code: str,
        strip_metadata: bool = False,
        use_master: bool = True,
        *,
        enable_aead: "basefwx.typing.Optional[bool]" = None
    ) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("b512file_encode_bytes expects bytes")
        approx_b64_len = ((len(data) + 2) // 3) * 4
        if approx_b64_len > basefwx.HKDF_MAX_LEN:
            raise ValueError("b512file_encode_bytes payload too large; use file-based streaming APIs")
        pubkey_bytes, master_available = basefwx._resolve_master_usage(
            use_master and not strip_metadata,
            None,
            create_if_missing=True
        )
        use_master_effective = (use_master and not strip_metadata) and master_available
        password = basefwx._resolve_password(code, use_master=use_master_effective)
        b64_payload = basefwx.base64.b64encode(bytes(data)).decode('utf-8')
        ext_token = basefwx.b512encode(ext or "", password, use_master=use_master_effective)
        data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        use_aead = basefwx.ENABLE_B512_AEAD if enable_aead is None else bool(enable_aead)
        metadata_blob = basefwx._build_metadata(
            "FWX512R",
            strip_metadata,
            use_master_effective,
            aead="AESGCM" if use_aead else "NONE",
            kdf=kdf_used
        )
        body = f"{ext_token}{basefwx.FWX_DELIM}{data_token}"
        payload = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        payload_bytes = payload.encode('utf-8')
        if not use_aead:
            return payload_bytes
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            password,
            use_master_effective,
            mask_info=basefwx.B512_FILE_MASK_INFO,
            require_password=not use_master_effective,
            aad=b'b512file'
        )
        aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        ct_blob = basefwx._aead_encrypt(aead_key, payload_bytes, basefwx.B512_AEAD_INFO)
        return basefwx._pack_length_prefixed(user_blob, master_blob, ct_blob)

    @staticmethod
    def b512file_decode_bytes(
        blob: bytes,
        code: str,
        strip_metadata: bool = False,
        use_master: bool = True
    ) -> "basefwx.typing.Tuple[bytes, str]":
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("b512file_decode_bytes expects bytes")
        use_master_effective = use_master and not strip_metadata
        password = basefwx._resolve_password(code, use_master=use_master_effective)
        raw_bytes = bytes(blob)
        binary_mode = False
        user_blob: bytes = b""
        master_blob: bytes = b""
        ct_blob: bytes = b""
        if basefwx.ENABLE_B512_AEAD:
            try:
                user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(raw_bytes, 3)
                binary_mode = True
            except ValueError:
                binary_mode = False
        if binary_mode:
            mask_key = basefwx._recover_mask_key_from_blob(
                user_blob,
                master_blob,
                password,
                use_master_effective,
                mask_info=basefwx.B512_FILE_MASK_INFO,
                aad=b'b512file'
            )
            aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
            payload_bytes = basefwx._aead_decrypt(aead_key, ct_blob, basefwx.B512_AEAD_INFO)
            content = payload_bytes.decode('utf-8')
        else:
            content = raw_bytes.decode('utf-8')
        metadata_blob, content_core = basefwx._split_metadata(content)
        meta = basefwx._decode_metadata(metadata_blob)
        master_hint = meta.get("ENC-MASTER") if meta else None
        if master_hint == "no":
            use_master_effective = False
        header, payload = basefwx._split_with_delims(
            content_core,
            (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM),
            "FWX container"
        )
        ext = basefwx.b512decode(header, password, use_master=use_master_effective)
        data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)
        decoded = basefwx.base64.b64decode(data_b64)
        return decoded, ext

    @staticmethod
    def pb512file_encode_bytes(
        data: bytes,
        ext: str,
        code: str,
        strip_metadata: bool = False,
        use_master: bool = True
    ) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("pb512file_encode_bytes expects bytes")
        approx_b64_len = ((len(data) + 2) // 3) * 4
        if approx_b64_len > basefwx.HKDF_MAX_LEN:
            raise ValueError("pb512file_encode_bytes payload too large; use file-based streaming APIs")
        use_master_effective = use_master and not strip_metadata
        password = basefwx._resolve_password(code, use_master=use_master_effective)
        b64_payload = basefwx.base64.b64encode(bytes(data)).decode('utf-8')
        ext_token = basefwx.pb512encode(ext or "", password, use_master=use_master_effective)
        data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(len(data))
        obf_mode = "fast" if fast_obf else "yes"
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            obfuscation=obf_mode,
            kdf_iters=heavy_iters,
            argon2_time_cost=heavy_argon_time,
            argon2_memory_cost=heavy_argon_mem,
            argon2_parallelism=heavy_argon_par
        )
        body = f"{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}"
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            kdf=kdf_used,
            obfuscate=True,
            kdf_iterations=heavy_iters,
            argon2_time_cost=heavy_argon_time,
            argon2_memory_cost=heavy_argon_mem,
            argon2_parallelism=heavy_argon_par,
            fast_obfuscation=fast_obf
        )
        return ciphertext

    @staticmethod
    def pb512file_decode_bytes(
        blob: bytes,
        code: str,
        strip_metadata: bool = False,
        use_master: bool = True
    ) -> "basefwx.typing.Tuple[bytes, str]":
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("pb512file_decode_bytes expects bytes")
        use_master_effective = use_master and not strip_metadata
        password = basefwx._resolve_password(code, use_master=use_master_effective)
        plaintext = basefwx.decryptAES(bytes(blob), password, use_master=use_master_effective)
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        meta = basefwx._decode_metadata(metadata_blob)
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        ext_token, data_token = basefwx._split_with_delims(
            payload,
            (basefwx.FWX_HEAVY_DELIM, basefwx.LEGACY_FWX_HEAVY_DELIM),
            "FWX heavy"
        )
        ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
        data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)
        decoded = basefwx.base64.b64decode(data_b64)
        return decoded, ext

    @staticmethod
    def bi512encode(string: str):
        code = string[0] + string[len(string) - 1]
        left = basefwx._mdcode_ascii(string)
        right = basefwx._mdcode_ascii(code)
        diff = basefwx._decimal_diff(left, right)
        packed = basefwx._fwx256bin_bytes(diff)
        return str(basefwx.hashlib.sha256(packed).hexdigest()).replace("-", "0")

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def a512encode(string: str):
        left = basefwx._mdcode_ascii(string)
        md_len = len(left)
        md_len_str = str(md_len)
        prefix_len = str(len(md_len_str))
        code = str(md_len * md_len)
        right = basefwx._mdcode_ascii(code)
        diff = basefwx._decimal_diff(left, right)
        packed = basefwx.fwx256bin(diff)
        return prefix_len + md_len_str + packed

    @staticmethod
    def a512decode(string: str):
        def maindc(string):
            try:
                if not string or not string[0].isdigit():
                    return "AN ERROR OCCURED!"
                leoa = int(string[0])
                if leoa <= 0 or len(string) < leoa + 1:
                    return "AN ERROR OCCURED!"
                length_str = string[1:leoa + 1]
                md_len = int(length_str)
                code = str(md_len * md_len)
                payload = string[leoa + 1:]
                string3 = basefwx.fwx256unbin(payload.replace("4G5tRA", "="))
                if string3 and string3[0] == "0":
                    string3 = "-" + string3[1:]
                md_code = basefwx._mdcode_ascii(code)
                if len(string3) <= basefwx._DECIMAL_INT_LIMIT and len(md_code) <= basefwx._DECIMAL_INT_LIMIT:
                    try:
                        total = str(int(string3) + int(md_code))
                    except (ValueError, OverflowError, MemoryError):
                        total = basefwx._add_signed(string3, md_code)
                else:
                    total = basefwx._add_signed(string3, md_code)
                if total.startswith("-"):
                    return "AN ERROR OCCURED!"
                return basefwx._mcode_digits(total)
            except Exception:
                return "AN ERROR OCCURED!"

        return maindc(string)

    # UNDCODABLE IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙❙
    @staticmethod
    def b1024encode(string: str):
        if not string:
            raise ValueError("b1024encode expects non-empty input")
        # Optimized path: since bi512encode only produces a hash, we can stream
        # the computation to avoid building huge intermediate strings
        a512_result = basefwx.a512encode(string)
        return basefwx.bi512encode(a512_result)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def _coerce_text(data: "basefwx.typing.Union[str, bytes, bytearray, memoryview]") -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data).decode('latin-1')
        raise TypeError(f"Unsupported type for textual conversion: {type(data)!r}")

    @classmethod
    def b256decode(cls, string: str) -> str:
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        data = base32text.encode('utf-8')
        # Use fast NumPy decoder for large data
        if cls.np is not None and len(data) >= cls._B32_FAST_THRESHOLD:
            decoded = cls._fast_b32hexdecode(data).decode('utf-8')
        else:
            decoded = cls.base64.b32hexdecode(data).decode('utf-8')
        return cls.decode(decoded)

    @classmethod
    def b256encode(cls, data: "basefwx.typing.Union[str, bytes, bytearray, memoryview]") -> str:
        text = cls._coerce_text(data)
        raw = cls.code(text).encode('utf-8')
        # Use fast NumPy encoder for large data
        if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
            encoded = cls._fast_b32hexencode(raw).decode('utf-8')
        else:
            encoded = cls.base64.b32hexencode(raw).decode('utf-8')
        padding_count = encoded.count("=")
        return encoded.rstrip("=") + str(padding_count)

# ENCRYPTION TYPES:
# BASE64 - b64encode/b64decode  V1.0
# HASH512 - hash512  V1.0
# HASH512U - uhash513 V1.2
# FWX512RP - pb512encode/pb512encode V2.0
# FWX512R - b512encode/b512decode V2.0 ★
# FWX512I - bi512encode V3.4 ★
# FWX512C - a512encode/a512decode V2.0 ❗❗❗ (NOT RECCOMENDED)
# FWX1024I - b1024encode V4.0 ★ (BEST)
# FWX256R - b256encode/b256decode V1.3 ❗❗❗ (NOT RECCOMENDED)

# HOW TO USE: basefwx.ENCRYPTION-TYPE("text","password")


# Emit a one-time warning at import if single-thread override is forced
basefwx._warn_single_thread_api()


def cli(argv=None) -> int:
    import argparse

    def _cli_config_path() -> "basefwx.pathlib.Path":
        cfg = _os_module.getenv("BASEFWX_CLI_CONFIG")
        if cfg:
            return basefwx.pathlib.Path(cfg).expanduser()
        xdg = _os_module.getenv("XDG_CONFIG_HOME")
        if xdg:
            return basefwx.pathlib.Path(xdg) / "basefwx" / "cli.conf"
        appdata = _os_module.getenv("APPDATA")
        if appdata:
            return basefwx.pathlib.Path(appdata) / "basefwx" / "cli.conf"
        return basefwx.pathlib.Path("~/.config/basefwx/cli.conf").expanduser()

    def _cli_plain_mode() -> bool:
        if _os_module.getenv("BASEFWX_CLI_PLAIN"):
            return True
        if _os_module.getenv("NO_COLOR"):
            return True
        style = (_os_module.getenv("BASEFWX_CLI_STYLE") or "").strip().lower()
        if style in {"plain", "boring", "0", "false", "off"}:
            return True
        if style in {"color", "emoji", "on"}:
            return False
        cfg_path = _cli_config_path()
        try:
            if cfg_path.exists():
                data = cfg_path.read_text(encoding="utf-8").lower()
                if "plain=1" in data or "plain=true" in data:
                    return True
                if "style=plain" in data or "mode=plain" in data or "boring=1" in data:
                    return True
        except OSError:
            pass
        return False

    class _CliTheme:
        def __init__(self, plain: bool):
            self.plain = plain
            self.reset = "" if plain else "\033[0m"
            self.bold = "" if plain else "\033[1m"
            self.red = "" if plain else "\033[31m"
            self.green = "" if plain else "\033[32m"
            self.yellow = "" if plain else "\033[33m"
            self.cyan = "" if plain else "\033[36m"

        def _wrap(self, msg: str, color: str, emoji: str | None = None) -> str:
            if self.plain:
                return msg
            prefix = f"{emoji} " if emoji else ""
            return f"{self.bold}{color}{prefix}{msg}{self.reset}"

        def ok(self, msg: str) -> str:
            return self._wrap(msg, self.green, "✅")

        def warn(self, msg: str) -> str:
            return self._wrap(msg, self.yellow, "⚠️")

        def err(self, msg: str) -> str:
            return self._wrap(msg, self.red, "❌")

        def info(self, msg: str) -> str:
            return self._wrap(msg, self.cyan, "✨")

    theme = _CliTheme(_cli_plain_mode())

    def _confirm_single_thread_cli() -> None:
        # Single-thread mode only triggers with explicit BASEFWX_FORCE_SINGLE_THREAD=1
        if not basefwx._SINGLE_THREAD_OVERRIDE:
            return
        if _os_module.getenv("BASEFWX_ALLOW_SINGLE_THREAD") == "1" or _os_module.getenv("BASEFWX_NONINTERACTIVE") == "1":
            # Non-interactive bypass: warn but do not prompt
            warning = "WARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION"
            security = "WARN: SINGLE-THREAD MODE REDUCES SIDE-CHANNEL RESILIENCE"
            orange = "\033[38;5;208m"
            reset = "\033[0m"
            decorated = f"{orange}{warning}\n{security}{reset}" if not theme.plain else f"{warning}\n{security}"
            print(decorated, file=basefwx.sys.stderr)
            return
        warning = "WARN: MULTI-THREAD IS DISABLED; THIS MAY CAUSE SEVERE PERFORMANCE DETERIORATION"
        security = "WARN: SINGLE-THREAD MODE REDUCES SIDE-CHANNEL RESILIENCE"
        orange = "\033[38;5;208m"
        reset = "\033[0m"
        decorated = f"{orange}{warning}\n{security}{reset}" if not theme.plain else f"{warning}\n{security}"
        print(decorated, file=basefwx.sys.stderr)
        prompt = "Type YES to continue with single-thread mode: "
        response = input(prompt)
        if response.strip() != "YES":
            raise SystemExit(theme.err("Aborted: multi-thread disabled by user override"))

    parser = argparse.ArgumentParser(prog="basefwx", description="BASEFWX encryption toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cryptin = subparsers.add_parser(
        "cryptin",
        help="Encrypt/decrypt one or more files using a BASEFWX method"
    )
    cryptin.add_argument(
        "method",
        help="Method name: 512, b512, pb512, aes, aes-light, aes-heavy"
    )
    cryptin.add_argument(
        "paths",
        nargs='+',
        help="One or more file paths"
    )
    cryptin.add_argument(
        "-p", "--password",
        default="",
        help="Password text or path (leave blank to rely on the master key)"
    )
    cryptin.add_argument(
        "--strip", "--trim",
        dest="strip_metadata",
        action="store_true",
        help="Disable metadata emission and zero timestamps"
    )
    cryptin.add_argument(
        "--no-master",
        dest="use_master",
        action="store_false",
        help="Opt out of master key wrapping/unwrapping"
    )
    cryptin.add_argument(
        "--no-obf",
        dest="obfuscate",
        action="store_false",
        help="Disable pre-AEAD obfuscation layers"
    )
    cryptin.set_defaults(use_master=True, obfuscate=True, archive_original=False)
    cryptin.add_argument(
        "--use-master-pub",
        dest="master_pub_path",
        default=None,
        help="Path to ML-KEM public key used for master key wrapping"
    )
    cryptin.add_argument(
        "--normalize",
        action="store_true",
        help="Wrap fwxAES output in zero-width cover text (fwxaes only)"
    )
    cryptin.add_argument(
        "--normalize-threshold",
        type=int,
        default=None,
        help="Max plaintext bytes for normalize wrapper (fwxaes only)"
    )
    cryptin.add_argument(
        "--cover-phrase",
        default="low taper fade",
        help="Cover phrase for normalize wrapper (fwxaes only)"
    )
    cryptin.add_argument(
        "--compress",
        action="store_true",
        help="Pack files/folders to tar.gz or tar.xz before encrypting; auto-unpack on decrypt"
    )
    cryptin.add_argument(
        "--ignore-media",
        action="store_true",
        help="Disable media auto-detection for fwxAES (use normal encryption)"
    )
    cryptin.add_argument(
        "--keep-meta",
        action="store_true",
        help="Preserve media metadata (encrypted) when using jMG media mode"
    )
    cryptin.add_argument(
        "--no-archive",
        dest="archive_original",
        action="store_false",
        help="jMG mode: do not embed full original payload (smaller output, non-byte-identical restore)"
    )
    cryptin.add_argument(
        "--archive",
        dest="archive_original",
        action="store_true",
        help="jMG mode: embed full original payload for exact restore"
    )
    cryptin.add_argument(
        "--keep-input",
        action="store_true",
        help="Do not delete the input after encryption"
    )

    n10_enc = subparsers.add_parser(
        "n10-enc",
        help="Encode UTF-8 text into a numeric n10 payload"
    )
    n10_enc.add_argument("text", help="Input text")

    n10_dec = subparsers.add_parser(
        "n10-dec",
        help="Decode an n10 numeric payload back to UTF-8 text"
    )
    n10_dec.add_argument("digits", help="n10 payload digits")

    n10file_enc = subparsers.add_parser(
        "n10file-enc",
        help="Encode a binary file into n10 digits"
    )
    n10file_enc.add_argument("input", help="Input file path")
    n10file_enc.add_argument("output", help="Output file path for digits")

    n10file_dec = subparsers.add_parser(
        "n10file-dec",
        help="Decode an n10 digit file back to binary"
    )
    n10file_dec.add_argument("input", help="Input n10 digit file")
    n10file_dec.add_argument("output", help="Output binary file path")

    kfme = subparsers.add_parser(
        "kFMe",
        help="Encode data into a BaseFWX carrier (image/media->WAV, audio->PNG)"
    )
    kfme.add_argument("input", help="Input file path (audio or image/media)")
    kfme.add_argument("-o", "--output", default=None, help="Output carrier path")
    kfme.add_argument(
        "--bw",
        action="store_true",
        help="When encoding audio->PNG, use black/white static mode"
    )

    kfmd = subparsers.add_parser(
        "kFMd",
        help="Decode BaseFWX carrier (audio/image) back to original payload"
    )
    kfmd.add_argument("input", help="Input carrier file path (audio/image)")
    kfmd.add_argument("-o", "--output", default=None, help="Output file path")
    kfmd.add_argument(
        "--bw",
        action="store_true",
        help="Deprecated no-op (kept for compatibility)"
    )

    kfae = subparsers.add_parser(
        "kFAe",
        help="Deprecated alias for kFMe (auto-detect)"
    )
    kfae.add_argument("input", help="Input file path")
    kfae.add_argument("-o", "--output", default=None, help="Output carrier path")
    kfae.add_argument("--bw", action="store_true", help="When encoding audio->PNG, use black/white static mode")

    kfad = subparsers.add_parser(
        "kFAd",
        help="Deprecated alias for kFMd (auto-detect)"
    )
    kfad.add_argument("input", help="Input carrier file path")
    kfad.add_argument("-o", "--output", default=None, help="Output file path")

    args = parser.parse_args(argv)

    _confirm_single_thread_cli()

    if args.command == "n10-enc":
        print(basefwx.n10encode(args.text))
        return 0

    if args.command == "n10-dec":
        try:
            print(basefwx.n10decode(args.digits))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 decode failed: {exc}"))
            return 1

    if args.command == "n10file-enc":
        try:
            in_path = basefwx.pathlib.Path(args.input)
            out_path = basefwx.pathlib.Path(args.output)
            out_path.write_text(basefwx.n10encode_bytes(in_path.read_bytes()), encoding="utf-8")
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 file encode failed: {exc}"))
            return 1

    if args.command == "n10file-dec":
        try:
            in_path = basefwx.pathlib.Path(args.input)
            out_path = basefwx.pathlib.Path(args.output)
            out_path.write_bytes(basefwx.n10decode_bytes(in_path.read_text(encoding="utf-8")))
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"n10 file decode failed: {exc}"))
            return 1

    if args.command == "kFMe":
        try:
            out_path = basefwx.kFMe(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFMe failed: {exc}"))
            return 1

    if args.command == "kFMd":
        try:
            out_path = basefwx.kFMd(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFMd failed: {exc}"))
            return 1

    if args.command == "kFAe":
        try:
            out_path = basefwx.kFAe(args.input, args.output, bw_mode=args.bw)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFAe failed: {exc}"))
            return 1

    if args.command == "kFAd":
        try:
            out_path = basefwx.kFAd(args.input, args.output)
            print(theme.ok(f"Wrote {out_path}"))
            return 0
        except Exception as exc:
            print(theme.err(f"kFAd failed: {exc}"))
            return 1

    if args.command == "cryptin":
        method = args.method.lower()
        password = args.password or ""
        use_master = args.use_master
        if args.strip_metadata:
            use_master = False
        if not args.obfuscate:
            basefwx.ENABLE_OBFUSCATION = False
        try:
            master_pub_bytes = basefwx._resolve_master_pubkey_path(args.master_pub_path)
        except FileNotFoundError as exc:
            print(theme.err(f"Failed to load master public key: {exc}"))
            return 1
        basefwx._set_master_pubkey_override(master_pub_bytes)
        method_map = {
            "512": "b512",
            "b512": "b512",
            "fwx512": "b512",
            "fwxaes": "fwxaes",
            "aes": "aes-light",
            "aes-light": "aes-light",
            "256": "aes-light",
            "light": "aes-light",
            "aes-heavy": "aes-heavy",
            "heavy": "aes-heavy",
            "pb512": "aes-heavy",
            "aes512": "aes-heavy"
        }

        normalized = method_map.get(method)
        if not normalized:
            parser.error(f"Unsupported method '{args.method}'")

        if normalized == "fwxaes":
            results = {}
            for raw_path in args.paths:
                try:
                    basefwx.fwxAES_file(
                        raw_path,
                        password,
                        use_master=use_master,
                        normalize=args.normalize,
                        normalize_threshold=args.normalize_threshold,
                        cover_phrase=args.cover_phrase,
                        compress=args.compress,
                        ignore_media=args.ignore_media,
                        keep_meta=args.keep_meta,
                        archive_original=args.archive_original,
                        keep_input=args.keep_input
                    )
                    results[str(raw_path)] = "SUCCESS!"
                except Exception as exc:
                    results[str(raw_path)] = f"FAIL! {exc}"
            result = results if len(args.paths) > 1 else next(iter(results.values()))
        elif normalized == "b512":
            result = basefwx.b512file(
                args.paths,
                password,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes,
                compress=args.compress,
                keep_input=args.keep_input
            )
        elif normalized == "aes-light":
            result = basefwx.AESfile(
                args.paths,
                password,
                light=True,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes,
                compress=args.compress,
                keep_input=args.keep_input
            )
        else:
            result = basefwx.AESfile(
                args.paths,
                password,
                light=False,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes,
                compress=args.compress,
                keep_input=args.keep_input
            )

        if isinstance(result, dict):
            failures = 0
            for path, status in result.items():
                if status == "SUCCESS!":
                    print(theme.ok(f"{path}: {status}"))
                else:
                    print(theme.err(f"{path}: {status}"))
                if status != "SUCCESS!":
                    failures += 1
            return 0 if failures == 0 else 1

        # Print an extra newline to ensure separation from progress output
        if result == "SUCCESS!":
            print(theme.ok(result))
        else:
            print(result)
        return 0 if result == "SUCCESS!" else 1

    return 0


def main(argv=None) -> int:
    try:
        return cli(argv)
    except KeyboardInterrupt:
        print("Exiting...")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
