# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

# BASEFWX ENCRYPTION ENGINE ->

import os as _os_module
import re as _re_module
import sys as _sys_module
import warnings as _warnings_module

try:
    from ._repo_version import __version__ as _BASEFWX_ENGINE_VERSION
except Exception:  # pragma: no cover - fallback for direct execution
    _BASEFWX_ENGINE_VERSION = "0.0.0"


from . import _primitives as _prim
from . import _codecs_str
from . import _codecs_n10
from . import _progress
from . import _obf
from . import _kdf
from . import _file_ops
from . import _an7
from . import _fwxaes
from . import _kfm
from . import _master_key
from . import _jmg
from . import _b512file
from . import _aes_file
from . import _media


class basefwx:
    import base64
    import array
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
    # cupy is lazy-loaded — eager import costs ~300 ms (pulls in numpy,
    # scipy, cupyx) and the CUDA path is opt-in via BASEFWX_KFM_ACCEL.
    # _ensure_cp() runs the import right before the should-use-cuda gate.
    cp = None
    _cp_load_attempted = False
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

    _env_int = staticmethod(_prim._env_int)

    _perf_mode_enabled = staticmethod(_prim._perf_mode_enabled)

    _use_fast_obfuscation = staticmethod(_prim._use_fast_obfuscation)

    _get_available_ram_mib = staticmethod(_prim._get_available_ram_mib)
    
    _check_ram_for_argon2 = staticmethod(_prim._check_ram_for_argon2)

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
    ENGINE_VERSION = _BASEFWX_ENGINE_VERSION
    N10_MOD = 10_000_000_000
    N10_MUL = 3_816_547_291
    N10_ADD = 7_261_940_353
    N10_MAGIC = "927451"
    N10_VERSION = "01"
    N10_HEADER_DIGITS = 28
    N10_MASK64 = (1 << 64) - 1
    N10_MUL_INV = pow(N10_MUL, -1, N10_MOD)
    N10_OFFSET_XOR = 0xA5A5F0F01234ABCD
    N10_OFFSET_CACHE = array.array("Q")
    KFM_MAGIC = b"KFM!"
    KFM_VERSION = 1
    KFM_MODE_IMAGE_AUDIO = 1
    KFM_MODE_AUDIO_IMAGE = 2
    KFM_FLAG_BW = 1
    KFM_HEADER_STRUCT = struct.Struct(">4sBBBBQIQI")
    KFM_HEADER_LEN = KFM_HEADER_STRUCT.size
    KFM_MAX_PAYLOAD = 1_073_741_824
    KFM_AUDIO_RATE = 24000
    KFM_ACCEL_ENV = "BASEFWX_KFM_ACCEL"
    KFM_ACCEL_MIN_BYTES_ENV = "BASEFWX_KFM_ACCEL_MIN_BYTES"
    KFM_ACCEL_DEFAULT_MIN_BYTES = 1 * 1024 * 1024
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
    JMG_VIDEO_ENABLE_ENV = "BASEFWX_ENABLE_JMG_VIDEO"
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
    HEAVY_PBKDF2_ITERATIONS = 2_000_000
    HEAVY_ARGON2_TIME_COST = 6
    HEAVY_ARGON2_MEMORY_COST = 2 ** 18
    # 3.7.0: fixed at 4 so blobs are portable across hosts — the wire
    # format does not carry parallelism, so hardware-dependent defaults
    # caused silent AEAD failures when ciphertext crossed machines.
    HEAVY_ARGON2_PARALLELISM = 4
    OFB_FAST_MIN = 64 * 1024
    PERM_FAST_MIN = 4 * 1024
    USER_KDF_SALT_SIZE = 16
    USER_KDF_ITERATIONS = 600_000
    SHORT_PASSWORD_MIN = 12
    SHORT_PBKDF2_ITERATIONS = 1_000_000
    SHORT_ARGON2_TIME_COST = 5
    SHORT_ARGON2_MEMORY_COST = 2 ** 17
    SHORT_ARGON2_PARALLELISM = 4  # see HEAVY_ARGON2_PARALLELISM note above
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
    _HAS_SUFFICIENT_RAM = _prim._check_ram_for_argon2() if _ARGON2_AVAILABLE else True
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
    _TEST_KDF_ITERS = _prim._env_int("BASEFWX_TEST_KDF_ITERS")
    _USER_KDF_ITERS_ENV = _prim._env_int("BASEFWX_USER_KDF_ITERS")
    if _USER_KDF_ITERS_ENV is not None:
        USER_KDF_ITERATIONS = _USER_KDF_ITERS_ENV
    elif _TEST_KDF_ITERS is not None:
        USER_KDF_ITERATIONS = _TEST_KDF_ITERS
    _HEAVY_PBKDF2_ITERS_ENV = _prim._env_int("BASEFWX_HEAVY_PBKDF2_ITERS")
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
    FWXAES_PBKDF2_ITERS = 600_000
    _FWXAES_PBKDF2_ITERS_ENV = _prim._env_int("BASEFWX_FWXAES_PBKDF2_ITERS")
    if _FWXAES_PBKDF2_ITERS_ENV is not None:
        FWXAES_PBKDF2_ITERS = _FWXAES_PBKDF2_ITERS_ENV
    elif _TEST_KDF_ITERS is not None:
        FWXAES_PBKDF2_ITERS = _TEST_KDF_ITERS
    FWXAES_KEY_LEN = 32
    FWXAES_AAD = b"fwxAES"
    FWXAES_MASK_INFO = b"basefwx.fwxaes.mask.v1"
    FWXAES_KEY_INFO = b"basefwx.fwxaes.key.v1"
    AN7_CHUNK_SIZE = 1 << 20
    AN7_SUPERBLOCK_CHUNKS = 10
    AN7_FLIP_STRIDE = 10
    AN7_FOOTER_SIZE = 64
    AN7_TAIL_PLAIN_LEN = 20
    AN7_TAIL_NONCE_LEN = 12
    AN7_TAIL_CIPHER_LEN = 20
    AN7_TAIL_TAG_LEN = 16
    AN7_SALT_LEN = 16
    AN7_TRAILER_NONCE_LEN = 12
    AN7_SHA256_LEN = 32
    AN7_ARGON2_TIME_COST = 5
    AN7_ARGON2_MEMORY_COST = 131072
    AN7_ARGON2_PARALLELISM = 4
    AN7_TRAILER_VERSION = b"AN7v1"
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
    _CODE_TRANSLATION_TABLE_BYTES: typing.ClassVar[tuple[bytes, ...]] = tuple(
        token.encode("utf-8") for token in _CODE_TRANSLATION_TABLE
    )
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
    # Threshold for byte-path code translation (list join beats generator above this size)
    _CODE_BYTES_ASCII_THRESHOLD = 500

    _fast_b32hexencode = staticmethod(_prim._fast_b32hexencode)

    _fast_b32hexdecode = staticmethod(_prim._fast_b32hexdecode)

    _require_pil = staticmethod(_prim._require_pil)

    _ProgressReporter = _progress._ProgressReporter

            

    _human_readable_size = staticmethod(_prim._human_readable_size)

    _del = staticmethod(_prim._del)

    _hkdf = staticmethod(_prim._hkdf)

    _splitmix64 = staticmethod(_prim._splitmix64)

    _permute_inplace = staticmethod(_prim._permute_inplace)

    _unpermute_inplace = staticmethod(_prim._unpermute_inplace)

    _xor_keystream_inplace = staticmethod(_prim._xor_keystream_inplace)

    _obfuscate_bytes = staticmethod(_obf._obfuscate_bytes)

    _deobfuscate_bytes = staticmethod(_obf._deobfuscate_bytes)

    _StreamObfuscator = _obf._StreamObfuscator

    _build_metadata = staticmethod(_file_ops._build_metadata)

    _decode_metadata = staticmethod(_file_ops._decode_metadata)

    _split_metadata = staticmethod(_file_ops._split_metadata)

    _split_with_delims = staticmethod(_file_ops._split_with_delims)

    _apply_strip_attributes = staticmethod(_file_ops._apply_strip_attributes)

    _remove_input = staticmethod(_file_ops._remove_input)

    _pack_mode_for_path = staticmethod(_file_ops._pack_mode_for_path)

    _pack_input_to_archive = staticmethod(_file_ops._pack_input_to_archive)

    _is_safe_tar_path = staticmethod(_file_ops._is_safe_tar_path)

    _unpack_archive = staticmethod(_file_ops._unpack_archive)

    _pack_flag_from_meta = staticmethod(_file_ops._pack_flag_from_meta)

    _maybe_unpack_output = staticmethod(_file_ops._maybe_unpack_output)

    _warn_on_metadata = staticmethod(_file_ops._warn_on_metadata)

    _decode_pubkey_bytes = staticmethod(_master_key._decode_pubkey_bytes)

    _set_master_pubkey_override = classmethod(_master_key._set_master_pubkey_override)

    _resolve_master_pubkey_path = staticmethod(_master_key._resolve_master_pubkey_path)

    _load_master_pq_public = staticmethod(_master_key._load_master_pq_public)

    _load_master_pq_private = staticmethod(_master_key._load_master_pq_private)

    _default_master_ec_public_path = staticmethod(_master_key._default_master_ec_public_path)

    _default_master_ec_private_path = staticmethod(_master_key._default_master_ec_private_path)

    _decode_ec_public_key = staticmethod(_master_key._decode_ec_public_key)

    _decode_ec_private_key = staticmethod(_master_key._decode_ec_private_key)

    _write_ec_keypair = staticmethod(_master_key._write_ec_keypair)

    _load_master_ec_public = staticmethod(_master_key._load_master_ec_public)

    _load_master_ec_private = staticmethod(_master_key._load_master_ec_private)

    _ec_kem_enc = staticmethod(_master_key._ec_kem_enc)

    _ec_kem_dec = staticmethod(_master_key._ec_kem_dec)

    _resolve_master_usage = staticmethod(_master_key._resolve_master_usage)

    _kem_derive_key = staticmethod(_master_key._kem_derive_key)

    _hkdf_sha256 = staticmethod(_prim._hkdf_sha256)

    _hkdf_stream_sha256 = staticmethod(_prim._hkdf_stream_sha256)

    _mdcode_ascii = staticmethod(_codecs_str._mdcode_ascii)

    _mcode_digits = staticmethod(_codecs_str._mcode_digits)

    _aead_encrypt = staticmethod(_prim._aead_encrypt)

    _aead_decrypt = staticmethod(_prim._aead_decrypt)

    _pack_length_prefixed = staticmethod(_b512file._pack_length_prefixed)

    _unpack_length_prefixed = staticmethod(_b512file._unpack_length_prefixed)

    _resolve_payload_length_from_file_size = staticmethod(_b512file._resolve_payload_length_from_file_size)

    _mask_payload = staticmethod(_obf._mask_payload)

    _estimate_aead_blob_size = staticmethod(_b512file._estimate_aead_blob_size)

    _prepare_mask_key = staticmethod(_master_key._prepare_mask_key)

    _recover_mask_key_from_blob = staticmethod(_master_key._recover_mask_key_from_blob)

    _jmg_security_profile_id = staticmethod(_jmg._jmg_security_profile_id)

    _jmg_video_enabled = staticmethod(_jmg._jmg_video_enabled)

    _jmg_stream_info_for_profile = staticmethod(_jmg._jmg_stream_info_for_profile)

    _jmg_archive_info_for_profile = staticmethod(_jmg._jmg_archive_info_for_profile)

    _jmg_build_key_header = staticmethod(_jmg._jmg_build_key_header)

    _jmg_profile_from_key_header = staticmethod(_jmg._jmg_profile_from_key_header)

    _jmg_parse_key_header = staticmethod(_jmg._jmg_parse_key_header)

    _jmg_prepare_keys = staticmethod(_jmg._jmg_prepare_keys)

    _append_balanced_trailer = staticmethod(_jmg._append_balanced_trailer)

    _extract_balanced_trailer_from_bytes = staticmethod(_jmg._extract_balanced_trailer_from_bytes)

    _extract_balanced_trailer_info = staticmethod(_jmg._extract_balanced_trailer_info)

    _kem_shared_to_digits = staticmethod(_master_key._kem_shared_to_digits)

    _derive_key_material = staticmethod(_kdf._derive_key_material)

    _pq_wrap_secret = staticmethod(_master_key._pq_wrap_secret)

    _pq_unwrap_secret = staticmethod(_master_key._pq_unwrap_secret)

    _pq_unwrap_secret_with_shared = staticmethod(_master_key._pq_unwrap_secret_with_shared)

    _normalize_path = staticmethod(_file_ops._normalize_path)

    _ensure_existing_file = staticmethod(_file_ops._ensure_existing_file)

    _ensure_size_limit = staticmethod(_file_ops._ensure_size_limit)

    _resolve_password = staticmethod(_file_ops._resolve_password)

    _coerce_file_list = staticmethod(_file_ops._coerce_file_list)


    generate_random_string = staticmethod(_prim.generate_random_string)

    derive_key_from_text = staticmethod(_kdf.derive_key_from_text)

    _derive_user_key_argon2id = staticmethod(_kdf._derive_user_key_argon2id)

    _derive_user_key_pbkdf2 = staticmethod(_kdf._derive_user_key_pbkdf2)

    _derive_user_key = staticmethod(_kdf._derive_user_key)

    encryptAES = staticmethod(_kdf.encryptAES)

    decryptAES = staticmethod(_kdf.decryptAES)

    _coerce_password_bytes = staticmethod(_kdf._coerce_password_bytes)

    _harden_kdf_params = staticmethod(_kdf._harden_kdf_params)

    _fwxaes_iterations = staticmethod(_kdf._fwxaes_iterations)

    _kdf_pbkdf2_raw = staticmethod(_kdf._kdf_pbkdf2_raw)

    _an7_read_exact = staticmethod(_an7._an7_read_exact)

    _an7_random_digits10 = staticmethod(_an7._an7_random_digits10)

    _an7_same_path = staticmethod(_an7._an7_same_path)

    _an7_ensure_collision_suffix = staticmethod(_an7._an7_ensure_collision_suffix)

    _an7_make_temp_path = staticmethod(_an7._an7_make_temp_path)

    _an7_commit_temp_file = staticmethod(_an7._an7_commit_temp_file)

    _an7_chunk_bytes_at = staticmethod(_an7._an7_chunk_bytes_at)

    _an7_total_chunks = staticmethod(_an7._an7_total_chunks)

    _an7_hmac_sha256 = staticmethod(_an7._an7_hmac_sha256)

    _an7_build_label = staticmethod(_an7._an7_build_label)

    _an7_derive_ctr_iv = staticmethod(_an7._an7_derive_ctr_iv)

    _an7_apply_xor_transform = staticmethod(_an7._an7_apply_xor_transform)

    _an7_flip_start = staticmethod(_an7._an7_flip_start)

    _an7_apply_sparse_flip = staticmethod(_an7._an7_apply_sparse_flip)

    _an7_build_permutation = staticmethod(_an7._an7_build_permutation)

    _an7_derive_keys = staticmethod(_an7._an7_derive_keys)

    _an7_serialize_trailer = staticmethod(_an7._an7_serialize_trailer)

    _an7_parse_trailer = staticmethod(_an7._an7_parse_trailer)

    _an7_parse_footer_and_derive = staticmethod(_an7._an7_parse_footer_and_derive)

    _an7_is_ascii_alnum = staticmethod(_an7._an7_is_ascii_alnum)

    _an7_sanitize_basename = staticmethod(_an7._an7_sanitize_basename)

    _an7_sanitize_extension = staticmethod(_an7._an7_sanitize_extension)

    _an7_resolve_output_path = staticmethod(_an7._an7_resolve_output_path)

    _an7_resolve_restored_name = staticmethod(_an7._an7_resolve_restored_name)

    _an7_resolve_dean_output_path = staticmethod(_an7._an7_resolve_dean_output_path)

    an7_file = staticmethod(_an7.an7_file)

    dean7_file = staticmethod(_an7.dean7_file)

    fwxAES_encrypt_raw = staticmethod(_fwxaes.fwxAES_encrypt_raw)

    fwxAES_decrypt_raw = staticmethod(_fwxaes.fwxAES_decrypt_raw)

    _is_seekable = staticmethod(_file_ops._is_seekable)

    fwxAES_encrypt_stream = staticmethod(_fwxaes.fwxAES_encrypt_stream)

    fwxAES_decrypt_stream = staticmethod(_fwxaes.fwxAES_decrypt_stream)

    _live_nonce = staticmethod(_fwxaes._live_nonce)

    _live_aad = staticmethod(_fwxaes._live_aad)

    _live_pack_frame = staticmethod(_fwxaes._live_pack_frame)

    LiveEncryptor = _fwxaes.LiveEncryptor

    LiveDecryptor = _fwxaes.LiveDecryptor

    fwxAES_live_encrypt_chunks = staticmethod(_fwxaes.fwxAES_live_encrypt_chunks)

    fwxAES_live_decrypt_chunks = staticmethod(_fwxaes.fwxAES_live_decrypt_chunks)

    fwxAES_live_encrypt_stream = staticmethod(_fwxaes.fwxAES_live_encrypt_stream)

    fwxAES_live_decrypt_stream = staticmethod(_fwxaes.fwxAES_live_decrypt_stream)

    _is_pathlike_target = staticmethod(_file_ops._is_pathlike_target)

    fwxAES_live_encrypt_ffmpeg = staticmethod(_fwxaes.fwxAES_live_encrypt_ffmpeg)

    fwxAES_live_decrypt_ffmpeg = staticmethod(_fwxaes.fwxAES_live_decrypt_ffmpeg)

    _bytes_to_bits = staticmethod(_obf._bytes_to_bits)

    _bits_to_bytes = staticmethod(_obf._bits_to_bytes)

    normalize_wrap = staticmethod(_obf.normalize_wrap)

    normalize_unwrap = staticmethod(_obf.normalize_unwrap)

    _wrap_pack_header = staticmethod(_file_ops._wrap_pack_header)

    _unwrap_pack_header = staticmethod(_file_ops._unwrap_pack_header)

    fwxAES_file = staticmethod(_fwxaes.fwxAES_file)
    # REVERSIBLE  - SECURITY: ❙
    b64encode = staticmethod(_prim.b64encode)

    b64decode = staticmethod(_prim.b64decode)

    _n10_mod_sub = staticmethod(_codecs_n10._n10_mod_sub)

    _n10_mix64 = staticmethod(_codecs_n10._n10_mix64)

    _n10_offset = staticmethod(_codecs_n10._n10_offset)

    _n10_ensure_offsets = staticmethod(_codecs_n10._n10_ensure_offsets)

    _n10_transform = staticmethod(_codecs_n10._n10_transform)

    _n10_inverse_transform = staticmethod(_codecs_n10._n10_inverse_transform)

    _n10_parse_fixed10 = staticmethod(_codecs_n10._n10_parse_fixed10)

    _n10_fnv1a32 = staticmethod(_codecs_n10._n10_fnv1a32)

    n10encode = staticmethod(_codecs_n10.n10encode)

    n10encode_bytes = staticmethod(_codecs_n10.n10encode_bytes)

    n10decode = staticmethod(_codecs_n10.n10decode)

    n10decode_bytes = staticmethod(_codecs_n10.n10decode_bytes)

    _kfm_clean_ext = staticmethod(_kfm._kfm_clean_ext)

    _kfm_is_audio_ext = staticmethod(_kfm._kfm_is_audio_ext)

    _kfm_is_image_ext = staticmethod(_kfm._kfm_is_image_ext)

    _kfm_warn = staticmethod(_kfm._kfm_warn)

    _kfm_accel_mode = staticmethod(_kfm._kfm_accel_mode)

    _kfm_accel_min_bytes = staticmethod(_kfm._kfm_accel_min_bytes)

    _ensure_cp = classmethod(_kfm._ensure_cp)

    _kfm_should_use_cuda = staticmethod(_kfm._kfm_should_use_cuda)

    _kfm_paths_equal = staticmethod(_kfm._kfm_paths_equal)

    _kfm_default_output = staticmethod(_kfm._kfm_default_output)

    _kfm_resolve_output = staticmethod(_kfm._kfm_resolve_output)

    _kfm_keystream = staticmethod(_kfm._kfm_keystream)

    _kfm_xor = staticmethod(_kfm._kfm_xor)

    _kfm_pack_container = staticmethod(_kfm._kfm_pack_container)

    _kfm_unpack_container = staticmethod(_kfm._kfm_unpack_container)

    _kfm_bytes_to_wav = staticmethod(_kfm._kfm_bytes_to_wav)

    _kfm_wav_to_bytes = staticmethod(_kfm._kfm_wav_to_bytes)

    _kfm_pcm16le_to_bytes = staticmethod(_kfm._kfm_pcm16le_to_bytes)

    _kfm_ffmpeg_audio_to_bytes = staticmethod(_kfm._kfm_ffmpeg_audio_to_bytes)

    _kfm_audio_to_bytes = staticmethod(_kfm._kfm_audio_to_bytes)

    _kfm_bytes_to_png = staticmethod(_kfm._kfm_bytes_to_png)

    _kfm_png_to_bytes = staticmethod(_kfm._kfm_png_to_bytes)

    _kfm_detect_carrier_kinds = staticmethod(_kfm._kfm_detect_carrier_kinds)

    _kfm_decode_container = staticmethod(_kfm._kfm_decode_container)

    kFMe = staticmethod(_kfm.kFMe)

    _kfae_legacy_encode = staticmethod(_kfm._kfae_legacy_encode)

    kFMd = staticmethod(_kfm.kFMd)

    kFAe = staticmethod(_kfm.kFAe)

    kFAd = staticmethod(_kfm.kFAd)

    hash512 = staticmethod(_prim.hash512)

    _looks_like_base64 = staticmethod(_obf._looks_like_base64)

    _maybe_obfuscate_codecs = staticmethod(_obf._maybe_obfuscate_codecs)

    _maybe_deobfuscate_codecs = staticmethod(_obf._maybe_deobfuscate_codecs)

    uhash513 = staticmethod(_prim.uhash513)

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    pb512encode = staticmethod(_b512file.pb512encode)

    pb512decode = staticmethod(_b512file.pb512decode)

    _pb512decode_legacy = staticmethod(_b512file._pb512decode_legacy)

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙

    b512encode = staticmethod(_b512file.b512encode)

    b512decode = staticmethod(_b512file.b512decode)

    _b512decode_legacy = staticmethod(_b512file._b512decode_legacy)

    _b512_encode_path = staticmethod(_b512file._b512_encode_path)
    _b512_encode_path_stream = staticmethod(_b512file._b512_encode_path_stream)
    _aes_heavy_encode_path_stream = staticmethod(_b512file._aes_heavy_encode_path_stream)

    _b512_decode_path = staticmethod(_b512file._b512_decode_path)
    _b512_decode_path_stream = staticmethod(_b512file._b512_decode_path_stream)

    b512file_encode = staticmethod(_b512file.b512file_encode)

    b512file = staticmethod(_b512file.b512file)

    ImageCipher = _media.ImageCipher

    MediaCipher = _media.MediaCipher
    _aes_light_encode_path = _aes_file._aes_light_encode_path

    _aes_light_decode_path = staticmethod(_aes_file._aes_light_decode_path)
    _aes_heavy_decode_path_stream = staticmethod(_aes_file._aes_heavy_decode_path_stream)

    _aes_heavy_encode_path = staticmethod(_aes_file._aes_heavy_encode_path)

    _aes_heavy_decode_path = staticmethod(_aes_file._aes_heavy_decode_path)

    AESfile = staticmethod(_aes_file.AESfile)

    _code_chunk = classmethod(_codecs_str._code_chunk)

    _code_bytes = classmethod(_codecs_str._code_bytes)

    code = classmethod(_codecs_str.code)

    fwx256bin = classmethod(_codecs_str.fwx256bin)

    _fwx256bin_bytes = classmethod(_codecs_str._fwx256bin_bytes)

    _b32_padding_count = staticmethod(_codecs_str._b32_padding_count)

    _strip_leading_zeros = staticmethod(_codecs_str._strip_leading_zeros)

    _compare_magnitude = staticmethod(_codecs_str._compare_magnitude)

    _decimal_diff = staticmethod(_codecs_str._decimal_diff)

    _add_magnitude = staticmethod(_codecs_str._add_magnitude)

    _subtract_magnitude = staticmethod(_codecs_str._subtract_magnitude)

    _add_signed = staticmethod(_codecs_str._add_signed)

    decode = classmethod(_codecs_str.decode)

    fwx256unbin = classmethod(_codecs_str.fwx256unbin)

    b512file_decode = staticmethod(_b512file.b512file_decode)

    b512file_encode_bytes = staticmethod(_b512file.b512file_encode_bytes)

    b512file_decode_bytes = staticmethod(_b512file.b512file_decode_bytes)

    pb512file_encode_bytes = staticmethod(_b512file.pb512file_encode_bytes)

    pb512file_decode_bytes = staticmethod(_b512file.pb512file_decode_bytes)

    bi512encode = staticmethod(_codecs_str.bi512encode)

    # CODELESS ENCODE - SECURITY: ❙
    a512encode = staticmethod(_codecs_str.a512encode)

    a512decode = staticmethod(_codecs_str.a512decode)

    # b1024encode retired in 3.6.5 — was bi512encode(a512encode(string)).
    # Caller code that needs the same byte-for-byte output should compose
    # the two primitives directly. Removed for parity with the C++ and
    # Java runtimes and to trim a large chunk of cross-runtime test time
    # the alias contributed without adding any new behavior.

    # CODELESS ENCODE - SECURITY: ❙
    _coerce_text = staticmethod(_codecs_str._coerce_text)

    b256decode = classmethod(_codecs_str.b256decode)

    b256encode = classmethod(_codecs_str.b256encode)

# ENCRYPTION TYPES:
# BASE64 - b64encode/b64decode  V1.0
# HASH512 - hash512  V1.0
# HASH512U - uhash513 V1.2
# FWX512RP - pb512encode/pb512encode V2.0
# FWX512R - b512encode/b512decode V2.0 ★
# FWX512I - bi512encode V3.4 ★
# FWX512C - a512encode/a512decode V2.0 ❗❗❗ (NOT RECCOMENDED)
# FWX256R - b256encode/b256decode V1.3 ❗❗❗ (NOT RECCOMENDED)

# HOW TO USE: basefwx.ENCRYPTION-TYPE("text","password")


basefwx._warn_single_thread_api()
