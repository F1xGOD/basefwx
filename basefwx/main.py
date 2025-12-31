# BASEFWX ENCRYPTION ENGINE ->

import os as _os_module
import re as _re_module


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
    from PIL import Image
    from io import BytesIO
    import numpy as np
    import os
    import zlib
    import hashlib
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
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pqcrypto.kem import ml_kem_768
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
    ENGINE_VERSION = "3.5.2"
    MASTER_PQ_ALG = "ml-kem-768"
    MASTER_PQ_PUBLIC = b"eJwBoARf+9Kzz6BzXHi8fntsVzKBAxCzV6VTNfbCvfAqh+jMdEfccE7UR4Nnbl+roH3ML55Adeabfs6kZ3CgSZijRTWJDbaUXj+LX391QXOnTa7rNEg1qTaxSa1DKmFZwY+kCRlyjP8BWUY0P9c2NLHDiHlBObDRjUyWrbb1YdiJXfITJz3bvBlnRLTQIRSpH042LZy1CwpQT+C0ISO5tc9qkDocWZ3Jx8+Avd0KcY2TP8rcCY4kY/7JR4xWiRV6e1wnz3BnQxdivx4jPusMo8VnlInHhYlSJvEIHDgqo5WjScSIKkT0UNXknxWgb5mpoB/poD4gtyCWA57iGarFM6k3oZZnRjMilMAwvQ8bGCRxnDLsnJPCEpTkDP2Ek7LDSGv6KaG3ManmIaAoZH4mpxAmePaRkTSKYuE7vMeVqeyxl394QUZrfi/YirIhfom6SYIChFzlAgHAZCPMx+9FVzmVxicnvlKRPCWITkFRnkVraxZ8x9S4OR9HzT4G0BEsj/sKOY5VeAi6c82ricH6HnaJB+eEvhjiTssSoxnBX9vUbftnLjFqTMPctY1DgmTabWz1U23rffPSqo0zeDxIlR0FD1foxs9gc9JSR/MChL2ZzFLAUqq7QBPWxHsrjN8VO86FyG64VncSQvtwEPR5kRQgEgoBkqsHHnOVBov3le/mB9oBbPDzCTw7rPchTzNWVvwDOS/bfkmQIlOKKENZLvMInF6ktaLGiAzhy0eob5g7dMFwLCnDU/iQjQqZbyIMVCqMuBlgTFHhPWgKErNwcnIMPEoYg+mstgJIq272I7VCX9usoSjWXZX6SViIpg8FrS2RFCzmXPEpbCQHcg9arbxCD+cZIWfxVmxFx1y4Od2Eb/FkZTt6Maq4zMNalRfBjX/0C0C1aetQWiJ8HCvkZufLlYwAwovRJE+7wkXDgQLMe6dwzzo6ydEJM32kJBuzhjxjMGd4BY8JGKzKVBeJhsMLaViBGw5SEiXWgZhUbECktcJDrfc6r8PBgcQwV1TpU3pTcNNHFt1YoAMCpO9XdO7cDfnbaqRbBUY0hr3sI3P0x962F7rkR45xEGzFZp9XfmsRmG5qHfSTk4EGyS0cdFoDZ51Rvw/4e738wo4QRJGkDBGagROXzbwnmpSpV+cxXvK0Su5FIaGhJQHJqTQTv94Gy710eE43GffqEuT6D4X6mRclSBNGTepgGq6laanzJSp3UcVwFZwCNjdbCB+ycdkqR77muhUgnxHAcZvRf4oXx0pnkGx2Px/gvvAaZGLmqv16jFFZj3pocKlIrVBiSduoYy/CBkehUQDoeykgZs73zhGklAi1NBTBkXjgasYySO2UuS8bSINJfKLqUHOsfbB6sEOLilCaPfCcRtqafMqYJwdXW+KwgpmXqbV0I+nyqAVMIpRmwMYjpBxEkV5CMRgHyEnMr2cBXuv8RcjZfLmMbCATfNcJdEuQUXDjfE4nr94DHERSk8y3IkE7paIUbGV4jgGnFtEYUiZ6ADewLTFDDTmFpRA7jCjytuukSqmmdchYYLIgQnRmTRk3AZbnMbwxkgwy86skVNZZYldaxFdWvulRMd1FgnQn5Q=="
    IMAGECIPHER_SCRAMBLE_CONTEXT = b'basefwx.imagecipher.scramble.v1'
    IMAGECIPHER_OFFSET_CONTEXT = b'basefwx.imagecipher.offset.v1'
    IMAGECIPHER_AEAD_INFO = b'basefwx.image.v1'
    IMAGECIPHER_STREAM_INFO = b'basefwx.imagecipher.stream.v1'
    IMAGECIPHER_ARCHIVE_INFO = b'basefwx.imagecipher.archive.v1'
    IMAGECIPHER_TRAILER_MAGIC = b'JMG0'
    ENABLE_B512_AEAD = os.getenv("BASEFWX_B512_AEAD", "1") == "1"
    B512_AEAD_INFO = b'basefwx.b512file.v1'
    B512_FILE_MASK_INFO = b'basefwx.b512file.mask.v1'
    ENABLE_OBFUSCATION = os.getenv("BASEFWX_OBFUSCATE", "1") == "1"
    OBF_INFO_MASK = b'basefwx.obf.mask.v1'
    OBF_INFO_PERM = b'basefwx.obf.perm.v1'
    STREAM_THRESHOLD = 250 * 1024
    STREAM_CHUNK_SIZE = 1 << 20  # 1 MiB streaming blocks
    STREAM_MAGIC = b'STRMOBF1'
    STREAM_INFO_KEY = b'basefwx.stream.obf.key.v1'
    STREAM_INFO_IV = b'basefwx.stream.obf.iv.v1'
    STREAM_INFO_PERM = b'basefwx.stream.obf.perm.v1'
    HEAVY_PBKDF2_ITERATIONS = 1_000_000
    HEAVY_ARGON2_TIME_COST = 5
    HEAVY_ARGON2_MEMORY_COST = 2 ** 17
    HEAVY_ARGON2_PARALLELISM = max(1, os.cpu_count() or 1)
    OFB_FAST_MIN = 64 * 1024
    PERM_FAST_MIN = 4 * 1024
    USER_KDF_SALT_SIZE = 16
    USER_KDF_ITERATIONS = 200_000
    if _Argon2Type is None:
        class _FallbackArgon2Type(enum.Enum):
            ID = 2
        Argon2Type = _FallbackArgon2Type
    else:
        Argon2Type = _Argon2Type
    hash_secret_raw = _argon2_hash_secret_raw
    _ARGON2_AVAILABLE = hash_secret_raw is not None
    USER_KDF_DEFAULT = "argon2id" if _ARGON2_AVAILABLE else "pbkdf2"
    USER_KDF = os.getenv("BASEFWX_USER_KDF", USER_KDF_DEFAULT).lower()
    if not _ARGON2_AVAILABLE:
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
    _CPU_COUNT = max(1, os.cpu_count() or 1)
    _PARALLEL_CHUNK_SIZE = 1 << 20  # 1 MiB chunks when fan-out encoding
    _SILENT_MODE: typing.ClassVar[bool] = False
    PQ_CIPHERTEXT_SIZE = getattr(ml_kem_768, "CIPHERTEXT_SIZE", 0)
    AEAD_NONCE_LEN = 12
    AEAD_TAG_LEN = 16
    EPHEMERAL_KEY_LEN = 32
    USER_WRAP_FIXED_LEN = USER_KDF_SALT_SIZE + AEAD_NONCE_LEN + AEAD_TAG_LEN + EPHEMERAL_KEY_LEN  # salt + nonce + tag + key
    FWXAES_MAGIC = b"FWX1"
    FWXAES_ALGO = 0x01
    FWXAES_KDF_PBKDF2 = 0x01
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
    _DECODE_MAP: typing.ClassVar[dict[str, str]] = {v: k for k, v in _CODE_MAP.items()}
    _DECODE_PATTERN = _re_module.compile(
        "|".join(
            _re_module.escape(token) for token in sorted(_DECODE_MAP, key=len, reverse=True)
        )
    )

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
                empty_part = '❚' * (width - filled)
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

                # normal write path
                self._write(line1, line2)

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
    def _obfuscate_bytes(data: bytes, ephemeral_key: bytes) -> bytes:
        if not data:
            return data
        perm_seed_bytes = basefwx._hkdf(
            basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
            ephemeral_key,
            16
        )
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        out = bytearray(data)
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        out.reverse()
        basefwx._permute_inplace(out, perm_seed)
        basefwx._del('perm_seed')
        return bytes(out)

    @staticmethod
    def _deobfuscate_bytes(data: bytes, ephemeral_key: bytes) -> bytes:
        if not data:
            return data
        perm_seed_bytes = basefwx._hkdf(
            basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
            ephemeral_key,
            16
        )
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        out = bytearray(data)
        basefwx._unpermute_inplace(out, perm_seed)
        out.reverse()
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        basefwx._del('perm_seed')
        return bytes(out)

    class _StreamObfuscator:
        """Chunked obfuscation helper for large AES-heavy payloads."""

        _SALT_LEN = 16

        def __init__(self, cipher, perm_material: bytes):
            self._cipher = cipher
            self._perm_material = perm_material
            self._chunk_index = 0

        @staticmethod
        def generate_salt() -> bytes:
            return basefwx.os.urandom(basefwx._StreamObfuscator._SALT_LEN)

        @classmethod
        def for_password(cls, password: str, salt: bytes) -> "_StreamObfuscator":
            if not isinstance(password, str):
                raise TypeError("password must be a string for streaming obfuscation")
            if not password:
                raise ValueError("Password required for streaming obfuscation")
            if len(salt) < cls._SALT_LEN:
                raise ValueError("Streaming obfuscation salt must be at least 16 bytes")
            base_material = password.encode('utf-8') + salt
            mask_key = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_KEY, length=32)
            iv = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_IV, length=16)
            perm_material = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_PERM, length=32)
            cipher = basefwx.Cipher(basefwx.algorithms.AES(mask_key), basefwx.modes.CTR(iv)).encryptor()
            return cls(cipher, perm_material)

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
            forward_chunk: "basefwx.typing.Callable[[bytes], None]",
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
        ) -> int:
            encoder = cls.for_password(password, salt)
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
            progress_cb: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
        ) -> int:
            decoder = cls.for_password(password, salt)
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
        obfuscation: "basefwx.typing.Optional[bool]" = None,
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
        password: str,
        use_master: bool,
        *,
        mask_info: bytes,
        require_password: bool,
        aad: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[bytes, bytes, bytes, bool]":
        if require_password and not password:
            raise ValueError("Password required for this mode")
        pubkey = basefwx._load_master_pq_public() if use_master else None
        use_master_effective = use_master and pubkey is not None
        if not password and not use_master_effective:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        if use_master_effective:
            kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(pubkey)
            master_blob = kem_ct
            mask_key = basefwx._hkdf_sha256(kem_shared, info=mask_info)
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
        password: str,
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
    def _resolve_password(password: str, use_master: bool = True) -> str:
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

        if basefwx.os.path.isfile(password):
            with open(password, "r", encoding="utf-8") as handle:
                password = handle.read()
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
        password: str,
        salt: "basefwx.typing.Optional[bytes]" = None,
        *,
        length: int = 32,
        time_cost: int = 3,
        memory_cost: int = 2 ** 15,
        parallelism: int = 4
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if salt is None:
            salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        if basefwx.hash_secret_raw is None:
            raise RuntimeError("Argon2 backend unavailable")
        key = basefwx.hash_secret_raw(
            password.encode("utf-8"),
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=length,
            type=basefwx.Argon2Type.ID
        )
        return key, salt

    @staticmethod
    def _derive_user_key_pbkdf2(
        password: str,
        salt: bytes,
        *,
        iterations: int | None = None,
        length: int = 32
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        iterations = iterations or basefwx.USER_KDF_ITERATIONS
        kdf = basefwx.PBKDF2HMAC(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations
        )
        return kdf.derive(password.encode("utf-8")), salt

    @staticmethod
    def _derive_user_key(
        password: str,
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
        requested_kdf = (kdf or basefwx.USER_KDF or basefwx.USER_KDF_DEFAULT).lower()
        if requested_kdf in {"argon2", "argon2id"}:
            if basefwx.hash_secret_raw is None:
                if kdf is not None:
                    raise RuntimeError("Argon2 KDF requested but argon2 backend is unavailable")
                if not basefwx._WARNED_ARGON2_MISSING:
                    print("Warning: argon2 backend unavailable, falling back to PBKDF2.")
                    basefwx._WARNED_ARGON2_MISSING = True
                requested_kdf = "pbkdf2"
            else:
                return basefwx._derive_user_key_argon2id(
                    password,
                    salt,
                    time_cost=argon2_time_cost or 3,
                    memory_cost=argon2_memory_cost or (2 ** 15),
                    parallelism=argon2_parallelism or basefwx._CPU_COUNT
                )
        return basefwx._derive_user_key_pbkdf2(password, salt, iterations=iterations)

    @staticmethod
    def encryptAES(
        plaintext: str,
        user_key: str,
        use_master: bool = True,
        *,
        metadata_blob: "basefwx.typing.Optional[str]" = None,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        kdf: "basefwx.typing.Optional[str]" = None,
        progress_callback: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None,
        obfuscate: bool = True,
        kdf_iterations: "basefwx.typing.Optional[int]" = None,
        argon2_time_cost: "basefwx.typing.Optional[int]" = None,
        argon2_memory_cost: "basefwx.typing.Optional[int]" = None,
        argon2_parallelism: "basefwx.typing.Optional[int]" = None
    ) -> bytes:
        if not user_key and not use_master:
            raise ValueError("Cannot encrypt without user password or master key")
        basefwx.sys.set_int_max_str_digits(2000000000)
        metadata_blob = metadata_blob if metadata_blob is not None else basefwx._split_metadata(plaintext)[0]
        metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
        aad = metadata_bytes if metadata_bytes else b''
        pq_public = master_public_key if master_public_key is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and pq_public is not None
        if use_master_effective:
            kem_ciphertext, kem_shared = basefwx.ml_kem_768.encrypt(pq_public)
            master_payload = kem_ciphertext
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
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
            payload_bytes = basefwx._obfuscate_bytes(payload_bytes, ephemeral_key)

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
        key: str = "",
        use_master: bool = True,
        *,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        allow_legacy: "basefwx.typing.Optional[bool]" = None,
        progress_callback: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
    ) -> str:
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
        offset = 0
        ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
        ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
        payload_blob, offset = read_chunk(encrypted_blob, offset)
        master_blob_present = len(ephemeral_enc_master) > 0
        user_blob_present = len(ephemeral_enc_user) > 0

        if len(payload_blob) < 4:
            if legacy_allowed:
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Ciphertext payload truncated")

        metadata_len = int.from_bytes(payload_blob[:4], 'big')
        metadata_end = 4 + metadata_len
        if metadata_end > len(payload_blob):
            if legacy_allowed:
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Malformed payload metadata header")
        metadata_bytes = payload_blob[4:metadata_end]
        try:
            metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ""
        except UnicodeDecodeError:
            metadata_blob = ""
        aad = metadata_bytes if metadata_bytes else b''
        meta_info = basefwx._decode_metadata(metadata_blob) if metadata_blob else {}
        should_deobfuscate = basefwx.ENABLE_OBFUSCATION and meta_info.get("ENC-OBF", "yes") != "no"

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
                    print("⚠️  User-branch AEAD authentication failed; attempting legacy CBC decrypt.")
                    return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
                raise ValueError("User branch authentication failed; incorrect password or tampering") from exc
        else:
            if legacy_allowed:
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
            payload_bytes = basefwx._deobfuscate_bytes(payload_bytes, ephemeral_key)
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
    def _kdf_pbkdf2_raw(password: bytes, salt: bytes, iters: int) -> bytes:
        kdf = basefwx.PBKDF2HMAC(
            algorithm=basefwx.hashes.SHA256(),
            length=basefwx.FWXAES_KEY_LEN,
            salt=salt,
            iterations=iters
        )
        return kdf.derive(password)

    @staticmethod
    def fwxAES_encrypt_raw(
        plaintext: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
    ) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("fwxAES_encrypt_raw expects bytes")
        pw = basefwx._coerce_password_bytes(password)
        salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
        iv = basefwx.os.urandom(basefwx.FWXAES_IV_LEN)
        key = basefwx._kdf_pbkdf2_raw(pw, salt, basefwx.FWXAES_PBKDF2_ITERS)
        aesgcm = basefwx.AESGCM(key)
        ct = aesgcm.encrypt(iv, bytes(plaintext), basefwx.FWXAES_AAD)
        header = bytearray()
        header += basefwx.FWXAES_MAGIC
        header += bytes([
            basefwx.FWXAES_ALGO,
            basefwx.FWXAES_KDF_PBKDF2,
            basefwx.FWXAES_SALT_LEN,
            basefwx.FWXAES_IV_LEN
        ])
        header += basefwx.struct.pack(">I", basefwx.FWXAES_PBKDF2_ITERS)
        header += basefwx.struct.pack(">I", len(ct))
        return bytes(header) + salt + iv + ct

    @staticmethod
    def fwxAES_decrypt_raw(
        blob: bytes,
        password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
    ) -> bytes:
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("fwxAES_decrypt_raw expects bytes")
        blob_bytes = bytes(blob)
        header_len = 4 + 1 + 1 + 1 + 1 + 4 + 4
        if len(blob_bytes) < header_len:
            raise ValueError("fwxAES blob too short")
        if blob_bytes[:4] != basefwx.FWXAES_MAGIC:
            raise ValueError("fwxAES bad magic")
        algo, kdf, salt_len, iv_len = blob_bytes[4], blob_bytes[5], blob_bytes[6], blob_bytes[7]
        if algo != basefwx.FWXAES_ALGO or kdf != basefwx.FWXAES_KDF_PBKDF2:
            raise ValueError("fwxAES unsupported algo/kdf")
        iters = basefwx.struct.unpack(">I", blob_bytes[8:12])[0]
        ct_len = basefwx.struct.unpack(">I", blob_bytes[12:16])[0]
        off = 16
        if len(blob_bytes) < off + salt_len + iv_len + ct_len:
            raise ValueError("fwxAES blob truncated")
        salt = blob_bytes[off:off + salt_len]
        off += salt_len
        iv = blob_bytes[off:off + iv_len]
        off += iv_len
        ct = blob_bytes[off:off + ct_len]
        pw = basefwx._coerce_password_bytes(password)
        key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        aesgcm = basefwx.AESGCM(key)
        return aesgcm.decrypt(iv, ct, basefwx.FWXAES_AAD)

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
        output: "basefwx.typing.Optional[str]" = None,
        normalize: bool = False,
        normalize_threshold: "basefwx.typing.Optional[int]" = None,
        cover_phrase: str = "low taper fade",
        compress: bool = False,
        ignore_media: bool = False,
        keep_meta: bool = False,
        keep_input: bool = False
    ) -> str:
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
            plain = basefwx.fwxAES_decrypt_raw(blob, password)
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
        blob = basefwx.fwxAES_encrypt_raw(payload, password)
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
    def hash512(string: str):

        return basefwx.hashlib.sha256(string.encode('utf-8')).hexdigest()

    @staticmethod
    def uhash513(string: str):

        sti = string
        return basefwx.hashlib.sha256(basefwx.b512encode(basefwx.hashlib.sha512(
            basefwx.hashlib.sha1(
                basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                "utf-8")).hexdigest(), basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
            'utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(t, p, use_master: bool = True):
        """
        Reversible obfuscation helper; confidentiality comes from AEAD layers, not this routine.
        """
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            p,
            use_master,
            mask_info=b'basefwx.pb512.mask.v1',
            require_password=True,
            aad=b'pb512'
        )
        plain_bytes = t.encode('utf-8')
        masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.pb512.stream.v1')
        payload = b'\x02' + len(plain_bytes).to_bytes(4, 'big') + masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, payload)
        result = basefwx.base64.b64encode(blob).decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def pb512decode(digs, key, use_master: bool = True):
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            raw = basefwx.base64.b64decode(digs)
        except Exception as exc:
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
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

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
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for x in arr:
                h += 1
                if x != "":
                    if h == 1:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

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
        payload = b'\x02' + len(plain_bytes).to_bytes(4, 'big') + masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, payload)
        result = basefwx.base64.b64encode(blob).decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def b512decode(enc, key="", use_master: bool = True):
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
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
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

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
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for xx in arr:
                h += 1
                if xx != "":
                    if h == 1:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

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
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", display_path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
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
        if input_size >= basefwx.STREAM_THRESHOLD and basefwx.ENABLE_B512_AEAD:
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
        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        stream_salt = basefwx._StreamObfuscator.generate_salt()
        ext_bytes = (path.suffix or "").encode('utf-8')

        metadata_blob = basefwx._build_metadata(
            "FWX512R",
            strip_metadata,
            use_master_effective,
            mode="STREAM",
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
        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
        heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
        heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
        stream_salt = basefwx._StreamObfuscator.generate_salt()
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            mode="STREAM",
            obfuscation=True,
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

                decoder = basefwx._StreamObfuscator.for_password(password, stream_salt)
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
            pubkey_bytes = basefwx._load_master_pq_public() if use_master else None
            effective_use_master = use_master and not strip_metadata and pubkey_bytes is not None
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
        encode_use_master = use_master and not strip_metadata and master_pubkey is not None
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
                                master_pubkey,
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
                                master_pubkey,
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
        def _image_primitives(password: str, num_pixels: int, channels: int) -> "basefwx.typing.Tuple[basefwx.np.ndarray, basefwx.typing.Optional[basefwx.np.ndarray], basefwx.np.ndarray, bytes]":
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
        def encrypt_image_inv(path: str, password: str, output: str | None = None) -> str:
            path_obj = basefwx.pathlib.Path(path)
            basefwx._ensure_existing_file(path_obj)
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
            mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(password, num_pixels, channels)
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
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO)
            archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, basefwx.IMAGECIPHER_ARCHIVE_INFO)
            with open(output_path, 'ab') as handle:
                handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
                handle.write(len(archive_blob).to_bytes(4, 'big'))
                handle.write(archive_blob)

            basefwx._del('mask')
            basefwx._del('rotations')
            basefwx._del('perm')
            basefwx._del('flat')
            basefwx._del('arr')
            basefwx._del('material')
            basefwx._del('archive_key')
            basefwx._del('archive_blob')
            basefwx._del('original_bytes')
            print(f"🔥 Encrypted image → {output_path}")
            return str(output_path)

        @staticmethod
        def decrypt_image_inv(path: str, password: str, output: str | None = None) -> str:
            path_obj = basefwx.pathlib.Path(path)
            basefwx._ensure_existing_file(path_obj)
            output_path = basefwx.pathlib.Path(output) if output else basefwx.ImageCipher._default_decrypted_path(path_obj)
            file_bytes = path_obj.read_bytes()
            magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
            marker_idx = file_bytes.rfind(magic)
            orig_blob = None
            payload_bytes = file_bytes
            if marker_idx >= 0 and marker_idx + len(magic) + 4 <= len(file_bytes):
                length = int.from_bytes(file_bytes[marker_idx + len(magic):marker_idx + len(magic) + 4], 'big')
                blob_start = marker_idx + len(magic) + 4
                blob_end = blob_start + length
                if blob_end <= len(file_bytes):
                    orig_blob = file_bytes[blob_start:blob_end]
                    payload_bytes = file_bytes[:marker_idx]
            arr, mode, fmt = basefwx.ImageCipher._load_image(path_obj, payload_bytes)
            shape = arr.shape
            if arr.ndim == 2:
                channels = 1
                flat = arr.reshape(-1, 1).astype(basefwx.np.uint8, copy=True)
            else:
                channels = shape[2]
                flat = arr.reshape(-1, channels).astype(basefwx.np.uint8, copy=True)
            num_pixels = flat.shape[0]
            mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(password, num_pixels, channels)
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO)
            if orig_blob is not None:
                try:
                    original_bytes = basefwx._aead_decrypt(archive_key, orig_blob, basefwx.IMAGECIPHER_ARCHIVE_INFO)
                    output_path.write_bytes(original_bytes)
                    basefwx._del('mask')
                    basefwx._del('rotations')
                    basefwx._del('perm')
                    basefwx._del('flat')
                    basefwx._del('arr')
                    basefwx._del('material')
                    basefwx._del('archive_key')
                    print(f"✅ Decrypted image → {output_path}")
                    return str(output_path)
                except Exception:
                    pass
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
        VIDEO_BLOCK_SIZE = 16
        AUDIO_BLOCK_SECONDS = 0.05
        AUDIO_GROUP_SECONDS = 1.0

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

        @staticmethod
        def _ensure_ffmpeg() -> None:
            if basefwx.shutil.which("ffmpeg") and basefwx.shutil.which("ffprobe"):
                return
            raise RuntimeError("ffmpeg/ffprobe are required for audio/video processing")

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
                "-show_entries", "stream=codec_type,width,height,avg_frame_rate,r_frame_rate,sample_rate,channels",
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
            if video:
                fps = basefwx.MediaCipher._parse_rate(
                    video.get("avg_frame_rate") or video.get("r_frame_rate") or ""
                )
                info["video"] = {
                    "width": int(video.get("width") or 0),
                    "height": int(video.get("height") or 0),
                    "fps": fps
                }
            if audio:
                info["audio"] = {
                    "sample_rate": int(audio.get("sample_rate") or 0),
                    "channels": int(audio.get("channels") or 0)
                }
            return info

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
        def _derive_base_key(password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]") -> bytes:
            material = basefwx.MediaCipher._derive_media_material(password)
            return material[:32]

        @staticmethod
        def _derive_media_material(
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> bytes:
            return basefwx._derive_key_material(
                basefwx._coerce_password_bytes(password),
                basefwx.IMAGECIPHER_STREAM_INFO,
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
        def _scramble_video_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            width: int,
            height: int,
            fps: float,
            base_key: bytes
        ) -> None:
            frame_size = width * height * 3
            if frame_size <= 0:
                raise ValueError("Invalid video dimensions")
            group_frames = max(2, int(round((fps or 30.0) * basefwx.MediaCipher.VIDEO_GROUP_SECONDS)))
            with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                frame_index = 0
                group_index = 0
                while True:
                    group_start_index = frame_index
                    frames: "list[bytes]" = []
                    for _ in range(group_frames):
                        data = src.read(frame_size)
                        if not data or len(data) < frame_size:
                            break
                        material = basefwx.MediaCipher._unit_material(base_key, b"jmg-frame", frame_index, 48)
                        key = material[:32]
                        iv = material[32:48]
                        masked = basefwx.MediaCipher._aes_ctr_transform(data, key, iv)
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, b"jmg-fblk", frame_index, 16)
                        seed = int.from_bytes(seed_bytes, "big")
                        shuffled = basefwx.MediaCipher._shuffle_frame_blocks(
                            masked,
                            width,
                            height,
                            3,
                            seed,
                            basefwx.MediaCipher.VIDEO_BLOCK_SIZE
                        )
                        frames.append(shuffled)
                        frame_index += 1
                    if not frames:
                        break
                    seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, b"jmg-fgrp", seed_index, 16)
                    seed = int.from_bytes(seed_bytes, "big")
                    perm = basefwx.MediaCipher._permute_indices(len(frames), seed)
                    for idx in perm:
                        dst.write(frames[idx])
                    group_index += 1

        @staticmethod
        def _scramble_audio_raw(
            raw_in: "basefwx.pathlib.Path",
            raw_out: "basefwx.pathlib.Path",
            sample_rate: int,
            channels: int,
            base_key: bytes
        ) -> None:
            if sample_rate <= 0 or channels <= 0:
                raise ValueError("Invalid audio stream parameters")
            samples_per_block = max(1, int(round(sample_rate * basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            block_size = samples_per_block * channels * 2
            group_blocks = max(2, int(round(basefwx.MediaCipher.AUDIO_GROUP_SECONDS / basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
            with open(raw_in, "rb") as src, open(raw_out, "wb") as dst:
                block_index = 0
                group_index = 0
                while True:
                    group_start_index = block_index
                    blocks: "list[bytes]" = []
                    for _ in range(group_blocks):
                        data = src.read(block_size)
                        if not data:
                            break
                        material = basefwx.MediaCipher._unit_material(base_key, b"jmg-ablock", block_index, 48)
                        key = material[:32]
                        iv = material[32:48]
                        masked = basefwx.MediaCipher._aes_ctr_transform(data, key, iv)
                        blocks.append(masked)
                        block_index += 1
                    if not blocks:
                        break
                    seed_index = (group_index * 0x9E3779B97F4A7C15) ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, b"jmg-agrp", seed_index, 16)
                    seed = int.from_bytes(seed_bytes, "big")
                    perm = basefwx.MediaCipher._permute_indices(len(blocks), seed)
                    for idx in perm:
                        dst.write(blocks[idx])
                    group_index += 1

        @staticmethod
        def _encrypt_metadata(
            tags: "dict[str, str]",
            password_text: str
        ) -> "list[str]":
            encoded_args: "list[str]" = []
            for key, value in tags.items():
                try:
                    enc = basefwx.b512encode(value, password_text, use_master=False)
                except Exception:
                    continue
                encoded_args.append(f"{key}={enc}")
            return encoded_args

        @staticmethod
        def _append_trailer(
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            original_bytes: bytes
        ) -> None:
            material = basefwx.MediaCipher._derive_media_material(password)
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
            archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, basefwx.IMAGECIPHER_ARCHIVE_INFO)
            with open(output_path, "ab") as handle:
                handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
                handle.write(len(archive_blob).to_bytes(4, "big"))
                handle.write(archive_blob)

        @staticmethod
        def _decrypt_trailer(
            file_bytes: bytes,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]"
        ) -> "basefwx.typing.Optional[bytes]":
            magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
            marker_idx = file_bytes.rfind(magic)
            if marker_idx < 0 or marker_idx + len(magic) + 4 > len(file_bytes):
                return None
            length = int.from_bytes(
                file_bytes[marker_idx + len(magic):marker_idx + len(magic) + 4],
                "big"
            )
            blob_start = marker_idx + len(magic) + 4
            blob_end = blob_start + length
            if blob_end > len(file_bytes):
                return None
            blob = file_bytes[blob_start:blob_end]
            material = basefwx.MediaCipher._derive_media_material(password)
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
            return basefwx._aead_decrypt(archive_key, blob, basefwx.IMAGECIPHER_ARCHIVE_INFO)

        @staticmethod
        def _run_ffmpeg(cmd: "list[str]") -> None:
            result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "ffmpeg failed")

        @staticmethod
        def _scramble_video(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            keep_meta: bool
        ) -> None:
            password_text = basefwx._coerce_password_bytes(password).decode("utf-8", "ignore")
            info = basefwx.MediaCipher._probe_streams(path)
            video = info.get("video")
            if not video:
                raise ValueError("No video stream found")
            width = int(video.get("width") or 0)
            height = int(video.get("height") or 0)
            fps = float(video.get("fps") or 0.0)
            audio = info.get("audio")

            temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-media-")
            try:
                raw_video = basefwx.pathlib.Path(temp_dir.name) / "video.raw"
                raw_video_out = basefwx.pathlib.Path(temp_dir.name) / "video.scr.raw"
                cmd_video = [
                    "ffmpeg", "-y", "-i", str(path),
                    "-map", "0:v:0",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    str(raw_video)
                ]
                basefwx.MediaCipher._run_ffmpeg(cmd_video)

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
                    basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                    sample_rate = sample_rate or 48000
                    channels = channels or 2

                base_key = basefwx.MediaCipher._derive_base_key(password)
                basefwx.MediaCipher._scramble_video_raw(raw_video, raw_video_out, width, height, fps, base_key)
                if raw_audio and raw_audio_out:
                    basefwx.MediaCipher._scramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key)

                cmd = [
                    "ffmpeg", "-y",
                    "-f", "rawvideo",
                    "-pix_fmt", "rgb24",
                    "-s", f"{width}x{height}",
                    "-r", str(fps or 30),
                    "-i", str(raw_video_out)
                ]
                if raw_audio_out:
                    cmd += [
                        "-f", "s16le",
                        "-ar", str(sample_rate),
                        "-ac", str(channels),
                        "-i", str(raw_audio_out),
                        "-shortest"
                    ]
                if keep_meta:
                    tags = basefwx.MediaCipher._probe_metadata(path)
                    for meta in basefwx.MediaCipher._encrypt_metadata(tags, password_text):
                        cmd += ["-metadata", meta]
                else:
                    cmd += ["-map_metadata", "-1"]
                cmd.append(str(output_path))
                basefwx.MediaCipher._run_ffmpeg(cmd)
            finally:
                temp_dir.cleanup()

        @staticmethod
        def _scramble_audio(
            path: "basefwx.pathlib.Path",
            output_path: "basefwx.pathlib.Path",
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            keep_meta: bool
        ) -> None:
            password_text = basefwx._coerce_password_bytes(password).decode("utf-8", "ignore")
            info = basefwx.MediaCipher._probe_streams(path)
            audio = info.get("audio")
            if not audio:
                raise ValueError("No audio stream found")
            sample_rate = int(audio.get("sample_rate") or 0)
            channels = int(audio.get("channels") or 0)
            sample_rate = sample_rate or 48000
            channels = channels or 2

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
                base_key = basefwx.MediaCipher._derive_base_key(password)
                basefwx.MediaCipher._scramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key)

                cmd = [
                    "ffmpeg", "-y",
                    "-f", "s16le",
                    "-ar", str(sample_rate),
                    "-ac", str(channels),
                    "-i", str(raw_audio_out)
                ]
                if keep_meta:
                    tags = basefwx.MediaCipher._probe_metadata(path)
                    for meta in basefwx.MediaCipher._encrypt_metadata(tags, password_text):
                        cmd += ["-metadata", meta]
                else:
                    cmd += ["-map_metadata", "-1"]
                cmd.append(str(output_path))
                basefwx.MediaCipher._run_ffmpeg(cmd)
            finally:
                temp_dir.cleanup()

        @staticmethod
        def encrypt_media(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None,
            *,
            keep_meta: bool = False,
            keep_input: bool = False
        ) -> str:
            path_obj = basefwx._normalize_path(path)
            basefwx._ensure_existing_file(path_obj)
            if not password:
                raise ValueError("Password is required for media encryption")
            password_text = basefwx._coerce_password_bytes(password).decode("utf-8", "ignore")
            output_path = basefwx.pathlib.Path(output) if output else path_obj
            temp_output = output_path
            if basefwx._normalize_path(output_path) == basefwx._normalize_path(path_obj):
                temp_output = output_path.with_name(f"{output_path.stem}._jmg{output_path.suffix}")

            original_bytes = path_obj.read_bytes()
            suffix = path_obj.suffix.lower()
            append_trailer = True
            if suffix in basefwx.MediaCipher.IMAGE_EXTS:
                result = basefwx.ImageCipher.encrypt_image_inv(str(path_obj), password_text, output=str(temp_output))
                append_trailer = False
            else:
                info = basefwx.MediaCipher._probe_streams(path_obj)
                if info.get("video"):
                    basefwx.MediaCipher._scramble_video(path_obj, temp_output, password, keep_meta)
                    result = str(temp_output)
                elif info.get("audio"):
                    basefwx.MediaCipher._scramble_audio(path_obj, temp_output, password, keep_meta)
                    result = str(temp_output)
                else:
                    raise ValueError("Unsupported media format")

            out_path = basefwx._normalize_path(result)
            if out_path != temp_output:
                temp_output = out_path
            if append_trailer:
                basefwx.MediaCipher._append_trailer(temp_output, password, original_bytes)
            if basefwx._normalize_path(output_path) != basefwx._normalize_path(temp_output):
                basefwx.os.replace(temp_output, output_path)
                temp_output = output_path
            basefwx._remove_input(path_obj, keep_input, output_path=temp_output)
            return str(temp_output)

        @staticmethod
        def decrypt_media(
            path: str,
            password: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
            output: str | None = None
        ) -> str:
            path_obj = basefwx._normalize_path(path)
            basefwx._ensure_existing_file(path_obj)
            if not password:
                raise ValueError("Password is required for media decryption")
            output_path = basefwx.pathlib.Path(output) if output else path_obj
            data = path_obj.read_bytes()
            plain = basefwx.MediaCipher._decrypt_trailer(data, password)
            if plain is None:
                raise ValueError("No media trailer found; unable to decrypt")
            output_path.write_bytes(plain)
            return str(output_path)
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

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
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
        metadata_blob = basefwx._build_metadata(
            "AES-LIGHT",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            obfuscation=obfuscate_payload,
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
            obfuscate=obfuscate_payload
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
                    decoder = basefwx._StreamObfuscator.for_password(password, stream_salt)
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
        if input_size >= basefwx.STREAM_THRESHOLD:
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

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
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
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            obfuscation=True,
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
            argon2_parallelism=heavy_argon_par
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

        encode_use_master = use_master and not strip_metadata and master_pubkey is not None
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
                                    master_pubkey,
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
                                    master_pubkey,
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
                                    master_pubkey,
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
                                    master_pubkey,
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
        return ''.join(cls._CODE_MAP.get(ch, ch) for ch in chunk)

    @classmethod
    def code(cls, string: str) -> str:
        if not string:
            return string
        if len(string) <= cls._PARALLEL_CHUNK_SIZE or cls._CPU_COUNT == 1:
            return cls._code_chunk(string)
        chunk_size = cls._PARALLEL_CHUNK_SIZE
        slices = [string[i:i + chunk_size] for i in range(0, len(string), chunk_size)]
        with cls.concurrent.futures.ThreadPoolExecutor(max_workers=cls._CPU_COUNT) as executor:
            parts = executor.map(cls._code_chunk, slices)
            return ''.join(parts)

    @classmethod
    def fwx256bin(cls, string: str) -> str:
        encoded = cls.base64.b32hexencode(cls.code(string).encode('utf-8')).decode('utf-8')
        padding_count = encoded.count("=")
        return encoded.rstrip("=") + str(padding_count)

    @classmethod
    def decode(cls, sttr: str) -> str:
        if not sttr:
            return sttr
        return cls._DECODE_PATTERN.sub(lambda match: cls._DECODE_MAP[match.group(0)], sttr)

    @classmethod
    def fwx256unbin(cls, string: str) -> str:
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        decoded = cls.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8')
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
    def bi512encode(string: str):

        code = string[0] + string[len(string) - 1]

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")).encode(
                'utf-8')).hexdigest()).replace("-", "0")

        return mainenc(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def a512encode(string: str):
        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        code = (str(len(mdcode((string))) * len(mdcode((string)))))

        def mainenc(string):
            return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

        return mainenc(string)

    @staticmethod
    def a512decode(string: str):

        def mcode(strin: str):
            end = strin
            eand = list(end)
            finish = ""
            ht = 0
            len = 0
            oht = 0
            for een in eand:
                ht += 1
                if een != "":
                    if ht == 1:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
                    if ht != 1 and len + oht + 1 == ht:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
            return finish

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def maindc(string):
            result = ""
            try:
                leoa = int(string[0])
                string2 = string[leoa + 1:len(string)]
                cdo = int(string[1:leoa + 1]) * int(string[1:leoa + 1])
                code = (str(cdo))
                string3 = basefwx.fwx256unbin(string2.replace("4G5tRA", "="))
                if string3[0] == "0":
                    string3 = "-" + string3[1:len(string3)]
                result = mcode(str(int(string3) + int(mdcode(code))))
            except:
                result = "AN ERROR OCCURED!"
            return result

        return maindc(string)

    # UNDCODABLE IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙❙
    @staticmethod
    def b1024encode(string: str):

        def fwx1024uBIN(string: str):
            def fwx512iiBIN(string: str):
                code = string[0] + string[len(string) - 1]

                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                def mainenc(string):
                    return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=",
                                                                                                         "4G5tRA")).encode(
                        'utf-8')).hexdigest()).replace("-", "0")

                return mainenc(string)

            def fwx512ciBIN(string: str):
                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                code = (str(len(mdcode((string))) * len(mdcode((string)))))

                def mainenc(string):
                    return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

                return mainenc(string)

            return fwx512iiBIN(fwx512ciBIN(string))

        return fwx1024uBIN(string)

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
        decoded = cls.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8')
        return cls.decode(decoded)

    @classmethod
    def b256encode(cls, data: "basefwx.typing.Union[str, bytes, bytearray, memoryview]") -> str:
        text = cls._coerce_text(data)
        raw = cls.code(text).encode('utf-8')
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


def cli(argv=None) -> int:
    import argparse

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
    cryptin.set_defaults(use_master=True, obfuscate=True)
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
        "--keep-input",
        action="store_true",
        help="Do not delete the input after encryption"
    )

    args = parser.parse_args(argv)

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
            print(f"Failed to load master public key: {exc}")
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
                        normalize=args.normalize,
                        normalize_threshold=args.normalize_threshold,
                        cover_phrase=args.cover_phrase,
                        compress=args.compress,
                        ignore_media=args.ignore_media,
                        keep_meta=args.keep_meta,
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
                print(f"{path}: {status}")
                if status != "SUCCESS!":
                    failures += 1
            return 0 if failures == 0 else 1

        # Print an extra newline to ensure separation from progress output
        print(result)
        return 0 if result == "SUCCESS!" else 1

    return 0


def main(argv=None) -> int:
    return cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
