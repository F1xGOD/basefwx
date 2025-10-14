# BASEFWX ENCRYPTION ENGINE ->

import re as _re_module


class basefwx:
    import base64
    import concurrent.futures
    import enum
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
    re = _re_module
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

    MAX_INPUT_BYTES = 20 * 1024 * 1024 * 1024  # allow up to ~20 GiB per file
    PROGRESS_BAR_WIDTH = 30
    FWX_DELIM = "A8igTOmG"
    FWX_HEAVY_DELIM = "673827837628292873"
    META_DELIM = "::FWX-META::"
    ENGINE_VERSION = "3.2.0"
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
    _WARNED_ARGON2_MISSING = False
    _MASTER_PUBKEY_OVERRIDE: typing.ClassVar[typing.Optional[bytes]] = None
    _CPU_COUNT = max(1, os.cpu_count() or 1)
    _PARALLEL_CHUNK_SIZE = 1 << 20  # 1 MiB chunks when fan-out encoding
    PQ_CIPHERTEXT_SIZE = getattr(ml_kem_768, "CIPHERTEXT_SIZE", 0)
    AEAD_NONCE_LEN = 12
    AEAD_TAG_LEN = 16
    EPHEMERAL_KEY_LEN = 32
    USER_WRAP_FIXED_LEN = USER_KDF_SALT_SIZE + AEAD_NONCE_LEN + AEAD_TAG_LEN + EPHEMERAL_KEY_LEN  # salt + nonce + tag + key
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
            self._last_render = 0.0
            self._cached_lines: "basefwx.typing.Optional[tuple[str, str]]" = None

        @staticmethod
        def _render_bar(fraction: float, width: int | None = None) -> str:
            width = width or basefwx.PROGRESS_BAR_WIDTH
            fraction = max(0.0, min(1.0, fraction))
            filled = int(fraction * width)
            bar = '=' * filled
            if filled < width:
                bar += '>'
                bar += '.' * (width - filled - 1)
            bar = bar.ljust(width, '.')
            return f"|{bar}| {fraction * 100:6.2f}%"

        @staticmethod
        def _format_size_hint(size_hint: "basefwx.typing.Tuple[int, int]") -> str:
            src, dst = size_hint
            return f"{basefwx._human_readable_size(src)} -> {basefwx._human_readable_size(dst)}"

        def _write(self, line1: str, line2: str, force: bool = False) -> None:
            now = basefwx.time.monotonic()
            self._cached_lines = (line1, line2)
            if not force and self._printed and (now - self._last_render) < self._min_interval:
                return
            cached = self._cached_lines
            if cached is None:
                return
            line1, line2 = cached
            if self._printed:
                self.stream.write('\r\033[2F')  # move up two lines and reset column
            self.stream.write('\r\033[2K' + line1 + '\n')
            self.stream.write('\r\033[2K' + line2 + '\n')
            self.stream.flush()
            self._printed = True
            self._last_render = now
            self._cached_lines = None

        def update(
            self,
            file_index: int,
            fraction: float,
            phase: str,
            path: "basefwx.pathlib.Path",
            *,
            size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        ) -> None:
            overall_fraction = (file_index + max(0.0, min(1.0, fraction))) / self.total_files
            overall = self._render_bar(overall_fraction)
            current = self._render_bar(fraction)
            label = path.name if path else ""
            line1 = f"Overall {overall} ({file_index}/{self.total_files} files complete)"
            hint_text = f" ({self._format_size_hint(size_hint)})" if size_hint else ""
            label_text = f" [{label}]" if label else ""
            line2 = f"File    {current} phase: {phase}{hint_text}{label_text}"
            self._write(line1, line2)

        def finalize_file(
            self,
            file_index: int,
            path: "basefwx.pathlib.Path",
            *,
            size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        ) -> None:
            overall_fraction = (file_index + 1) / self.total_files
            overall = self._render_bar(overall_fraction)
            label = path.name if path else ""
            current = self._render_bar(1.0)
            line1 = f"Overall {overall} ({file_index + 1}/{self.total_files} files complete)"
            hint_text = f" ({self._format_size_hint(size_hint)})" if size_hint else ""
            label_text = f" [{label}]" if label else ""
            line2 = f"File    {current} phase: done{hint_text}{label_text}"
            self._write(line1, line2, force=True)

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
            dst_handle,
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
        mode: "basefwx.typing.Optional[str]" = None
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
    def _apply_strip_attributes(path: "basefwx.pathlib.Path") -> None:
        try:
            basefwx.os.utime(path, (0, 0))
        except Exception:
            pass

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
        length: int = 32
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
            time_cost=3,
            memory_cost=2 ** 15,
            parallelism=4,
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
        kdf: "basefwx.typing.Optional[str]" = None
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
                return basefwx._derive_user_key_argon2id(password, salt)
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
        progress_callback: "basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]" = None
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
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_used
            )
            wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
            ephemeral_enc_user = user_salt + wrapped_ephemeral
        else:
            ephemeral_enc_user = b""
        payload_bytes = plaintext.encode('utf-8')
        if basefwx.ENABLE_OBFUSCATION:
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
        kdf_hint = (meta_info.get("ENC-KDF") or basefwx.USER_KDF or "argon2id").lower()
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
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_hint
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
        if basefwx.ENABLE_OBFUSCATION:
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
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
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
                input_size=input_size
            )
        data = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(data).decode('utf-8')
        ext_token = basefwx.b512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
        if reporter:
            reporter.update(file_index, 0.65, "b256", path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        use_aead = basefwx.ENABLE_B512_AEAD
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

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(output_bytes)

        approx_size = len(output_bytes)
        size_hint = (input_size, approx_size)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
            reporter.update(
                file_index,
                0.9,
                f"write (~{basefwx._human_readable_size(approx_size)})",
                output_path,
                size_hint=size_hint
            )
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
            *,
            input_size: "basefwx.typing.Optional[int]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        input_size = input_size if input_size is not None else path.stat().st_size
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)
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
            mode="STREAM"
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
            reporter.update(file_index, 0.12, "stream-setup", path, size_hint=estimated_hint)

        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix="basefwx-b512-stream-")
        cleanup_paths: "basefwx.typing.List[str]" = []
        output_path = path.with_suffix('.fwx')
        processed_plain = 0

        def _seal_progress(done_plain: int) -> None:
            if not reporter:
                return
            fraction = 0.55 + 0.3 * (done_plain / plaintext_len if plaintext_len else 0.0)
            reporter.update(file_index, fraction, "seal", path, size_hint=estimated_hint)

        def _obf_progress(done_bytes: int, total_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.2 + 0.35 * (done_bytes / total_bytes if total_bytes else 0.0)
            reporter.update(file_index, fraction, "pb512-stream", path, size_hint=estimated_hint)

        result: "basefwx.typing.Optional[basefwx.typing.Tuple[basefwx.pathlib.Path, int]]" = None
        try:
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as payload_tmp, \
                 basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as obf_tmp:
                cleanup_paths.extend([payload_tmp.name, obf_tmp.name])
                payload_tmp.write(metadata_len.to_bytes(4, 'big'))
                if metadata_bytes:
                    payload_tmp.write(metadata_bytes)
                nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
                payload_tmp.write(nonce)
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
                        payload_tmp.write(ct)
                    processed_plain += len(data)
                    _seal_progress(processed_plain)

                if prefix_bytes:
                    _write_plain(prefix_bytes)
                _write_plain(stream_header_bytes)
                basefwx._StreamObfuscator.encode_file(
                    path,
                    obf_tmp,
                    password,
                    stream_salt,
                    chunk_size=chunk_size,
                    forward_chunk=_write_plain,
                    progress_cb=_obf_progress
                )
                tail = encryptor.finalize()
                if tail:
                    payload_tmp.write(tail)
                payload_tmp.write(encryptor.tag)
                payload_len = payload_tmp.tell()
                payload_tmp.flush()
                payload_tmp.seek(0)

                with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as final_tmp:
                    cleanup_paths.append(final_tmp.name)
                    final_tmp.write(len_user.to_bytes(4, 'big'))
                    final_tmp.write(user_blob)
                    final_tmp.write(len_master.to_bytes(4, 'big'))
                    final_tmp.write(master_blob)
                    final_tmp.write(payload_len.to_bytes(4, 'big'))
                    while True:
                        chunk = payload_tmp.read(basefwx.STREAM_CHUNK_SIZE)
                        if not chunk:
                            break
                        final_tmp.write(chunk)
                    final_tmp.flush()
                    final_tmp_path = final_tmp.name

            actual_size = basefwx.os.path.getsize(final_tmp_path)
            actual_hint = (input_size, actual_size)
            basefwx.os.replace(final_tmp_path, output_path)
            cleanup_paths.remove(final_tmp_path)
            basefwx.os.remove(obf_tmp.name)
            cleanup_paths.remove(obf_tmp.name)
            if reporter:
                reporter.update(file_index, 0.9, "write", output_path, size_hint=actual_hint)
            if strip_metadata:
                basefwx._apply_strip_attributes(output_path)
                basefwx.os.chmod(output_path, 0)
            basefwx.os.remove(path)
            human = basefwx._human_readable_size(actual_size)
            print(f"{output_path.name}: approx output size {human}")
            if reporter:
                reporter.update(file_index, 0.97, f"write (~{human})", output_path, size_hint=actual_hint)
                reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
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
            *,
            input_size: "basefwx.typing.Optional[int]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        input_size = input_size if input_size is not None else path.stat().st_size
        if password == "":
            raise ValueError("Password required for AES heavy streaming mode")
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)
        chunk_size = basefwx.STREAM_CHUNK_SIZE
        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        stream_salt = basefwx._StreamObfuscator.generate_salt()
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used,
            mode="STREAM"
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
            reporter.update(file_index, 0.12, "stream-setup", path, size_hint=estimated_hint)
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
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_used
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
        output_path = path.with_suffix('.fwx')
        processed_plain = 0
        total_plain = plaintext_len
        def _aes_progress(done_plain: int, total_plain_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.55 + 0.30 * (done_plain / total_plain_bytes if total_plain_bytes else 0.0)
            reporter.update(file_index, fraction, "AES512", path, size_hint=estimated_hint)

        def _obf_progress(done_bytes: int, total_bytes: int) -> None:
            if not reporter:
                return
            fraction = 0.2 + 0.30 * (done_bytes / total_bytes if total_bytes else 0.0)
            reporter.update(file_index, fraction, "pb512-stream", path, size_hint=estimated_hint)

        try:
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as obf_tmp, \
                 basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as cipher_tmp:
                cleanup_paths.extend([obf_tmp.name, cipher_tmp.name])
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
                    obf_tmp,
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
                obf_tmp_path = obf_tmp.name
            actual_size = basefwx.os.path.getsize(cipher_tmp_path)
            actual_hint = (input_size, actual_size)
            basefwx.os.replace(cipher_tmp_path, output_path)
            cleanup_paths.remove(cipher_tmp_path)
            if reporter:
                reporter.update(file_index, 0.88, "write", output_path, size_hint=actual_hint)
            if strip_metadata:
                basefwx._apply_strip_attributes(output_path)
                basefwx.os.chmod(output_path, 0)
            basefwx.os.remove(path)
            basefwx.os.remove(obf_tmp_path)
            cleanup_paths.remove(obf_tmp_path)
            human = basefwx._human_readable_size(actual_size)
            print(f"{output_path.name}: approx output size {human}")
            if reporter:
                reporter.update(file_index, 0.95, f"write (~{human})", output_path, size_hint=actual_hint)
                reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
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

        try:
            header, payload = content_core.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX container") from exc

        if reporter:
            reporter.update(file_index, 0.35, "b256", path)

        ext = basefwx.b512decode(header, password, use_master=use_master_effective)
        data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.65, "base64", path)

        decoded_bytes = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(decoded_bytes)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(decoded_bytes)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 0.9, "write", target, size_hint=size_hint)
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
            if ext_bytes:
                try:
                    ext_text = ext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    ext_text = ""
                if ext_text:
                    target = target.with_suffix(ext_text)

            if decoded_path is None:
                raise RuntimeError("Missing decoded payload")
            basefwx.os.replace(decoded_path, target)
            cleanup_paths.remove(decoded_path)
            if strip_metadata:
                basefwx._apply_strip_attributes(target)
            basefwx.os.remove(path)
            if plaintext_path and plaintext_path in cleanup_paths:
                basefwx.os.remove(plaintext_path)
                cleanup_paths.remove(plaintext_path)
            output_len = original_size
            size_hint = (input_size, output_len)
            if reporter:
                reporter.update(file_index, 0.95, "write", target, size_hint=size_hint)
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
    def b512file_encode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
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
                master_pubkey=pubkey_bytes
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
            silent: bool = False
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

        reporter = basefwx._ProgressReporter(len(paths)) if not silent else None
        results: dict[str, str] = {}

        def _process_with_reporter(idx: int, path: "basefwx.pathlib.Path") -> tuple[str, str]:
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                if reporter:
                    reporter.update(idx, 0.0, "missing", path)
                    reporter.finalize_file(idx, path)
                return str(path), "FAIL!"
            try:
                if path.suffix.lower() == ".fwx":
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
                    basefwx._b512_encode_path(
                        path,
                        resolved_password,
                        reporter,
                        idx,
                        len(paths),
                        strip_metadata,
                        encode_use_master,
                        master_pubkey
                    )
                return str(path), "SUCCESS!"
            except Exception as exc:
                if reporter:
                    reporter.update(idx, 0.0, f"error: {exc}", path)
                    reporter.finalize_file(idx, path)
                return str(path), "FAIL!"

        def _process_without_reporter(path: "basefwx.pathlib.Path") -> tuple[str, str]:
            try:
                basefwx._ensure_existing_file(path)
                if path.suffix.lower() == ".fwx":
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
                    basefwx._b512_encode_path(
                        path,
                        resolved_password,
                        None,
                        0,
                        len(paths),
                        strip_metadata,
                        encode_use_master,
                        master_pubkey
                    )
                return str(path), "SUCCESS!"
            except FileNotFoundError:
                return str(path), "FAIL!"
            except Exception:
                return str(path), "FAIL!"

        if reporter is None and len(paths) > 1 and basefwx._CPU_COUNT > 1:
            max_workers = min(len(paths), basefwx._CPU_COUNT)
            with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for file_id, status in executor.map(_process_without_reporter, paths):
                    results[file_id] = status
        else:
            for idx, path in enumerate(paths):
                file_id, status = _process_with_reporter(idx, path)
                results[file_id] = status

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

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
    def _aes_light_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        input_size = path.stat().st_size
        size_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
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
                    reporter.update(file_index, fraction, "base64", path)
        if buffer:
            b64_parts.append(basefwx.base64.b64encode(buffer).decode('ascii'))
        b64_payload = ''.join(b64_parts)
        basefwx._del('b64_parts')
        basefwx._del('buffer')
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        metadata_blob = basefwx._build_metadata(
            "AES-LIGHT",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used
        )
        body = (path.suffix or "") + basefwx.FWX_DELIM + b64_payload
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body

        plain_bytes_len = len(plaintext.encode('utf-8'))
        est_cipher_len = basefwx.AEAD_NONCE_LEN + plain_bytes_len + basefwx.AEAD_TAG_LEN
        progress_cb = None
        if reporter:
            enc_hint = (input_size, est_cipher_len)

            def _enc_progress(done: int, total: int) -> None:
                fraction = 0.55 + 0.25 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", path, size_hint=enc_hint)

            progress_cb = _enc_progress

        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used,
            progress_callback=progress_cb
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
                fraction = 0.8 + 0.1 * (processed_cipher / total_cipher)
                reporter.update(file_index, min(fraction, 0.89), "compress", path)
        tail = compressor.flush()
        if tail:
            compressed_parts.append(tail)
        compressed = b"".join(compressed_parts)
        basefwx._del('compressed_parts')
        output_len = len(compressed)
        size_hint = (input_size, output_len)

        if reporter:
            reporter.update(file_index, 0.9, "compress", path, size_hint=size_hint)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(compressed)
        basefwx._del('ciphertext')
        basefwx._del('compressed')

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
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
            ext, b64_payload = payload.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX light payload") from exc

        if reporter:
            reporter.update(file_index, 0.75, "base64", path)

        raw = basefwx.base64.b64decode(b64_payload)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(raw)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 0.9, "write", target, size_hint=size_hint)
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
                    kdf_hint = (meta.get("ENC-KDF") or basefwx.USER_KDF or "argon2id").lower()
                    user_derived_key, _ = basefwx._derive_user_key(
                        password,
                        salt=user_salt,
                        iterations=basefwx.USER_KDF_ITERATIONS,
                        kdf=kdf_hint
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
            if ext_bytes:
                try:
                    ext_text = ext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    ext_text = ""
                if ext_text:
                    target = target.with_suffix(ext_text)

            if decoded_path is None:
                raise RuntimeError("Missing decoded payload")
            basefwx.os.replace(decoded_path, target)
            cleanup_paths.remove(decoded_path)
            if strip_metadata:
                basefwx._apply_strip_attributes(target)
            basefwx.os.remove(path)
            if plaintext_path and plaintext_path in cleanup_paths:
                basefwx.os.remove(plaintext_path)
                cleanup_paths.remove(plaintext_path)
            output_len = original_size
            size_hint = (input_size, output_len)
            if reporter:
                reporter.update(file_index, 0.95, "write", target, size_hint=size_hint)
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
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
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
                input_size=input_size
            )
        estimated_hint: "basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]" = None
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        ext_token = basefwx.pb512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.55, "pb512", path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used
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
                fraction = 0.55 + 0.25 * (done / total if total else 0.0)
                reporter.update(file_index, fraction, "AES512", path, size_hint=estimated_hint)

            progress_cb = _enc_progress
        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used,
            progress_callback=progress_cb
        )
        approx_size = len(ciphertext)
        actual_hint = (input_size, approx_size)

        if reporter:
            reporter.update(
                file_index,
                0.8,
                "AES512",
                path,
                size_hint=actual_hint
            )

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(ciphertext)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        human = basefwx._human_readable_size(approx_size)
        print(f"{output_path.name}: approx output size {human}")

        if reporter:
            reporter.update(file_index, 0.95, f"write (~{human})", output_path, size_hint=actual_hint)
            reporter.finalize_file(file_index, output_path, size_hint=actual_hint)

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

        try:
            ext_token, data_token = payload.split(basefwx.FWX_HEAVY_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX heavy payload") from exc

        if reporter:
            reporter.update(file_index, 0.6, "pb512", path)

        ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
        data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.8, "base64", path)

        raw = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = len(raw)
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 0.9, "write", target, size_hint=size_hint)
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
            silent: bool = False
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

        reporter = basefwx._ProgressReporter(len(paths)) if not silent else None
        results: dict[str, str] = {}

        def _process_with_reporter(idx: int, path: "basefwx.pathlib.Path") -> tuple[str, str]:
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                if reporter:
                    reporter.update(idx, 0.0, "missing", path)
                    reporter.finalize_file(idx, path)
                return str(path), "FAIL!"
            try:
                if path.suffix.lower() == ".fwx":
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                else:
                    if light:
                        basefwx._aes_light_encode_path(path, resolved_password, reporter, idx, strip_metadata, encode_use_master, master_pubkey)
                    else:
                        basefwx._aes_heavy_encode_path(path, resolved_password, reporter, idx, strip_metadata, encode_use_master, master_pubkey)
                return str(path), "SUCCESS!"
            except Exception as exc:
                if reporter:
                    reporter.update(idx, 0.0, f"error: {exc}", path)
                    reporter.finalize_file(idx, path)
                return str(path), "FAIL!"

        def _process_without_reporter(path: "basefwx.pathlib.Path") -> tuple[str, str]:
            try:
                basefwx._ensure_existing_file(path)
                if path.suffix.lower() == ".fwx":
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                else:
                    if light:
                        basefwx._aes_light_encode_path(path, resolved_password, None, 0, strip_metadata, encode_use_master, master_pubkey)
                    else:
                        basefwx._aes_heavy_encode_path(path, resolved_password, None, 0, strip_metadata, encode_use_master, master_pubkey)
                return str(path), "SUCCESS!"
            except FileNotFoundError:
                return str(path), "FAIL!"
            except Exception:
                return str(path), "FAIL!"

        if reporter is None and len(paths) > 1 and basefwx._CPU_COUNT > 1:
            max_workers = min(len(paths), basefwx._CPU_COUNT)
            with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                for file_id, status in executor.map(_process_without_reporter, paths):
                    results[file_id] = status
        else:
            for idx, path in enumerate(paths):
                file_id, status = _process_with_reporter(idx, path)
                results[file_id] = status

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

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

        if normalized == "b512":
            result = basefwx.b512file(
                args.paths,
                password,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )
        elif normalized == "aes-light":
            result = basefwx.AESfile(
                args.paths,
                password,
                light=True,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )
        else:
            result = basefwx.AESfile(
                args.paths,
                password,
                light=False,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )

        if isinstance(result, dict):
            failures = 0
            for path, status in result.items():
                print(f"{path}: {status}")
                if status != "SUCCESS!":
                    failures += 1
            return 0 if failures == 0 else 1

        print(result)
        return 0 if result == "SUCCESS!" else 1

    return 0


def main(argv=None) -> int:
    return cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
