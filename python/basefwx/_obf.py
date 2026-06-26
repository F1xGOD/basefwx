# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _obfuscate_bytes(data: bytes, ephemeral_key: bytes, *, fast: bool=False) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
    if not fast:
        perm_seed_bytes = basefwx._hkdf(basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'), ephemeral_key, 16)
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        out.reverse()
        basefwx._permute_inplace(out, perm_seed)
        basefwx._del('perm_seed')
    return bytes(out)


def _deobfuscate_bytes(data: bytes, ephemeral_key: bytes, *, fast: bool=False) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    if not fast:
        perm_seed_bytes = basefwx._hkdf(basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'), ephemeral_key, 16)
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        basefwx._unpermute_inplace(out, perm_seed)
        out.reverse()
        basefwx._del('perm_seed')
    basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
    return bytes(out)


def _mask_payload(mask_key: bytes, payload: bytes, *, info: bytes) -> bytes:
    if not payload:
        return b''
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
    ranges = [(start, min(start + chunk, total_len)) for start in range(0, total_len, chunk)]

    def _xor_slice(bounds: 'tuple[int, int]') -> None:
        start, end = bounds
        basefwx.np.bitwise_xor(data_arr[start:end], mask_arr[start:end], out=out_arr[start:end])
    max_workers = min(len(ranges), basefwx._CPU_COUNT)
    with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(_xor_slice, ranges))
    return out_arr.tobytes()


def _looks_like_base64(text: str) -> bool:
    try:
        basefwx.base64.b64decode(text, validate=True)
        return True
    except Exception:
        return False


def _maybe_obfuscate_codecs(text: str) -> str:
    if not basefwx.ENABLE_CODEC_OBFUSCATION:
        return text
    return basefwx.code(text)


def _maybe_deobfuscate_codecs(text: str) -> str:
    if basefwx._looks_like_base64(text):
        return text
    try:
        return basefwx.decode(text)
    except Exception:
        return text


def _bytes_to_bits(data: bytes) -> str:
    return ''.join((f'{b:08b}' for b in data))


def _bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8:
        raise ValueError('bits not multiple of 8')
    return bytes((int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))


def normalize_wrap(blob: bytes, cover_phrase: str='low taper fade') -> str:
    if not cover_phrase.strip():
        raise ValueError('cover_phrase empty')
    payload = basefwx.struct.pack('>I', len(blob)) + blob
    bits = basefwx._bytes_to_bits(payload)
    words = cover_phrase.split()
    token_count = len(bits) + 1
    repeats = (token_count + len(words) - 1) // len(words)
    tokens = (words * repeats)[:token_count]
    out_parts: 'basefwx.typing.List[str]' = []
    bit_idx = 0
    for idx, token in enumerate(tokens):
        if idx > 0:
            out_parts.append(' ')
            out_parts.append(basefwx.ZW1 if bits[bit_idx] == '1' else basefwx.ZW0)
            bit_idx += 1
        out_parts.append(token)
    if bit_idx != len(bits):
        raise RuntimeError('failed to embed all bits')
    return ''.join(out_parts)


def normalize_unwrap(text: str) -> bytes:
    bits: 'basefwx.typing.List[str]' = []
    for ch in text:
        if ch == basefwx.ZW0:
            bits.append('0')
        elif ch == basefwx.ZW1:
            bits.append('1')
    if len(bits) < 32:
        raise ValueError('not enough hidden data')
    length = int(''.join(bits[:32]), 2)
    needed = 32 + length * 8
    if len(bits) < needed:
        raise ValueError('hidden data truncated')
    blob_bits = ''.join(bits[32:needed])
    return basefwx._bits_to_bytes(blob_bits)


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
    def for_password(cls, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', salt: bytes, fast: bool=False) -> '_StreamObfuscator':
        if not password:
            raise ValueError('Password required for streaming obfuscation')
        if len(salt) < cls._SALT_LEN:
            raise ValueError('Streaming obfuscation salt must be at least 16 bytes')
        base_material = basefwx._coerce_password_bytes(password) + salt
        mask_key = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_KEY, length=32)
        iv = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_IV, length=16)
        perm_material = basefwx._hkdf_sha256(base_material, info=basefwx.STREAM_INFO_PERM, length=32)
        cipher = basefwx.Cipher(basefwx.algorithms.AES(mask_key), basefwx.modes.CTR(iv)).encryptor()
        return cls(cipher, perm_material, fast)

    def _next_params(self) -> 'basefwx.typing.Tuple[int, int, bool]':
        idx_bytes = self._chunk_index.to_bytes(8, 'big')
        seed_bytes = basefwx._hkdf_sha256(self._perm_material, info=basefwx.STREAM_INFO_PERM + idx_bytes, length=16)
        self._chunk_index += 1
        perm_seed = int.from_bytes(seed_bytes, 'big')
        rotation = seed_bytes[0] & 7
        swap = bool(seed_bytes[1] & 1)
        return (perm_seed, rotation, swap)

    @staticmethod
    def _rotate_left_inplace(arr: 'basefwx.np.ndarray', rotation: int) -> None:
        if rotation == 0:
            return
        left = basefwx.np.left_shift(arr, rotation) & 255
        right = basefwx.np.right_shift(arr, 8 - rotation)
        basefwx.np.bitwise_or(left, right, out=arr, casting='unsafe')

    @staticmethod
    def _rotate_right_inplace(arr: 'basefwx.np.ndarray', rotation: int) -> None:
        if rotation == 0:
            return
        right = basefwx.np.right_shift(arr, rotation)
        left = basefwx.np.left_shift(arr, 8 - rotation) & 255
        basefwx.np.bitwise_or(left, right, out=arr, casting='unsafe')

    @staticmethod
    def _swap_nibbles_inplace(arr: 'basefwx.np.ndarray') -> None:
        high = basefwx.np.right_shift(arr, 4)
        low = (arr & 15) << 4
        basefwx.np.bitwise_or(high, low, out=arr, casting='unsafe')

    def encode_chunk(self, chunk: bytes) -> bytes:
        if not chunk:
            return b''
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
            return b''
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
    def encode_file(cls, src_path: 'basefwx.pathlib.Path', dst_handle: 'basefwx.typing.Optional[basefwx.typing.Any]', password: str, salt: bytes, *, chunk_size: int, fast: bool=False, forward_chunk: 'basefwx.typing.Callable[[bytes], None]', progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]'=None) -> int:
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
    def decode_file(cls, src_handle, dst_handle, password: str, salt: bytes, *, chunk_size: int, total_plain: int, fast: bool=False, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]'=None) -> int:
        decoder = cls.for_password(password, salt, fast=fast)
        processed = 0
        while processed < total_plain:
            to_read = min(chunk_size, total_plain - processed)
            chunk = src_handle.read(to_read)
            if not chunk:
                raise ValueError('Streaming decode truncated input')
            plain = decoder.decode_chunk(chunk)
            dst_handle.write(plain)
            processed += len(plain)
            if progress_cb:
                progress_cb(processed, total_plain)
        return processed
