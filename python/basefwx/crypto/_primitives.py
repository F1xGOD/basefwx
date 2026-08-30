# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Native-backed cryptographic primitives and runtime capability helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as stdlib_hmac
import os
import secrets
import string
import struct
import sys
from typing import Optional, Tuple

try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _runtime_arch_label() -> str:
    try:
        machine = os.uname().machine.lower()
    except AttributeError:
        machine = ""
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    if machine in ("i386", "i486", "i586", "i686", "x86"):
        return "x86"
    return machine or "unknown"


def _python_build_origin_label() -> str:
    return "GitHub Actions" if os.getenv("GITHUB_ACTIONS") else "local/manual"


def _enable_large_int_string_conversion_for_cli() -> None:
    if hasattr(sys, "set_int_max_str_digits"):
        sys.set_int_max_str_digits(0)

PERM_FAST_MIN = 4 * 1024
OFB_FAST_MIN = 64 * 1024
OBF_INFO_MASK = b'basefwx.obf.mask.v1'
PERF_OBFUSCATION_THRESHOLD = 1 << 20
_B32HEX_ALPHABET = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
_B32HEX_DECODE_LUT: bytes = bytes(
    [255] * 48
    + list(range(10))
    + [255] * 7
    + list(range(10, 32))
    + [255] * 10
    + list(range(10, 32))
    + [255] * 137
)
_SHA256_DIGEST_LEN = 32
_HKDF_SHA256_MAX_LEN = 255 * _SHA256_DIGEST_LEN
_AES_256_KEY_LEN = 32
_AEAD_NONCE_LEN = 12
_AEAD_TAG_LEN = 16
_ARGON2_MIN_AVAILABLE_RAM_MIB = 128.0

def _env_int(name: str) -> 'Optional[int]':
    value = os.getenv(name)
    if not value:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _env_enabled_value(value: 'Optional[str]') -> bool:
    if value is None:
        return False
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def _env_enabled(name: str) -> bool:
    return _env_enabled_value(os.getenv(name))


def _perf_mode_enabled() -> bool:
    return _env_enabled('BASEFWX_PERF')


def _use_fast_obfuscation(length: int) -> bool:
    return _perf_mode_enabled() and length >= PERF_OBFUSCATION_THRESHOLD


def _get_available_ram_mib():
    """Return available RAM in MiB, or ``None`` when it cannot be read."""
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 * 1024)
    except Exception:
        pass
    try:
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemAvailable:'):
                        kb = int(line.split()[1])
                        return kb / 1024
        import subprocess
        result = subprocess.run(['sysctl', '-n', 'vm.stats.vm.v_free_count'], capture_output=True, text=True, timeout=1)
        if result.returncode == 0:
            page_count = int(result.stdout.strip())
            page_size_result = subprocess.run(['sysctl', '-n', 'hw.pagesize'], capture_output=True, text=True, timeout=1)
            if page_size_result.returncode == 0:
                page_size = int(page_size_result.stdout.strip())
                return page_count * page_size / (1024 * 1024)
    except Exception:
        pass
    return None


def _check_ram_for_argon2():
    """Return whether the host has enough reported free RAM for Argon2."""
    ram_mib = _get_available_ram_mib()
    return (
        ram_mib is None
        or ram_mib >= _ARGON2_MIN_AVAILABLE_RAM_MIB
    )


def _fast_b32hexencode(data: bytes) -> bytes:
    """NumPy-accelerated base32hex encoding (18x faster than stdlib)."""
    import numpy as np
    arr = np.frombuffer(data, dtype=np.uint8)
    pad_len = (5 - len(arr) % 5) % 5
    if pad_len:
        arr = np.concatenate([arr, np.zeros(pad_len, dtype=np.uint8)])
    groups = arr.reshape(-1, 5)
    out = np.empty((len(groups), 8), dtype=np.uint8)
    out[:, 0] = groups[:, 0] >> 3
    out[:, 1] = (groups[:, 0] & 7) << 2 | groups[:, 1] >> 6
    out[:, 2] = groups[:, 1] >> 1 & 31
    out[:, 3] = (groups[:, 1] & 1) << 4 | groups[:, 2] >> 4
    out[:, 4] = (groups[:, 2] & 15) << 1 | groups[:, 3] >> 7
    out[:, 5] = groups[:, 3] >> 2 & 31
    out[:, 6] = (groups[:, 3] & 3) << 3 | groups[:, 4] >> 5
    out[:, 7] = groups[:, 4] & 31
    b32_lut = np.frombuffer(_B32HEX_ALPHABET, dtype=np.uint8)
    result = b32_lut[out.ravel()]
    if pad_len:
        pad_chars = [0, 6, 4, 3, 1][pad_len]
        if pad_chars:
            result[-pad_chars:] = ord('=')
    return result.tobytes()


def _fast_b32hexdecode(data: bytes) -> bytes:
    """NumPy-accelerated base32hex decoding."""
    import numpy as np
    pad_count = 0
    while pad_count < len(data) and data[-1 - pad_count] == ord('='):
        pad_count += 1
    if len(data) % 8 != 0 or pad_count not in (0, 1, 3, 4, 6):
        raise binascii.Error('Incorrect padding')
    expected_remainder = {0: 0, 1: 7, 3: 5, 4: 4, 6: 2}[pad_count]
    if (len(data) - pad_count) % 8 != expected_remainder:
        raise binascii.Error('Incorrect padding')
    if pad_count:
        data = data[:-pad_count]
    arr = np.frombuffer(data, dtype=np.uint8)
    lut = np.frombuffer(_B32HEX_DECODE_LUT, dtype=np.uint8)
    vals = lut[arr]
    if np.any(vals == 255):
        raise binascii.Error('Non-base32 digit found')
    pad_to_8 = (8 - len(vals) % 8) % 8
    if pad_to_8:
        vals = np.concatenate([vals, np.zeros(pad_to_8, dtype=np.uint8)])
    groups = vals.reshape(-1, 8)
    out = np.empty((len(groups), 5), dtype=np.uint8)
    out[:, 0] = groups[:, 0] << 3 | groups[:, 1] >> 2
    out[:, 1] = groups[:, 1] << 6 | groups[:, 2] << 1 | groups[:, 3] >> 4
    out[:, 2] = groups[:, 3] << 4 | groups[:, 4] >> 1
    out[:, 3] = groups[:, 4] << 7 | groups[:, 5] << 2 | groups[:, 6] >> 3
    out[:, 4] = groups[:, 6] << 5 | groups[:, 7]
    result = out.ravel().tobytes()
    if pad_count:
        remove = [0, 1, 0, 2, 3, 0, 4][pad_count]
        if remove:
            result = result[:-remove]
    return result


def _human_readable_size(num_bytes: int) -> str:
    units = ['B', 'KiB', 'MiB', 'GiB']
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f'{value:.2f} {unit}'
        value /= 1024.0
    return f'{value:.2f} TiB'


def _del(varname: str) -> None:
    """Legacy best-effort reference drop; do not use as a memory wipe."""
    try:
        frame = sys._getframe(1)
    except Exception:
        return
    try:
        if varname in frame.f_locals:
            frame.f_locals[varname] = None
    except Exception:
        pass


def _clear_secret(value):
    """Zero mutable secret storage and drop the caller's reference via assignment."""
    if isinstance(value, bytearray):
        value[:] = b'\x00' * len(value)
    elif isinstance(value, memoryview) and not value.readonly:
        value[:] = b'\x00' * value.nbytes
    return None


def _hkdf(info: bytes, key: bytes, length: int=32) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hk.derive(key)


def _splitmix64(state: int) -> 'Tuple[int, int]':
    z = state + 11400714819323198485 & (1 << 64) - 1
    x = z
    x = (x ^ x >> 30) * 13787848793156543929 & (1 << 64) - 1
    x = (x ^ x >> 27) * 10723151780598845931 & (1 << 64) - 1
    x = x ^ x >> 31
    return (z, x & (1 << 64) - 1)


def _permute_inplace(data: bytearray, seed: int) -> None:
    n = len(data)
    if n >= PERM_FAST_MIN:
        rng = np.random.Generator(np.random.PCG64(seed & (1 << 64) - 1))
        perm = rng.permutation(n)
        arr = np.frombuffer(memoryview(data), dtype=np.uint8)
        out = arr.take(perm)
        arr[:] = out
        return
    st = seed & (1 << 64) - 1
    for i in range(n - 1, 0, -1):
        st, rnd = _splitmix64(st)
        j = rnd % (i + 1)
        if j != i:
            data[i], data[j] = (data[j], data[i])


def _unpermute_inplace(data: bytearray, seed: int) -> None:
    n = len(data)
    if n >= PERM_FAST_MIN:
        rng = np.random.Generator(np.random.PCG64(seed & (1 << 64) - 1))
        perm = rng.permutation(n)
        inv = np.empty_like(perm)
        inv[perm] = np.arange(n, dtype=perm.dtype)
        arr = np.frombuffer(memoryview(data), dtype=np.uint8)
        out = arr.take(inv)
        arr[:] = out
        return
    swaps = []
    st = seed & (1 << 64) - 1
    for i in range(n - 1, 0, -1):
        st, rnd = _splitmix64(st)
        j = rnd % (i + 1)
        swaps.append((i, j))
    for i, j in reversed(swaps):
        if j != i:
            data[i], data[j] = (data[j], data[i])


def _xor_keystream_inplace(buf: bytearray, key: bytes, info: bytes=OBF_INFO_MASK) -> None:
    if not buf:
        return
    n = len(buf)
    block_key = _hkdf(info, key, 32)
    ctr = 0
    total_len_bytes = n.to_bytes(8, 'big')
    if n >= OFB_FAST_MIN:
        mv = memoryview(buf)
        arr = np.frombuffer(mv, dtype=np.uint8)
        offset = 0
        while offset < n:
            h = hmac.HMAC(block_key, hashes.SHA256())
            meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
            h.update(meta)
            block = h.finalize()
            take = min(len(block), n - offset)
            block_arr = np.frombuffer(block, dtype=np.uint8)
            np.bitwise_xor(arr[offset:offset + take], block_arr[:take], out=arr[offset:offset + take])
            offset += take
            ctr += 1
        return
    off = 0
    while off < n:
        h = hmac.HMAC(block_key, hashes.SHA256())
        meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
        h.update(meta)
        block = h.finalize()
        take = min(len(block), n - off)
        for i in range(take):
            buf[off + i] ^= block[i]
        off += take
        ctr += 1


def _hkdf_sha256(
    key_material: bytes,
    *,
    length: int = 32,
    info: bytes = b'basefwx.kem.v1',
    salt: bytes | None = None,
) -> bytes:
    """HKDF-SHA256. ``salt=None`` / empty matches C++ empty-salt (HashLen zeros)."""
    if length < 0:
        raise ValueError('HKDF length must not be negative')
    if length > _HKDF_SHA256_MAX_LEN:
        raise ValueError('HKDF-SHA256 output exceeds RFC 5869 limit')
    extract_salt = None if not salt else salt
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=extract_salt, info=info)
    return hk.derive(key_material)


def _compat_prf_stream_sha256(key_material: bytes, info: bytes, length: int) -> bytes:
    """Released large-payload PRF stream; not RFC 5869 HKDF.

    The stream uses a zero-salt HMAC-SHA256 extract followed by
    ``HMAC(PRK, previous || info || uint32_be(counter))`` blocks. Its bytes are
    retained for existing BaseFWX masked payloads larger than 8160 bytes.
    """
    if length < 0:
        raise ValueError('compatibility PRF length must not be negative')
    if length == 0:
        return b''
    blocks = (length + 31) // 32
    if blocks > 0xFFFFFFFF:
        raise ValueError('compatibility PRF stream counter exhausted')
    info_bytes = info or b''
    zero_salt = b'\x00' * 32
    prk = stdlib_hmac.new(zero_salt, key_material, hashlib.sha256).digest()
    out = bytearray(length)
    mv = memoryview(out)
    prev = b''
    offset = 0
    counter = 1
    base_hmac = stdlib_hmac.new(prk, digestmod=hashlib.sha256)
    counter_bytes = bytearray(4)
    while offset < length:
        h = base_hmac.copy()
        if prev:
            h.update(prev)
        h.update(info_bytes)
        struct.pack_into('>I', counter_bytes, 0, counter)
        h.update(counter_bytes)
        block = h.digest()
        take = min(32, length - offset)
        mv[offset:offset + take] = block[:take]
        offset += take
        prev = block
        counter += 1
    return bytes(out)


def _hkdf_stream_sha256(key_material: bytes, info: bytes, length: int) -> bytes:
    """Compatibility alias for :func:`_compat_prf_stream_sha256`."""
    return _compat_prf_stream_sha256(key_material, info, length)


def _aead_encrypt(key: bytes, plaintext: bytes, aad: 'Optional[bytes]') -> bytes:
    if len(key) != _AES_256_KEY_LEN:
        raise ValueError('AES-GCM expects a 32-byte key')
    nonce = os.urandom(_AEAD_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return nonce + ct


def _aead_decrypt(key: bytes, blob: bytes, aad: 'Optional[bytes]') -> bytes:
    if len(key) != _AES_256_KEY_LEN:
        raise ValueError('AES-GCM expects a 32-byte key')
    if len(blob) < _AEAD_NONCE_LEN + _AEAD_TAG_LEN:
        raise ValueError('Malformed AEAD blob: too short')
    nonce, ct = (blob[:_AEAD_NONCE_LEN], blob[_AEAD_NONCE_LEN:])
    return AESGCM(key).decrypt(nonce, ct, aad or None)


def generate_random_string(length):
    """Generates a random string of the specified length."""
    alphabet = string.ascii_letters + string.digits
    return ''.join((secrets.choice(alphabet) for i in range(length)))


def b64encode(string: str):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')


def b64decode(string: str):
    return base64.b64decode(string.encode('utf-8')).decode('utf-8')


def hash512(string: str):
    return hashlib.sha512(string.encode('utf-8')).hexdigest()
