# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

from ._b512_common import basefwx

def _pack_length_prefixed(*parts: bytes) -> bytes:
    total = 4 * len(parts) + sum((len(p) for p in parts))
    out = bytearray(total)
    mv = memoryview(out)
    offset = 0
    for part in parts:
        mv[offset:offset + 4] = len(part).to_bytes(4, 'big')
        offset += 4
        mv[offset:offset + len(part)] = part
        offset += len(part)
    return bytes(out)

def _unpack_length_prefixed(data: bytes, count: int) -> 'basefwx.typing.Tuple[bytes, ...]':
    mv = memoryview(data)
    total_len = len(mv)
    offset = 0
    parts: 'basefwx.typing.List[bytes]' = []
    for _ in range(count):
        if offset + 4 > total_len:
            raise ValueError('Malformed length-prefixed blob (missing length)')
        length = basefwx.struct.unpack_from('>I', mv, offset)[0]
        offset += 4
        if offset + length > total_len:
            raise ValueError('Malformed length-prefixed blob (truncated part)')
        parts.append(bytes(mv[offset:offset + length]))
        offset += length
    if offset != total_len:
        raise ValueError('Malformed length-prefixed blob (extra bytes)')
    return tuple(parts)

def _resolve_payload_length_from_file_size(path: 'basefwx.pathlib.Path', len_user: int, len_master: int, encoded_payload_len: int) -> int:
    payload_len = int(encoded_payload_len)
    if payload_len < 0:
        payload_len = 0
    try:
        file_size = int(path.stat().st_size)
    except Exception:
        return payload_len
    prefix_len = 4 + int(len_user) + 4 + int(len_master) + 4
    if file_size < prefix_len:
        return payload_len
    actual_payload_len = file_size - prefix_len
    if actual_payload_len == payload_len:
        return payload_len
    mod = 1 << 32
    if actual_payload_len > payload_len and (actual_payload_len - payload_len) % mod == 0:
        return actual_payload_len
    return payload_len

def _estimate_aead_blob_size(plaintext_bytes: int, metadata_bytes: int, *, include_user: bool, include_master: bool) -> int:
    cipher_section = basefwx.AEAD_NONCE_LEN + plaintext_bytes + basefwx.AEAD_TAG_LEN
    payload_section = 4 + metadata_bytes + cipher_section
    user_section = basefwx.USER_WRAP_FIXED_LEN if include_user else 0
    master_section = basefwx.PQ_CIPHERTEXT_SIZE if include_master else 0
    total = 4 + user_section + 4 + master_section + 4 + payload_section
    return total
