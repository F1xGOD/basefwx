# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _n10_mod_sub(value: int, sub: int) -> int:
    if value >= sub:
        return value - sub
    return basefwx.N10_MOD - (sub - value)


def _n10_mix64(value: int) -> int:
    value = value + 11400714819323198485 & basefwx.N10_MASK64
    value = (value ^ value >> 30) * 13787848793156543929 & basefwx.N10_MASK64
    value = (value ^ value >> 27) * 10723151780598845931 & basefwx.N10_MASK64
    return (value ^ value >> 31) & basefwx.N10_MASK64


def _n10_offset(index: int) -> int:
    if index < 0:
        raise ValueError('n10 index out of range')
    basefwx._n10_ensure_offsets(index)
    return int(basefwx.N10_OFFSET_CACHE[index])


def _n10_ensure_offsets(max_index: int) -> None:
    if max_index < 0:
        return
    cache = basefwx.N10_OFFSET_CACHE
    current = len(cache)
    if current > max_index:
        return
    mask64 = basefwx.N10_MASK64
    n10_mod = basefwx.N10_MOD
    seed = basefwx.N10_OFFSET_XOR
    for index in range(current, max_index + 1):
        value = (index ^ seed) & mask64
        value = value + 11400714819323198485 & mask64
        value = (value ^ value >> 30) * 13787848793156543929 & mask64
        value = (value ^ value >> 27) * 10723151780598845931 & mask64
        value = (value ^ value >> 31) & mask64
        cache.append(value % n10_mod)


def _n10_transform(value: int, index: int) -> int:
    if value < 0 or value >= basefwx.N10_MOD:
        raise ValueError('n10 value too large')
    mixed = (value + basefwx._n10_offset(index)) % basefwx.N10_MOD
    return (basefwx.N10_MUL * mixed + basefwx.N10_ADD) % basefwx.N10_MOD


def _n10_inverse_transform(encoded: int, index: int) -> int:
    if encoded < 0 or encoded >= basefwx.N10_MOD:
        raise ValueError('n10 encoded value too large')
    step = basefwx._n10_mod_sub(encoded, basefwx.N10_ADD)
    mixed = step * basefwx.N10_MUL_INV % basefwx.N10_MOD
    return basefwx._n10_mod_sub(mixed, basefwx._n10_offset(index))


def _n10_parse_fixed10(payload: str, offset: int) -> int:
    part = payload[offset:offset + 10]
    if len(part) != 10:
        raise ValueError('n10 payload truncated')
    try:
        return int(part)
    except ValueError:
        raise ValueError('n10 payload must contain only digits')


def _n10_fnv1a32(data: bytes) -> int:
    hash_value = 2166136261
    for byte in data:
        hash_value ^= byte
        hash_value = hash_value * 16777619 & 4294967295
    return hash_value


def n10encode(data):
    if isinstance(data, str):
        return basefwx.n10encode_bytes(data.encode('utf-8'))
    return basefwx.n10encode_bytes(data)


def n10encode_bytes(data):
    if isinstance(data, memoryview):
        raw = data.cast('B')
    elif isinstance(data, (bytearray, bytes)):
        raw = memoryview(data).cast('B')
    else:
        raise TypeError('n10encode_bytes expects bytes-like input')
    raw_len = raw.nbytes
    if raw_len >= basefwx.N10_MOD:
        raise ValueError('n10 input is too large')
    block_count = (raw_len + 3) // 4
    basefwx._n10_ensure_offsets(block_count + 1)
    offsets = basefwx.N10_OFFSET_CACHE
    n10_mod = basefwx.N10_MOD
    n10_mul = basefwx.N10_MUL
    n10_add = basefwx.N10_ADD
    transformed_len = (n10_mul * (raw_len + offsets[0]) + n10_add) % n10_mod
    transformed_checksum = (n10_mul * (basefwx._n10_fnv1a32(raw) + offsets[1]) + n10_add) % n10_mod
    full_blocks = raw_len // 4
    if full_blocks:
        words = basefwx.struct.unpack_from(f'>{full_blocks}I', raw, 0)
    else:
        words = ()
    block_offsets = offsets[2:2 + full_blocks]
    body = ['%010d' % ((n10_mul * (w + o) + n10_add) % n10_mod) for w, o in zip(words, block_offsets)]
    tail_len = raw_len - full_blocks * 4
    if tail_len:
        raw_offset = full_blocks * 4
        word = 0
        if tail_len >= 1:
            word |= raw[raw_offset] << 24
        if tail_len >= 2:
            word |= raw[raw_offset + 1] << 16
        if tail_len >= 3:
            word |= raw[raw_offset + 2] << 8
        transformed = (n10_mul * (word + offsets[full_blocks + 2]) + n10_add) % n10_mod
        body.append('%010d' % transformed)
    return ''.join((basefwx.N10_MAGIC, basefwx.N10_VERSION, '%010d' % transformed_len, '%010d' % transformed_checksum, *body))


def n10decode(digits: str, errors: str='strict'):
    return basefwx.n10decode_bytes(digits).decode('utf-8', errors=errors)


def n10decode_bytes(digits: str):
    if not isinstance(digits, str):
        raise TypeError('n10decode expects string digits')
    start = 0
    end = len(digits)
    while start < end and digits[start].isspace():
        start += 1
    while end > start and digits[end - 1].isspace():
        end -= 1
    payload = digits[start:end] if start != 0 or end != len(digits) else digits
    if len(payload) < basefwx.N10_HEADER_DIGITS:
        raise ValueError('n10 payload is too short')
    if payload[:6] != basefwx.N10_MAGIC or payload[6:8] != basefwx.N10_VERSION:
        raise ValueError('n10 header mismatch')
    payload_len_encoded = basefwx._n10_parse_fixed10(payload, 8)
    checksum_encoded = basefwx._n10_parse_fixed10(payload, 18)
    n10_mod = basefwx.N10_MOD
    n10_add = basefwx.N10_ADD
    n10_mul_inv = basefwx.N10_MUL_INV
    basefwx._n10_ensure_offsets(1)
    offsets = basefwx.N10_OFFSET_CACHE
    payload_len_step = payload_len_encoded - n10_add
    if payload_len_step < 0:
        payload_len_step += n10_mod
    payload_len_mixed = payload_len_step * n10_mul_inv % n10_mod
    payload_len = payload_len_mixed - offsets[0]
    if payload_len < 0:
        payload_len += n10_mod
    if payload_len >= basefwx.N10_MOD:
        raise ValueError('n10 decoded length is invalid')
    checksum_step = checksum_encoded - n10_add
    if checksum_step < 0:
        checksum_step += n10_mod
    checksum_mixed = checksum_step * n10_mul_inv % n10_mod
    checksum_expected = checksum_mixed - offsets[1]
    if checksum_expected < 0:
        checksum_expected += n10_mod
    if checksum_expected > 4294967295:
        raise ValueError('n10 checksum is invalid')
    block_count = (payload_len + 3) // 4
    expected_digits = basefwx.N10_HEADER_DIGITS + block_count * 10
    if len(payload) != expected_digits:
        raise ValueError('n10 payload length mismatch')
    basefwx._n10_ensure_offsets(block_count + 1)
    offsets = basefwx.N10_OFFSET_CACHE
    hdr_digits = basefwx.N10_HEADER_DIGITS
    block_offsets = offsets[2:2 + block_count]
    arr = basefwx.array.array('I', b'\x00\x00\x00\x00' * block_count) if block_count else None
    for block in range(block_count):
        in_offset = hdr_digits + block * 10
        part = payload[in_offset:in_offset + 10]
        if len(part) != 10:
            raise ValueError('n10 payload truncated')
        try:
            encoded = int(part)
        except ValueError:
            raise ValueError('n10 payload must contain only digits')
        step = encoded - n10_add
        if step < 0:
            step += n10_mod
        mixed = step * n10_mul_inv % n10_mod
        decoded = mixed - block_offsets[block]
        if decoded < 0:
            decoded += n10_mod
        if decoded > 4294967295:
            raise ValueError('n10 block out of range')
        arr[block] = decoded
    if arr is not None:
        if basefwx.sys.byteorder == 'little':
            arr.byteswap()
        raw = arr.tobytes()[:payload_len]
    else:
        raw = b''
    if basefwx._n10_fnv1a32(raw) != checksum_expected:
        raise ValueError('n10 checksum mismatch')
    return raw
