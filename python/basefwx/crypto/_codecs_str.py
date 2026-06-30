# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from ..legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _mdcode_ascii(text: str) -> str:
    if not text.isascii():
        text.encode('ascii')
    data = text.encode('ascii')
    table = basefwx._MD_CODE_TABLE_BYTES
    result_parts = [table[b] for b in data] if len(data) > basefwx._MDCODE_ASCII_THRESHOLD else (table[b] for b in data)
    return b''.join(result_parts).decode('ascii')


def _mcode_digits(encoded: str) -> str:
    if not encoded:
        return ''
    try:
        data = encoded.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('Invalid mcode payload')
    out = bytearray(len(data) // 2)
    out_idx = 0
    idx = 0
    total = len(data)
    while idx < total:
        ch = data[idx]
        if ch < 48 or ch > 57:
            raise ValueError('Invalid mcode payload')
        span = ch - 48
        idx += 1
        if span <= 0 or idx + span > total:
            raise ValueError('Invalid mcode payload length')
        if span == 1:
            d0 = data[idx] - 48
            if d0 > 9:
                raise ValueError('Invalid mcode payload')
            val = d0
            idx += 1
        elif span == 2:
            d0 = data[idx] - 48
            d1 = data[idx + 1] - 48
            if d0 > 9 or d1 > 9:
                raise ValueError('Invalid mcode payload')
            val = d0 * 10 + d1
            idx += 2
        elif span == 3:
            d0 = data[idx] - 48
            d1 = data[idx + 1] - 48
            d2 = data[idx + 2] - 48
            if d0 > 9 or d1 > 9 or d2 > 9:
                raise ValueError('Invalid mcode payload')
            val = d0 * 100 + d1 * 10 + d2
            idx += 3
        else:
            val = 0
            for i in range(span):
                d = data[idx + i] - 48
                if d > 9:
                    raise ValueError('Invalid mcode payload')
                val = val * 10 + d
            idx += span
        if out_idx >= len(out):
            out.extend(bytes(len(out) // 2 + 64))
        out[out_idx] = val
        out_idx += 1
    return out[:out_idx].decode('latin-1')


def _code_chunk(cls, chunk: str) -> str:
    if chunk.isascii():
        return chunk.translate(cls._CODE_TRANSLATION_TABLE)
    return chunk.translate(cls._CODE_TRANSLATION)


def _code_bytes(cls, string: str) -> bytes:
    if not string:
        return b''
    if string.isascii():
        return string.translate(cls._CODE_TRANSLATION).encode('ascii')
    return cls._code_chunk(string).encode('utf-8')


def code(cls, string: str) -> str:
    if not string:
        return string
    return cls._code_chunk(string)


def decode(cls, sttr: str) -> str:
    if not sttr:
        return sttr
    return cls._DECODE_PATTERN.sub(lambda match: cls._DECODE_MAP[match.group(0)], sttr)


def fwx256bin(cls, string: str) -> str:
    raw = cls._code_bytes(string)
    padding_count = cls._b32_padding_count(len(raw))
    if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
        encoded = cls._fast_b32hexencode(raw)
    else:
        encoded = cls.base64.b32hexencode(raw)
    if padding_count:
        encoded = encoded[:-padding_count]
    return encoded.decode('utf-8') + str(padding_count)


def fwx256unbin(cls, string: str) -> str:
    padding_count = int(string[-1])
    base32text = string[:-1] + '=' * padding_count
    data = base32text.encode('utf-8')
    if cls.np is not None and len(data) >= cls._B32_FAST_THRESHOLD:
        decoded = cls._fast_b32hexdecode(data).decode('utf-8')
    else:
        decoded = cls.base64.b32hexdecode(data).decode('utf-8')
    return cls.decode(decoded)


def _fwx256bin_bytes(cls, string: str) -> bytes:
    raw = cls._code_bytes(string)
    padding_count = cls._b32_padding_count(len(raw))
    if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
        encoded = cls._fast_b32hexencode(raw)
    else:
        encoded = cls.base64.b32hexencode(raw)
    if padding_count:
        encoded = encoded[:-padding_count]
    return encoded + str(padding_count).encode('ascii')


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


def _coerce_text(data: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode('latin-1')
    raise TypeError(f'Unsupported type for textual conversion: {type(data)!r}')


def b256encode(cls, data: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> str:
    text = cls._coerce_text(data)
    raw = cls._code_bytes(text)
    if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
        encoded = cls._fast_b32hexencode(raw).decode('utf-8')
    else:
        encoded = cls.base64.b32hexencode(raw).decode('utf-8')
    padding_count = encoded.count('=')
    return encoded.rstrip('=') + str(padding_count)


def b256decode(cls, string: str) -> str:
    padding_count = int(string[-1])
    base32text = string[:-1] + '=' * padding_count
    data = base32text.encode('utf-8')
    if cls.np is not None and len(data) >= cls._B32_FAST_THRESHOLD:
        decoded = cls._fast_b32hexdecode(data).decode('utf-8')
    else:
        decoded = cls.base64.b32hexdecode(data).decode('utf-8')
    return cls.decode(decoded)


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


def a512decode(string: str):

    def maindc(string):
        try:
            if not string or not string[0].isdigit():
                return 'AN ERROR OCCURED!'
            leoa = int(string[0])
            if leoa <= 0 or len(string) < leoa + 1:
                return 'AN ERROR OCCURED!'
            length_str = string[1:leoa + 1]
            md_len = int(length_str)
            code = str(md_len * md_len)
            payload = string[leoa + 1:]
            string3 = basefwx.fwx256unbin(payload.replace('4G5tRA', '='))
            if string3 and string3[0] == '0':
                string3 = '-' + string3[1:]
            md_code = basefwx._mdcode_ascii(code)
            if len(string3) <= basefwx._DECIMAL_INT_LIMIT and len(md_code) <= basefwx._DECIMAL_INT_LIMIT:
                try:
                    total = str(int(string3) + int(md_code))
                except (ValueError, OverflowError, MemoryError):
                    total = basefwx._add_signed(string3, md_code)
            else:
                total = basefwx._add_signed(string3, md_code)
            if total.startswith('-'):
                return 'AN ERROR OCCURED!'
            return basefwx._mcode_digits(total)
        except Exception:
            return 'AN ERROR OCCURED!'
    return maindc(string)


def bi512encode(string: str):
    code = string[0] + string[len(string) - 1]
    left = basefwx._mdcode_ascii(string)
    right = basefwx._mdcode_ascii(code)
    diff = basefwx._decimal_diff(left, right)
    packed = basefwx._fwx256bin_bytes(diff)
    return str(basefwx.hashlib.sha256(packed).hexdigest()).replace('-', '0')


def _strip_leading_zeros(number: str) -> str:
    if not number:
        return '0'
    stripped = number.lstrip('0')
    return stripped if stripped else '0'


def _compare_magnitude(a: str, b: str) -> int:
    aa = basefwx._strip_leading_zeros(a)
    bb = basefwx._strip_leading_zeros(b)
    if len(aa) != len(bb):
        return -1 if len(aa) < len(bb) else 1
    if aa == bb:
        return 0
    return -1 if aa < bb else 1


def _decimal_diff(a: str, b: str) -> str:
    if len(a) <= 1000 and len(b) <= 1000:
        try:
            ai = int(a)
            bi = int(b)
            if ai >= bi:
                return str(ai - bi)
            return '0' + str(bi - ai)
        except (ValueError, OverflowError, MemoryError):
            pass
    cmp = basefwx._compare_magnitude(a, b)
    if cmp >= 0:
        return basefwx._subtract_magnitude(a, b)
    return '0' + basefwx._subtract_magnitude(b, a)


def _add_magnitude(a: str, b: str) -> str:
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
        out[pos] = 48 + total % 10
        carry = total // 10
        ia -= 1
        ib -= 1
        pos -= 1
    idx = pos + 1
    while idx < max_len and out[idx] == 48:
        idx += 1
    if idx == max_len:
        return '0'
    return out[idx:].decode('ascii')


def _subtract_magnitude(a: str, b: str) -> str:
    """Decimal string subtraction (a >= b assumed). Uses NumPy for large inputs."""
    len_a = len(a)
    len_b = len(b)
    if basefwx.np is not None and len_a >= 1000:
        np = basefwx.np
        arr_a = np.frombuffer(a.encode('ascii'), dtype=np.uint8).astype(np.int16) - 48
        arr_b = np.zeros(len_a, dtype=np.int16)
        if len_b > 0:
            arr_b[-len_b:] = np.frombuffer(b.encode('ascii'), dtype=np.uint8) - 48
        result = arr_a - arr_b
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
        return '0'
    return out[idx:].decode('ascii')


def _add_signed(a: str, b: str) -> str:

    def parse_signed(value: str) -> tuple[bool, str]:
        if not value:
            return (False, '0')
        negative = value[0] == '-'
        digits = value[1:] if negative else value
        digits = basefwx._strip_leading_zeros(digits)
        if digits == '0':
            negative = False
        return (negative, digits)
    neg_a, da = parse_signed(a)
    neg_b, db = parse_signed(b)
    if neg_a == neg_b:
        total = basefwx._add_magnitude(da, db)
        return '-' + total if neg_a and total != '0' else total
    cmp = basefwx._compare_magnitude(da, db)
    if cmp == 0:
        return '0'
    if cmp > 0:
        diff = basefwx._subtract_magnitude(da, db)
        return '-' + diff if neg_a else diff
    diff = basefwx._subtract_magnitude(db, da)
    return '-' + diff if neg_b else diff
