# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Retired b256/A512/Bi512/Uhash513 compatibility implementations."""

from __future__ import annotations

import hashlib
import os


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from ..legacy import basefwx as engine

        return getattr(engine, name)


basefwx = _LazyEngine()


def _mdcode_ascii(text: str) -> str:
    if not text.isascii():
        text.encode("ascii")
    data = text.encode("ascii")
    table = basefwx._MD_CODE_TABLE_BYTES
    result_parts = (
        [table[b] for b in data]
        if len(data) > basefwx._MDCODE_ASCII_THRESHOLD
        else (table[b] for b in data)
    )
    return b"".join(result_parts).decode("ascii")


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
            val = d0 * 10 + d1
            idx += 2
        elif span == 3:
            d0 = data[idx] - 48
            d1 = data[idx + 1] - 48
            d2 = data[idx + 2] - 48
            if d0 > 9 or d1 > 9 or d2 > 9:
                raise ValueError("Invalid mcode payload")
            val = d0 * 100 + d1 * 10 + d2
            idx += 3
        else:
            val = 0
            for offset in range(span):
                digit = data[idx + offset] - 48
                if digit > 9:
                    raise ValueError("Invalid mcode payload")
                val = val * 10 + digit
            idx += span
        if out_idx >= len(out):
            out.extend(bytes(len(out) // 2 + 64))
        out[out_idx] = val
        out_idx += 1
    return out[:out_idx].decode("latin-1")


def _coerce_text(data: "basefwx.typing.Union[str, bytes, bytearray, memoryview]") -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode("latin-1")
    raise TypeError(f"Unsupported type for textual conversion: {type(data)!r}")


def b256encode(
    cls,
    data: "basefwx.typing.Union[str, bytes, bytearray, memoryview]",
) -> str:
    text = cls._coerce_text(data)
    raw = cls._code_bytes(text)
    if cls.np is not None and len(raw) >= cls._B32_FAST_THRESHOLD:
        encoded = cls._fast_b32hexencode(raw).decode("utf-8")
    else:
        encoded = cls.base64.b32hexencode(raw).decode("utf-8")
    padding_count = encoded.count("=")
    return encoded.rstrip("=") + str(padding_count)


def b256decode(cls, string: str) -> str:
    padding_count = int(string[-1])
    base32text = string[:-1] + "=" * padding_count
    data = base32text.encode("utf-8")
    if cls.np is not None and len(data) >= cls._B32_FAST_THRESHOLD:
        decoded = cls._fast_b32hexdecode(data).decode("utf-8")
    else:
        decoded = cls.base64.b32hexdecode(data).decode("utf-8")
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
    def maindc(value):
        try:
            if not value or not value[0].isdigit():
                return "AN ERROR OCCURED!"
            leoa = int(value[0])
            if leoa <= 0 or len(value) < leoa + 1:
                return "AN ERROR OCCURED!"
            length_str = value[1 : leoa + 1]
            md_len = int(length_str)
            code = str(md_len * md_len)
            payload = value[leoa + 1 :]
            string3 = basefwx.fwx256unbin(
                payload.replace("4G5tRA", "=")
            )
            if string3 and string3[0] == "0":
                string3 = "-" + string3[1:]
            md_code = basefwx._mdcode_ascii(code)
            if (
                len(string3) <= basefwx._DECIMAL_INT_LIMIT
                and len(md_code) <= basefwx._DECIMAL_INT_LIMIT
            ):
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


def bi512encode(string: str):
    code = string[0] + string[len(string) - 1]
    left = basefwx._mdcode_ascii(string)
    right = basefwx._mdcode_ascii(code)
    diff = basefwx._decimal_diff(left, right)
    packed = basefwx._fwx256bin_bytes(diff)
    return str(basefwx.hashlib.sha256(packed).hexdigest()).replace("-", "0")


def _strip_leading_zeros(number: str) -> str:
    if not number:
        return "0"
    stripped = number.lstrip("0")
    return stripped if stripped else "0"


def _compare_magnitude(left: str, right: str) -> int:
    normalized_left = basefwx._strip_leading_zeros(left)
    normalized_right = basefwx._strip_leading_zeros(right)
    if len(normalized_left) != len(normalized_right):
        return -1 if len(normalized_left) < len(normalized_right) else 1
    if normalized_left == normalized_right:
        return 0
    return -1 if normalized_left < normalized_right else 1


def _decimal_diff(left: str, right: str) -> str:
    if len(left) <= 1000 and len(right) <= 1000:
        try:
            left_int = int(left)
            right_int = int(right)
            if left_int >= right_int:
                return str(left_int - right_int)
            return "0" + str(right_int - left_int)
        except (ValueError, OverflowError, MemoryError):
            pass
    comparison = basefwx._compare_magnitude(left, right)
    if comparison >= 0:
        return basefwx._subtract_magnitude(left, right)
    return "0" + basefwx._subtract_magnitude(right, left)


def _add_magnitude(left: str, right: str) -> str:
    left_bytes = left.encode("ascii")
    right_bytes = right.encode("ascii")
    left_index = len(left_bytes) - 1
    right_index = len(right_bytes) - 1
    carry = 0
    max_len = max(len(left_bytes), len(right_bytes)) + 1
    out = bytearray(max_len)
    position = max_len - 1
    while left_index >= 0 or right_index >= 0 or carry:
        left_digit = left_bytes[left_index] - 48 if left_index >= 0 else 0
        right_digit = (
            right_bytes[right_index] - 48 if right_index >= 0 else 0
        )
        total = left_digit + right_digit + carry
        out[position] = 48 + total % 10
        carry = total // 10
        left_index -= 1
        right_index -= 1
        position -= 1
    index = position + 1
    while index < max_len and out[index] == 48:
        index += 1
    if index == max_len:
        return "0"
    return out[index:].decode("ascii")


def _subtract_magnitude(left: str, right: str) -> str:
    """Decimal string subtraction (left >= right assumed)."""
    left_len = len(left)
    right_len = len(right)
    if basefwx.np is not None and left_len >= 1000:
        np = basefwx.np
        left_array = (
            np.frombuffer(left.encode("ascii"), dtype=np.uint8).astype(np.int16)
            - 48
        )
        right_array = np.zeros(left_len, dtype=np.int16)
        if right_len > 0:
            right_array[-right_len:] = (
                np.frombuffer(right.encode("ascii"), dtype=np.uint8) - 48
            )
        result = left_array - right_array
        while True:
            mask = result < 0
            if not np.any(mask):
                break
            borrow_from = np.where(mask)[0] - 1
            borrow_from = borrow_from[borrow_from >= 0]
            result[mask] += 10
            np.subtract.at(result, borrow_from, 1)
        out = (result.astype(np.uint8) + 48).tobytes()
        index = 0
        while index < left_len - 1 and out[index] == 48:
            index += 1
        return out[index:].decode("ascii")
    left_bytes = left.encode("ascii")
    right_bytes = right.encode("ascii")
    left_index = left_len - 1
    right_index = right_len - 1
    borrow = 0
    out = bytearray(left_len)
    position = left_len - 1
    while left_index >= 0:
        left_digit = left_bytes[left_index] - 48 - borrow
        right_digit = (
            right_bytes[right_index] - 48 if right_index >= 0 else 0
        )
        if left_digit < right_digit:
            left_digit += 10
            borrow = 1
        else:
            borrow = 0
        out[position] = 48 + (left_digit - right_digit)
        left_index -= 1
        right_index -= 1
        position -= 1
    index = 0
    while index < left_len and out[index] == 48:
        index += 1
    if index == left_len:
        return "0"
    return out[index:].decode("ascii")


def _add_signed(left: str, right: str) -> str:
    def parse_signed(value: str) -> tuple[bool, str]:
        if not value:
            return (False, "0")
        negative = value[0] == "-"
        digits = value[1:] if negative else value
        digits = basefwx._strip_leading_zeros(digits)
        if digits == "0":
            negative = False
        return (negative, digits)

    left_negative, left_digits = parse_signed(left)
    right_negative, right_digits = parse_signed(right)
    if left_negative == right_negative:
        total = basefwx._add_magnitude(left_digits, right_digits)
        return "-" + total if left_negative and total != "0" else total
    comparison = basefwx._compare_magnitude(left_digits, right_digits)
    if comparison == 0:
        return "0"
    if comparison > 0:
        difference = basefwx._subtract_magnitude(left_digits, right_digits)
        return "-" + difference if left_negative else difference
    difference = basefwx._subtract_magnitude(right_digits, left_digits)
    return "-" + difference if right_negative else difference


def uhash513(string: str):
    input_text = string
    if os.getenv("BASEFWX_UHASH_LEGACY") == "1":
        input_bytes = input_text.encode("utf-8")
        first_digest = hashlib.sha256(input_bytes).hexdigest().encode("utf-8")
        compatibility_sha1 = hashlib.sha1(
            first_digest,
            usedforsecurity=False,
        ).hexdigest().encode("utf-8")
        chained_digest = hashlib.sha512(compatibility_sha1).hexdigest()
        input_digest = hashlib.sha512(input_bytes).hexdigest()
        encoded = basefwx.b512encode(chained_digest, input_digest)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    first = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
    compatibility_sha1 = hashlib.sha1(
        first.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    chained = hashlib.sha512(compatibility_sha1.encode("utf-8")).hexdigest()
    direct = hashlib.sha512(input_text.encode("utf-8")).hexdigest()
    return hashlib.sha256((chained + direct).encode("utf-8")).hexdigest()


def install(engine) -> None:
    engine._MD_CODE_TABLE_BYTES = tuple(
        f"{len(str(value))}{value}".encode("ascii") for value in range(256)
    )
    engine._MDCODE_ASCII_THRESHOLD = 500
    engine._mdcode_ascii = staticmethod(_mdcode_ascii)
    engine._mcode_digits = staticmethod(_mcode_digits)
    engine._coerce_text = staticmethod(_coerce_text)
    engine._strip_leading_zeros = staticmethod(_strip_leading_zeros)
    engine._compare_magnitude = staticmethod(_compare_magnitude)
    engine._decimal_diff = staticmethod(_decimal_diff)
    engine._add_magnitude = staticmethod(_add_magnitude)
    engine._subtract_magnitude = staticmethod(_subtract_magnitude)
    engine._add_signed = staticmethod(_add_signed)
    engine.b256decode = classmethod(b256decode)
    engine.b256encode = classmethod(b256encode)
    engine.a512encode = staticmethod(a512encode)
    engine.a512decode = staticmethod(a512decode)
    engine.bi512encode = staticmethod(bi512encode)
    engine.uhash513 = staticmethod(uhash513)
