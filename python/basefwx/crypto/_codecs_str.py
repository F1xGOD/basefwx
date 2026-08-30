# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Maintained text and base32 codec implementations."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from ..legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()


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
