# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

from ._b512_obfuscation import (
    _estimate_aead_blob_size,
    _pack_length_prefixed,
    _resolve_payload_length_from_file_size,
    _unpack_length_prefixed,
)
from ._b512_memory import (
    _b512decode_legacy,
    _pb512decode_legacy,
    b512decode,
    b512encode,
    b512file_decode_bytes,
    b512file_encode_bytes,
    pb512decode,
    pb512encode,
    pb512file_decode_bytes,
    pb512file_encode_bytes,
)
from ._b512_stream import (
    _aes_heavy_encode_path_stream,
    _b512_decode_path,
    _b512_decode_path_stream,
    _b512_encode_path,
    _b512_encode_path_stream,
    b512file,
    b512file_decode,
    b512file_encode,
)

__all__ = [
    "_aes_heavy_encode_path_stream",
    "_b512_decode_path",
    "_b512_decode_path_stream",
    "_b512_encode_path",
    "_b512_encode_path_stream",
    "_b512decode_legacy",
    "_estimate_aead_blob_size",
    "_pack_length_prefixed",
    "_pb512decode_legacy",
    "_resolve_payload_length_from_file_size",
    "_unpack_length_prefixed",
    "b512decode",
    "b512encode",
    "b512file",
    "b512file_decode",
    "b512file_decode_bytes",
    "b512file_encode",
    "b512file_encode_bytes",
    "pb512decode",
    "pb512encode",
    "pb512file_decode_bytes",
    "pb512file_encode_bytes",
]
