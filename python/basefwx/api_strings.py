# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""String/byte codec convenience wrappers."""

import warnings

from .main import basefwx


def b64encode(string: str):
    return basefwx.b64encode(string)


def b512encode(string: str, code: str = "", use_master: bool = False):
    return basefwx.b512encode(string, code, use_master=use_master)


def b256encode(string: str):
    return basefwx.b256encode(string)


def n10encode(data):
    return basefwx.n10encode(data)


def n10encode_bytes(data):
    return basefwx.n10encode_bytes(data)


# b1024encode retired in 3.6.5 — was bi512encode(a512encode(string)).


def bi512encode(string: str):
    """Deprecated since 3.7.0: SHA-256 with a custom prefilter (no added security).

    Use ``hash512`` or ``uhash513`` for new code.
    """
    warnings.warn(
        "bi512encode is deprecated since 3.7.0; use hash512 or uhash513 "
        "(bi512 is SHA-256 with a prefilter and adds no security).",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.bi512encode(string)


def pb512encode(string: str, code: str = "", use_master: bool = False):
    return basefwx.pb512encode(string, code, use_master=use_master)


def a512encode(string: str):
    """Deprecated since 3.7.0: reversible obfuscation codec with no security goal.

    Use ``b256encode`` or stdlib ``base64.b64encode`` for new code.
    """
    warnings.warn(
        "a512encode is deprecated since 3.7.0; use b256encode or base64 "
        "(a512 is a slow obfuscation codec with no security goal).",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.a512encode(string)


def hash512(string: str):
    return basefwx.hash512(string)


def uhash513(string: str):
    return basefwx.uhash513(string)


def b64decode(string: str):
    return basefwx.b64decode(string)


def b256decode(string: str):
    return basefwx.b256decode(string)


def n10decode(string: str, errors: str = "strict"):
    return basefwx.n10decode(string, errors=errors)


def n10decode_bytes(string: str):
    return basefwx.n10decode_bytes(string)


def a512decode(string: str):
    """Deprecated since 3.7.0 — see :func:`a512encode`."""
    warnings.warn(
        "a512decode is deprecated since 3.7.0; the matching a512encode is "
        "also deprecated. Old blobs still decode.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.a512decode(string)


def b512decode(string: str, code: str = "", use_master: bool = False):
    return basefwx.b512decode(string, code, use_master=use_master)


def pb512decode(string: str, code: str = "", use_master: bool = False):
    return basefwx.pb512decode(string, code, use_master=use_master)


__all__ = [
    "a512decode",
    "a512encode",
    "b256decode",
    "b256encode",
    "b512decode",
    "b512encode",
    "b64decode",
    "b64encode",
    "bi512encode",
    "hash512",
    "n10decode",
    "n10decode_bytes",
    "n10encode",
    "n10encode_bytes",
    "pb512decode",
    "pb512encode",
    "uhash513",
]
