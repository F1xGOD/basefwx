# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Public wrappers for retired text-codec compatibility."""

import warnings

from ..main import basefwx


def b256encode(string: str):
    warnings.warn(
        "b256 is retired and available only for compatibility; use base64 "
        "for new reversible encodings.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.b256encode(string)


def b256decode(string: str):
    warnings.warn(
        "b256 is retired and available only for compatibility.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.b256decode(string)


def a512encode(string: str):
    warnings.warn(
        "a512 is retired reversible obfuscation; use base64 for new data.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.a512encode(string)


def a512decode(string: str):
    warnings.warn(
        "a512 is retired and available only for compatibility.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.a512decode(string)


def bi512encode(string: str):
    warnings.warn(
        "bi512 is retired; use hash512 for new hashes.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.bi512encode(string)


def uhash513(string: str):
    warnings.warn(
        "uhash513 is retired; use hash512 or SHA3-512 for new hashes.",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.uhash513(string)


__all__ = [
    "a512decode",
    "a512encode",
    "b256decode",
    "b256encode",
    "bi512encode",
    "uhash513",
]
