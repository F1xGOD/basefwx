# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""String/byte codec convenience wrappers."""

import warnings

from .main import basefwx


def b64encode(string: str):
    return basefwx.b64encode(string)


def b512encode(string: str, code: str = "", use_master: bool = False):
    """Password-keyed (or master-keyed) AEAD encoding to a base64 string.

    Sibling of :func:`pb512encode`; pick the one that matches your use case:

    * **b512** allows the password to be empty *if* ``use_master=True`` —
      so you can encrypt to just the master public key with no user
      secret. Output uses standard base64 (may contain ``+`` and ``/``).
      AEAD label / HKDF info: ``basefwx.b512.*``.
    * **pb512** requires a non-empty password. Output is URL-safe base64
      (``-`` / ``_`` instead of ``+`` / ``/``), so the string travels
      cleanly through URLs, filenames, and most other text channels.
      AEAD label / HKDF info: ``basefwx.pb512.*``.

    Their underlying primitive (HKDF mask + AES-GCM) is identical; the
    AAD-label difference is intentional domain separation so blobs do
    not cross between the two APIs.
    """
    return basefwx.b512encode(string, code, use_master=use_master)


def b256encode(string: str):
    """Retired since 3.7.0 — see the :func:`b256encode` deprecation note below.

    b256 was the very first encoding method in BaseFWX, born in V1 when this
    was a proof of concept and not a project. Existing b256-encoded blobs
    still decode; use stdlib ``base64.b64encode`` or :func:`hash512` /
    :func:`uhash513` for new code. Emits a one-time retirement notice
    via :class:`DeprecationWarning` on first call.
    """
    warnings.warn(
        "🫡 b256 has been retired as of BaseFWX 3.7.0. "
        "b256 was the very first encoding method in BaseFWX, born in V1 "
        "back when this was a proof of concept and not a project. It served "
        "from day one. Existing b256-encoded blobs still decode; use base64 "
        "or hash512 / uhash513 for new code. ❤️  Thank you for the journey. "
        "It's time to go.",
        DeprecationWarning,
        stacklevel=2,
    )
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
    """Password-keyed AEAD encoding to a URL-safe base64 string.

    Sibling of :func:`b512encode`; see that function's docstring for
    the side-by-side comparison. Short version: **pb512 = password
    required, output is URL-safe**; **b512 = password optional with
    master, output is standard base64**.
    """
    return basefwx.pb512encode(string, code, use_master=use_master)


def a512encode(string: str):
    """Deprecated since 3.7.0: reversible obfuscation codec with no security goal.

    Use stdlib ``base64.b64encode`` for new code.
    """
    warnings.warn(
        "a512encode is deprecated since 3.7.0; use stdlib base64 "
        "(a512 is a slow obfuscation codec with no security goal).",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.a512encode(string)


def hash512(string: str):
    return basefwx.hash512(string)


def uhash513(string: str):
    """Deprecated since 3.7.0: non-standard chained hash.

    ``uhash513`` computes ``SHA-256 → SHA-1 → SHA-512 → SHA-256`` over the
    concatenation of two intermediate digests. The embedded SHA-1 step
    adds no security and uses a hash with known collision weaknesses;
    the overall collision resistance is bounded by the outer SHA-256
    anyway. The "513" in the name is marketing — the output is a
    256-bit SHA-256 hex string. Use :func:`hash512` (SHA-512) or
    ``hashlib.new('sha3_512')`` for new code.
    """
    warnings.warn(
        "uhash513 is deprecated since 3.7.0; use hash512 (SHA-512) or "
        "SHA3-512 (uhash513 is a non-standard chain with a SHA-1 hop and "
        "a misleading name).",
        DeprecationWarning,
        stacklevel=2,
    )
    return basefwx.uhash513(string)


def b64decode(string: str):
    return basefwx.b64decode(string)


def b256decode(string: str):
    """Retired since 3.7.0 — see :func:`b256encode`. Existing blobs still decode."""
    warnings.warn(
        "🫡 b256 has been retired as of BaseFWX 3.7.0. "
        "Existing b256-encoded blobs still decode; the matching b256encode "
        "is also retired. ❤️  Thank you for the journey.",
        DeprecationWarning,
        stacklevel=2,
    )
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
