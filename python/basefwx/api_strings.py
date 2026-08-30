# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""String/byte codec convenience wrappers."""

from .main import basefwx


def b64encode(string: str):
    return basefwx.b64encode(string)


def b512encode(string: str, code: str = "", use_master: bool = False):
    """Password-keyed (or master-keyed) AEAD encoding to a base64 string.

    Sibling of :func:`pb512encode`; pick the one that matches your use case:

    * **b512** allows the password to be empty *if* ``use_master=True`` —
      so you can encrypt to just the master public key with no user
      secret. Output uses canonical standard base64 (may contain ``+`` and
      ``/``).
      AEAD label / HKDF info: ``basefwx.b512.*``.
    * **pb512** requires a non-empty password and uses the same canonical
      standard base64 alphabet. Decoders retain the older URL-safe alphabet
      for compatibility.
      AEAD label / HKDF info: ``basefwx.pb512.*``.

    Both v3 payloads use AES-256-GCM with a payload key derived from the
    wrapped mask key. Distinct HKDF and AAD domains prevent blobs from
    crossing between the two APIs. The historical token map is cosmetic and
    is writer opt-in through ``BASEFWX_OBFUSCATE_CODECS=1``.
    """
    return basefwx.b512encode(string, code, use_master=use_master)


def n10encode(data):
    return basefwx.n10encode(data)


def n10encode_bytes(data):
    return basefwx.n10encode_bytes(data)


def pb512encode(string: str, code: str = "", use_master: bool = False):
    """Password-keyed AEAD encoding to a canonical base64 string.

    Sibling of :func:`b512encode`; see that function's docstring for
    the side-by-side comparison. Short version: **pb512 = password
    required**; **b512 = password optional with master**. Both writers use
    standard base64 and both decoders accept older URL-safe input.
    """
    return basefwx.pb512encode(string, code, use_master=use_master)


def hash512(string: str):
    return basefwx.hash512(string)


def b64decode(string: str):
    return basefwx.b64decode(string)


def n10decode(string: str, errors: str = "strict"):
    return basefwx.n10decode(string, errors=errors)


def n10decode_bytes(string: str):
    return basefwx.n10decode_bytes(string)


def b512decode(string: str, code: str = "", use_master: bool = False):
    return basefwx.b512decode(string, code, use_master=use_master)


def pb512decode(string: str, code: str = "", use_master: bool = False):
    return basefwx.pb512decode(string, code, use_master=use_master)


__all__ = [
    "b512decode",
    "b512encode",
    "b64decode",
    "b64encode",
    "hash512",
    "n10decode",
    "n10decode_bytes",
    "n10encode",
    "n10encode_bytes",
    "pb512decode",
    "pb512encode",
]
