"""String/byte codec convenience wrappers."""

from .main import basefwx


def b64encode(string: str):
    return basefwx.b64encode(string)


def b512encode(string: str, code: str = "", use_master: bool = True):
    return basefwx.b512encode(string, code, use_master=use_master)


def b256encode(string: str):
    return basefwx.b256encode(string)


def n10encode(data):
    return basefwx.n10encode(data)


def n10encode_bytes(data):
    return basefwx.n10encode_bytes(data)


def b1024encode(string: str):
    return basefwx.b1024encode(string)


def bi512encode(string: str):
    return basefwx.bi512encode(string)


def pb512encode(string: str, code: str = "", use_master: bool = True):
    return basefwx.pb512encode(string, code, use_master=use_master)


def a512encode(string: str):
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
    return basefwx.a512decode(string)


def b512decode(string: str, code: str = "", use_master: bool = True):
    return basefwx.b512decode(string, code, use_master=use_master)


def pb512decode(string: str, code: str = "", use_master: bool = True):
    return basefwx.pb512decode(string, code, use_master=use_master)


__all__ = [
    "a512decode",
    "a512encode",
    "b1024encode",
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
