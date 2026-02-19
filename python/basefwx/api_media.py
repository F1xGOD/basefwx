"""Media carrier helpers (kFM/kFA and media cipher wrappers)."""

from .main import basefwx


def kFMe(path: str, output: str | None = None, *, bw_mode: bool = False):
    return basefwx.kFMe(path, output, bw_mode=bw_mode)


def kFMd(path: str, output: str | None = None, *, bw_mode: bool = False):
    return basefwx.kFMd(path, output, bw_mode=bw_mode)


def kFAe(path: str, output: str | None = None, *, bw_mode: bool = False):
    return basefwx.kFAe(path, output, bw_mode=bw_mode)


def kFAd(path: str, output: str | None = None):
    return basefwx.kFAd(path, output)


def jMGe(
    path: str,
    password: str = "",
    output: str | None = None,
    *,
    keep_meta: bool = False,
    keep_input: bool = False,
):
    return basefwx.MediaCipher.encrypt_media(
        path,
        password,
        output=output,
        keep_meta=keep_meta,
        keep_input=keep_input,
    )


def jMGd(path: str, password: str = "", output: str | None = None):
    return basefwx.MediaCipher.decrypt_media(path, password, output=output)


__all__ = ["jMGd", "jMGe", "kFAd", "kFAe", "kFMd", "kFMe"]
