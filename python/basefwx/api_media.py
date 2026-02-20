"""Media carrier helpers (kFM/kFA and media cipher wrappers)."""

import sys
import warnings

from .main import basefwx


def _with_friendly_interrupt(fn, *args, **kwargs):
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", UserWarning)
            result = fn(*args, **kwargs)
        for item in caught:
            msg = str(item.message).strip()
            if msg:
                print(f"⚠ {msg}", file=sys.stderr)
        return result
    except KeyboardInterrupt:
        raise KeyboardInterrupt("Exiting...") from None


def kFMe(path: str, output: str | None = None, *, bw_mode: bool = False):
    return _with_friendly_interrupt(basefwx.kFMe, path, output, bw_mode=bw_mode)


def kFMd(path: str, output: str | None = None, *, bw_mode: bool = False):
    return _with_friendly_interrupt(basefwx.kFMd, path, output, bw_mode=bw_mode)


def kFAe(path: str, output: str | None = None, *, bw_mode: bool = False):
    return _with_friendly_interrupt(basefwx.kFAe, path, output, bw_mode=bw_mode)


def kFAd(path: str, output: str | None = None):
    return _with_friendly_interrupt(basefwx.kFAd, path, output)


def jMGe(
    path: str,
    password: str = "",
    output: str | None = None,
    *,
    keep_meta: bool = False,
    archive_original: bool = False,
    keep_input: bool = False,
):
    return _with_friendly_interrupt(
        basefwx.MediaCipher.encrypt_media,
        path,
        password,
        output=output,
        keep_meta=keep_meta,
        archive_original=archive_original,
        keep_input=keep_input,
    )


def jMGd(path: str, password: str = "", output: str | None = None):
    return _with_friendly_interrupt(
        basefwx.MediaCipher.decrypt_media,
        path,
        password,
        output=output,
    )


__all__ = ["jMGd", "jMGe", "kFAd", "kFAe", "kFMd", "kFMe"]
