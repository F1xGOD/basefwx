# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _ensure_cp(cls):
    if cls._cp_load_attempted:
        return cls.cp
    cls._cp_load_attempted = True
    try:
        import cupy as _cp
        cls.cp = _cp
    except Exception:
        cls.cp = None
    return cls.cp


def kFMe(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    payload = src.read_bytes()
    if basefwx._kfm_is_audio_ext(src_ext):
        flags = basefwx.KFM_FLAG_BW if bw_mode else 0
        container = basefwx._kfm_pack_container(basefwx.KFM_MODE_AUDIO_IMAGE, payload, src_ext, flags=flags)
        out_path = basefwx._kfm_resolve_output(src, output, '.png', 'kfme')
        basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
    else:
        container = basefwx._kfm_pack_container(basefwx.KFM_MODE_IMAGE_AUDIO, payload, src_ext)
        out_path = basefwx._kfm_resolve_output(src, output, '.wav', 'kfme')
        basefwx._kfm_bytes_to_wav(container, out_path)
    return str(out_path)


def kFMd(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    if bw_mode:
        basefwx._kfm_warn('kFMd --bw is deprecated and ignored in strict decode mode.')
    decoded = basefwx._kfm_decode_container(src, src_ext)
    ext = decoded['ext']
    out_path = basefwx._kfm_resolve_output(src, output, ext, 'kfmd')
    out_path.write_bytes(decoded['payload'])
    return str(out_path)


def _kfae_legacy_encode(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    payload = src.read_bytes()
    flags = basefwx.KFM_FLAG_BW if bw_mode else 0
    container = basefwx._kfm_pack_container(basefwx.KFM_MODE_AUDIO_IMAGE, payload, src_ext, flags=flags)
    out_path = basefwx._kfm_resolve_output(src, output, '.png', 'kfae')
    basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
    return str(out_path)


def kFAe(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    basefwx._kfm_warn('kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode.')
    return basefwx._kfae_legacy_encode(path, output, bw_mode=bw_mode)


def kFAd(path: str, output: str | None=None) -> str:
    basefwx._kfm_warn('kFAd is deprecated; use kFMd (auto-detect) instead.')
    return basefwx.kFMd(path, output)
