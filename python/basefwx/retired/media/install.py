# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Attach retired jMG/kFM/kFA compatibility APIs to the legacy engine."""

from __future__ import annotations

import wave
from io import BytesIO

from . import _jmg, _kfm, _media


_CONSTANTS = {
    "KFM_MAGIC": b"KFM!",
    "KFM_VERSION": 1,
    "KFM_MODE_IMAGE_AUDIO": 1,
    "KFM_MODE_AUDIO_IMAGE": 2,
    "KFM_FLAG_BW": 1,
    "KFM_MAX_PAYLOAD": 1_073_741_824,
    "KFM_AUDIO_RATE": 24000,
    "KFM_ACCEL_ENV": "BASEFWX_KFM_ACCEL",
    "KFM_ACCEL_MIN_BYTES_ENV": "BASEFWX_KFM_ACCEL_MIN_BYTES",
    "KFM_ACCEL_DEFAULT_MIN_BYTES": 1 * 1024 * 1024,
    "KFM_AUDIO_EXTENSIONS": frozenset({
        ".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".oga",
        ".opus", ".wma", ".amr", ".aiff", ".aif", ".alac", ".m4b",
        ".caf", ".mka",
    }),
    "KFM_IMAGE_EXTENSIONS": frozenset({
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif",
        ".tiff", ".ico", ".heic", ".heif", ".ppm", ".pgm",
    }),
    "IMAGECIPHER_SCRAMBLE_CONTEXT": b"basefwx.imagecipher.scramble.v1",
    "IMAGECIPHER_OFFSET_CONTEXT": b"basefwx.imagecipher.offset.v1",
    "IMAGECIPHER_AEAD_INFO": b"basefwx.image.v1",
    "IMAGECIPHER_STREAM_INFO": b"basefwx.imagecipher.stream.v1",
    "IMAGECIPHER_ARCHIVE_INFO": b"basefwx.imagecipher.archive.v1",
    "IMAGECIPHER_TRAILER_MAGIC": b"JMG0",
    "IMAGECIPHER_KEY_TRAILER_MAGIC": b"JMG1",
    "JMG_KEY_MAGIC": b"JMGK",
    "JMG_KEY_VERSION_LEGACY": 1,
    "JMG_KEY_VERSION": 2,
    "JMG_SECURITY_PROFILE_LEGACY": 0,
    "JMG_SECURITY_PROFILE_MAX": 1,
    "JMG_SECURITY_PROFILE_DEFAULT": 1,
    "JMG_SECURITY_PROFILE_LABELS": {0: "legacy", 1: "max"},
    "JMG_SECURITY_PROFILE_NAMES": {"legacy": 0, "max": 1},
    "JMG_VIDEO_ENABLE_ENV": "BASEFWX_ENABLE_JMG_VIDEO",
    "JMG_MASK_INFO": b"basefwx.jmg.mask.v1",
    "JMG_MASK_AAD": b"jmg",
}

_JMG_FUNCTIONS = (
    "_jmg_security_profile_id",
    "_jmg_video_enabled",
    "_jmg_stream_info_for_profile",
    "_jmg_archive_info_for_profile",
    "_jmg_build_key_header",
    "_jmg_profile_from_key_header",
    "_jmg_parse_key_header",
    "_jmg_prepare_keys",
    "_append_balanced_trailer",
    "_extract_balanced_trailer_from_bytes",
    "_extract_balanced_trailer_info",
)

_KFM_FUNCTIONS = (
    "_kfm_clean_ext",
    "_kfm_is_audio_ext",
    "_kfm_is_image_ext",
    "_kfm_warn",
    "_kfm_accel_mode",
    "_kfm_accel_min_bytes",
    "_kfm_should_use_cuda",
    "_kfm_paths_equal",
    "_kfm_default_output",
    "_kfm_resolve_output",
    "_kfm_keystream",
    "_kfm_xor",
    "_kfm_pack_container",
    "_kfm_unpack_container",
    "_kfm_bytes_to_wav",
    "_kfm_wav_to_bytes",
    "_kfm_pcm16le_to_bytes",
    "_kfm_ffmpeg_audio_to_bytes",
    "_kfm_audio_to_bytes",
    "_kfm_bytes_to_png",
    "_kfm_png_to_bytes",
    "_kfm_detect_carrier_kinds",
    "_kfm_decode_container",
    "kFMe",
    "_kfae_legacy_encode",
    "kFMd",
    "kFAe",
    "kFAd",
)


def _require_pil(engine) -> None:
    if engine.Image is None:
        raise RuntimeError(
            "Pillow is required for retired media compatibility "
            "(pip install Pillow)"
        )


def _try_encrypt_media(
    engine,
    path,
    password,
    *,
    output,
    ignore_media,
    keep_meta,
    archive_original,
    keep_input,
    reporter,
    display_path,
):
    if ignore_media:
        return None
    media_ext = path.suffix.lower()
    supported = (
        engine.MediaCipher.IMAGE_EXTS
        | engine.MediaCipher.VIDEO_EXTS
        | engine.MediaCipher.AUDIO_EXTS
    )
    if media_ext not in supported:
        return None
    try:
        return engine.MediaCipher.encrypt_media(
            str(path),
            password,
            output=output,
            keep_meta=keep_meta,
            archive_original=archive_original,
            keep_input=keep_input,
            reporter=reporter,
            file_index=0,
            display_path=display_path,
        )
    except Exception:
        # Preserve the historical fwxAES media auto-route fallback.
        return None


def install(engine) -> None:
    import struct

    try:
        from PIL import Image
    except Exception:  # pragma: no cover - optional compatibility dependency
        Image = None

    for name, value in _CONSTANTS.items():
        setattr(engine, name, value)
    engine.KFM_HEADER_STRUCT = struct.Struct(">4sBBBBQIQI")
    engine.KFM_HEADER_LEN = engine.KFM_HEADER_STRUCT.size
    engine.Image = Image
    engine.BytesIO = BytesIO
    engine.wave = wave
    engine.cp = None
    engine._cp_load_attempted = False
    engine._require_pil = staticmethod(lambda: _require_pil(engine))
    engine._ensure_cp = classmethod(_kfm._ensure_cp)
    for name in _JMG_FUNCTIONS:
        setattr(engine, name, staticmethod(getattr(_jmg, name)))
    for name in _KFM_FUNCTIONS:
        setattr(engine, name, staticmethod(getattr(_kfm, name)))
    engine.ImageCipher = _media.ImageCipher
    engine.MediaCipher = _media.MediaCipher
    engine._try_encrypt_retired_media = staticmethod(
        lambda *args, **kwargs: _try_encrypt_media(engine, *args, **kwargs)
    )
