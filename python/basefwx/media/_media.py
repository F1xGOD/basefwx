# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.


from __future__ import annotations

from ._media_image import ImageCipher
from ._media_pipeline import _MediaPipelineMixin
from ._media_support import _MediaSupportMixin
from ._media_trailer import _MediaTrailerMixin
from ._media_transforms import _MediaTransformMixin


class MediaCipher(_MediaPipelineMixin, _MediaTrailerMixin, _MediaTransformMixin, _MediaSupportMixin):
    """Media cipher for images/videos/audio with deterministic shuffling + AES-CTR masking."""
    VIDEO_GROUP_SECONDS = 1.0
    VIDEO_GROUP_MAX_FRAMES = 12
    VIDEO_BLOCK_SIZE = 2
    VIDEO_MASK_BITS = 6
    VIDEO_MASK_BITS_MAX = 8
    AUDIO_BLOCK_SECONDS = 0.15
    AUDIO_GROUP_SECONDS = 1.0
    AUDIO_MASK_BITS = 13
    AUDIO_MASK_BITS_MAX = 16
    DEFAULT_SECURITY_PROFILE = 1
    JMG_TARGET_GROWTH = 1.1
    JMG_MAX_GROWTH = 2.0
    JMG_MIN_AUDIO_BPS = 64000
    JMG_MIN_VIDEO_BPS = 200000
    TRAILER_FALLBACK_MAX = 64 * 1024 * 1024
    WORKSPACE_RESERVE_BYTES = 64 * 1024 * 1024
    IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.bmp', '.tga', '.gif', '.webp', '.tif', '.tiff', '.heic', '.heif', '.avif', '.ico'}
    VIDEO_EXTS = {'.mp4', '.mkv', '.mov', '.avi', '.webm', '.m4v', '.flv', '.wmv', '.mpg', '.mpeg', '.3gp', '.3g2', '.ts', '.m2ts'}
    AUDIO_EXTS = {'.mp3', '.wav', '.flac', '.aac', '.m4a', '.ogg', '.opus', '.wma', '.aiff', '.alac'}
    HWACCEL_ENV = 'BASEFWX_HWACCEL'
    HWACCEL_STRICT_ENV = 'BASEFWX_HWACCEL_STRICT'
    GPU_PIXELS_ENV = 'BASEFWX_GPU_PIXELS'
    GPU_PIXELS_MIN_BYTES_ENV = 'BASEFWX_GPU_PIXELS_MIN_BYTES'
    GPU_PIXELS_MIN_BYTES_DEFAULT = 1000000
    GPU_PIXELS_AUTO_MIN_BYTES = 8 * 1024 * 1024
    _HWACCEL_CACHE: 'basefwx.typing.Optional[str]' = None
    _HWACCEL_READY = False
    _HWACCEL_ENV_CACHE: 'basefwx.typing.Optional[str]' = None
    _ENCODER_CACHE: 'basefwx.typing.Optional[set[str]]' = None
    _HWACCELS_CACHE: 'basefwx.typing.Optional[set[str]]' = None
    _CUDA_RUNTIME_READY: 'basefwx.typing.Optional[bool]' = None
    _CUDA_RUNTIME_ERROR: str = ''
    _CUDA_RUNTIME_ENV_CACHE: 'basefwx.typing.Optional[str]' = None
