# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Public Python API for BaseFWX."""

from typing import Optional

from . import x25519
from .features import RETIRED_MEDIA_ENABLED
from .api_files import (
    LiveDecryptor,
    LiveEncryptor,
    an7_file,
    b512decodefile,
    b512encodefile,
    b512file_decode_bytes,
    b512file_encode_bytes,
    b512handlefile,
    dean7_file,
    fwxAES,
    fwxAES_decrypt_raw,
    fwxAES_decrypt_stream,
    fwxAES_encrypt_raw,
    fwxAES_encrypt_stream,
    fwxAES_live_decrypt_chunks,
    fwxAES_live_decrypt_ffmpeg,
    fwxAES_live_decrypt_stream,
    fwxAES_live_encrypt_chunks,
    fwxAES_live_encrypt_ffmpeg,
    fwxAES_live_encrypt_stream,
    normalize_unwrap,
    normalize_wrap,
    pb512file_decode_bytes,
    pb512file_encode_bytes,
)
from .api_strings import (
    b512decode,
    b512encode,
    b64decode,
    b64encode,
    hash512,
    n10decode,
    n10decode_bytes,
    n10encode,
    n10encode_bytes,
    pb512decode,
    pb512encode,
)
from .crypto._pq import (
    current_kem_algorithm,
    generate_kem_keypair,
    is_supported_kem_algorithm,
    kem_algorithm_for_public_key,
)
from .main import basefwx, cli, main
from .plugin import (
    API_VERSION as PLUGIN_API_VERSION,
    BasefwxPlugin,
    BasefwxPluginError,
    NativePluginShim,
    PLUGIN_ID_LEN,
    PluginErrorBadInput,
    PluginErrorBadState,
    PluginErrorGeneric,
    PluginErrorNotSupported,
    PluginErrorOutputTooSmall,
    Position as PluginPosition,
    all_plugins,
    discover as discover_plugins,
    factory_for as plugin_factory_for,
    load_native_plugin,
    register as register_plugin,
    register_native as register_native_plugin,
)
from .version import __version__

HAS_RETIRED_MEDIA = RETIRED_MEDIA_ENABLED


def hkdf_sha256(
    key_material: bytes,
    *,
    length: int = 32,
    info: bytes = b"basefwx.kem.v1",
    salt: Optional[bytes] = None,
) -> bytes:
    """Derive key material with HKDF-SHA256 and an optional explicit salt."""
    from .crypto._primitives import _hkdf_sha256

    return _hkdf_sha256(
        key_material,
        length=length,
        info=info,
        salt=salt,
    )


__all__ = [
    "__version__",
    "an7_file",
    "b512decode",
    "b512decodefile",
    "b512encode",
    "b512encodefile",
    "b512file_decode_bytes",
    "b512file_encode_bytes",
    "b512handlefile",
    "b64decode",
    "b64encode",
    "basefwx",
    "cli",
    "dean7_file",
    "fwxAES",
    "fwxAES_decrypt_raw",
    "fwxAES_decrypt_stream",
    "fwxAES_encrypt_raw",
    "fwxAES_encrypt_stream",
    "fwxAES_live_decrypt_chunks",
    "fwxAES_live_decrypt_ffmpeg",
    "fwxAES_live_decrypt_stream",
    "fwxAES_live_encrypt_chunks",
    "fwxAES_live_encrypt_ffmpeg",
    "fwxAES_live_encrypt_stream",
    "generate_kem_keypair",
    "hash512",
    "HAS_RETIRED_MEDIA",
    "hkdf_sha256",
    "current_kem_algorithm",
    "is_supported_kem_algorithm",
    "kem_algorithm_for_public_key",
    "LiveDecryptor",
    "LiveEncryptor",
    "main",
    "n10decode",
    "n10decode_bytes",
    "n10encode",
    "n10encode_bytes",
    "normalize_unwrap",
    "normalize_wrap",
    "pb512decode",
    "pb512encode",
    "pb512file_decode_bytes",
    "pb512file_encode_bytes",
    "x25519",
    # plugin SPI (3.7.0)
    "BasefwxPlugin",
    "BasefwxPluginError",
    "NativePluginShim",
    "PLUGIN_API_VERSION",
    "PLUGIN_ID_LEN",
    "PluginErrorBadInput",
    "PluginErrorBadState",
    "PluginErrorGeneric",
    "PluginErrorNotSupported",
    "PluginErrorOutputTooSmall",
    "PluginPosition",
    "all_plugins",
    "discover_plugins",
    "load_native_plugin",
    "plugin_factory_for",
    "register_native_plugin",
    "register_plugin",
]

if RETIRED_MEDIA_ENABLED:
    from .retired import install_public_api as _install_retired_public_api

    _install_retired_public_api(globals(), __all__)
    del _install_retired_public_api
