# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from ..legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _jmg_security_profile_id(security_profile: 'basefwx.typing.Union[str, int, None]') -> int:
    if security_profile is None:
        return basefwx.JMG_SECURITY_PROFILE_DEFAULT
    if isinstance(security_profile, str):
        profile = basefwx.JMG_SECURITY_PROFILE_NAMES.get(security_profile.strip().lower(), None)
        if profile is None:
            raise ValueError(f'Unsupported JMG security profile: {security_profile}')
        return profile
    profile = int(security_profile)
    if profile not in basefwx.JMG_SECURITY_PROFILE_LABELS:
        raise ValueError(f'Unsupported JMG security profile id: {profile}')
    return profile


def _jmg_video_enabled() -> bool:
    raw = basefwx.os.getenv(basefwx.JMG_VIDEO_ENABLE_ENV, '0').strip().lower()
    return raw in {'1', 'true', 'yes', 'on'}


def _jmg_stream_info_for_profile(profile_id: int) -> bytes:
    if profile_id == basefwx.JMG_SECURITY_PROFILE_MAX:
        return basefwx.IMAGECIPHER_STREAM_INFO + b'.max'
    return basefwx.IMAGECIPHER_STREAM_INFO


def _jmg_archive_info_for_profile(profile_id: int) -> bytes:
    if profile_id == basefwx.JMG_SECURITY_PROFILE_MAX:
        return basefwx.IMAGECIPHER_ARCHIVE_INFO + b'.max'
    return basefwx.IMAGECIPHER_ARCHIVE_INFO


def _jmg_build_key_header(user_blob: bytes, master_blob: bytes, *, security_profile: 'basefwx.typing.Union[str, int, None]'=None) -> bytes:
    profile_id = basefwx._jmg_security_profile_id(security_profile)
    payload = bytes([profile_id]) + basefwx._pack_length_prefixed(user_blob, master_blob)
    return basefwx.JMG_KEY_MAGIC + bytes([basefwx.JMG_KEY_VERSION]) + len(payload).to_bytes(4, 'big') + payload


def _jmg_profile_from_key_header(blob: bytes) -> int:
    header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
    if len(blob) < header_min or not blob.startswith(basefwx.JMG_KEY_MAGIC):
        raise ValueError('Invalid JMG key header')
    version = blob[len(basefwx.JMG_KEY_MAGIC)]
    payload_len = int.from_bytes(blob[len(basefwx.JMG_KEY_MAGIC) + 1:len(basefwx.JMG_KEY_MAGIC) + 5], 'big')
    header_len = header_min + payload_len
    if len(blob) != header_len:
        raise ValueError('Truncated JMG key header')
    if version == basefwx.JMG_KEY_VERSION_LEGACY:
        return basefwx.JMG_SECURITY_PROFILE_LEGACY
    if version != basefwx.JMG_KEY_VERSION:
        raise ValueError('Unsupported JMG key header version')
    payload = blob[header_min:header_len]
    if not payload:
        raise ValueError('Truncated JMG key header profile')
    return basefwx._jmg_security_profile_id(payload[0])


def _jmg_parse_key_header(blob: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool) -> 'basefwx.typing.Optional[tuple[int, bytes, bytes, bytes, int]]':
    header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
    if len(blob) < header_min or not blob.startswith(basefwx.JMG_KEY_MAGIC):
        return None
    version = blob[len(basefwx.JMG_KEY_MAGIC)]
    if version not in {basefwx.JMG_KEY_VERSION_LEGACY, basefwx.JMG_KEY_VERSION}:
        raise ValueError('Unsupported JMG key header version')
    payload_len = int.from_bytes(blob[len(basefwx.JMG_KEY_MAGIC) + 1:len(basefwx.JMG_KEY_MAGIC) + 5], 'big')
    header_len = header_min + payload_len
    if len(blob) < header_len:
        raise ValueError('Truncated JMG key header')
    payload = blob[header_min:header_len]
    if version == basefwx.JMG_KEY_VERSION_LEGACY:
        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
        key_payload = payload
    else:
        if not payload:
            raise ValueError('Truncated JMG key header profile')
        profile_id = basefwx._jmg_security_profile_id(payload[0])
        key_payload = payload[1:]
    user_blob, master_blob = basefwx._unpack_length_prefixed(key_payload, 2)
    mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, use_master, mask_info=basefwx.JMG_MASK_INFO, aad=basefwx.JMG_MASK_AAD)
    material = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_stream_info_for_profile(profile_id), length=64)
    base_key = material[:32]
    archive_key = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_archive_info_for_profile(profile_id), length=32)
    return (header_len, base_key, archive_key, material, profile_id)


def _jmg_prepare_keys(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool=True, *, security_profile: 'basefwx.typing.Union[str, int, None]'=None) -> 'tuple[bytes, bytes, bytes, bytes]':
    profile_id = basefwx._jmg_security_profile_id(security_profile)
    mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(password, use_master, mask_info=basefwx.JMG_MASK_INFO, require_password=False, aad=basefwx.JMG_MASK_AAD)
    header = basefwx._jmg_build_key_header(user_blob, master_blob, security_profile=profile_id)
    material = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_stream_info_for_profile(profile_id), length=64)
    base_key = material[:32]
    archive_key = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_archive_info_for_profile(profile_id), length=32)
    return (base_key, archive_key, material, header)


def _append_balanced_trailer(output_path: 'basefwx.pathlib.Path', magic: bytes, payload: bytes) -> None:
    if not payload:
        return
    if len(payload) > 4294967295:
        raise ValueError('Trailer payload too large')
    with open(output_path, 'ab') as handle:
        handle.write(magic)
        handle.write(len(payload).to_bytes(4, 'big'))
        handle.write(payload)
        handle.write(magic)
        handle.write(len(payload).to_bytes(4, 'big'))


def _extract_balanced_trailer_from_bytes(file_bytes: bytes, magic: bytes) -> 'basefwx.typing.Optional[tuple[bytes, bytes]]':
    footer_len = len(magic) + 4
    if len(file_bytes) < footer_len:
        return None
    footer_idx = len(file_bytes) - footer_len
    if file_bytes[footer_idx:footer_idx + len(magic)] == magic:
        length = int.from_bytes(file_bytes[footer_idx + len(magic):footer_idx + footer_len], 'big')
        trailer_start = len(file_bytes) - footer_len - length - footer_len
        if trailer_start >= 0:
            header = file_bytes[trailer_start:trailer_start + footer_len]
            if header[:len(magic)] == magic and int.from_bytes(header[len(magic):], 'big') == length:
                blob_start = trailer_start + footer_len
                blob_end = blob_start + length
                return (file_bytes[blob_start:blob_end], file_bytes[:trailer_start])
    marker_idx = file_bytes.rfind(magic)
    if marker_idx < 0 or marker_idx + len(magic) + 4 > len(file_bytes):
        return None
    length = int.from_bytes(file_bytes[marker_idx + len(magic):marker_idx + len(magic) + 4], 'big')
    blob_start = marker_idx + len(magic) + 4
    blob_end = blob_start + length
    if blob_end != len(file_bytes):
        return None
    return (file_bytes[blob_start:blob_end], file_bytes[:marker_idx])


def _extract_balanced_trailer_info(path: 'basefwx.pathlib.Path', magic: bytes) -> 'basefwx.typing.Optional[tuple[int, int, int]]':
    footer_len = len(magic) + 4
    try:
        size = path.stat().st_size
    except Exception:
        return None
    if size < footer_len:
        return None
    with open(path, 'rb') as handle:
        handle.seek(size - footer_len)
        footer = handle.read(footer_len)
        if len(footer) != footer_len or footer[:len(magic)] != magic:
            return None
        blob_len = int.from_bytes(footer[len(magic):], 'big')
        trailer_start = size - footer_len - blob_len - footer_len
        if trailer_start < 0:
            return None
        handle.seek(trailer_start)
        header = handle.read(footer_len)
        if len(header) != footer_len or header[:len(magic)] != magic:
            return None
        if int.from_bytes(header[len(magic):], 'big') != blob_len:
            return None
        blob_start = trailer_start + footer_len
        return (blob_start, blob_len, trailer_start)
