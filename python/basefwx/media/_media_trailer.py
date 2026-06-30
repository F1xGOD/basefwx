# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.


from __future__ import annotations

from ._media_shared import basefwx


class _MediaTrailerMixin:
    @staticmethod
    def _encrypt_metadata(tags: 'dict[str, str]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'list[str]':
        encoded_args: 'list[str]' = []
        for key, value in tags.items():
            try:
                enc = basefwx.b512encode(value, password, use_master=False)
            except Exception:
                continue
            encoded_args.append(f'{key}={enc}')
        return encoded_args

    @staticmethod
    def _decrypt_metadata(tags: 'dict[str, str]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'list[str]':
        decoded_args: 'list[str]' = []
        for key, value in tags.items():
            try:
                dec = basefwx.b512decode(value, password, use_master=False)
            except Exception:
                continue
            decoded_args.append(f'{key}={dec}')
        return decoded_args

    @staticmethod
    def _append_trailer(output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', original_bytes: bytes, *, archive_key: 'basefwx.typing.Optional[bytes]'=None, key_header: bytes=b'') -> None:
        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
        if key_header:
            profile_id = basefwx._jmg_profile_from_key_header(key_header)
        archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        if archive_key is None:
            material = basefwx.MediaCipher._derive_media_material(password, security_profile=profile_id)
            archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
        archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, archive_info)
        trailer_blob = key_header + archive_blob
        basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_TRAILER_MAGIC, trailer_blob)

    @staticmethod
    def _append_trailer_stream(output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', original_path: 'basefwx.pathlib.Path', progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, *, archive_key: 'basefwx.typing.Optional[bytes]'=None, key_header: bytes=b'') -> None:
        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
        if key_header:
            profile_id = basefwx._jmg_profile_from_key_header(key_header)
        archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        if archive_key is None:
            material = basefwx.MediaCipher._derive_media_material(password, security_profile=profile_id)
            archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
        aad = archive_info
        size = original_path.stat().st_size
        blob_len = len(key_header) + basefwx.AEAD_NONCE_LEN + size + basefwx.AEAD_TAG_LEN
        if blob_len > 4294967295:
            raise ValueError('Trailer too large for 4-byte length field')
        nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
        cipher = basefwx.Cipher(basefwx.algorithms.AES(archive_key), basefwx.modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        chunk_size = 1024 * 1024
        with open(output_path, 'ab') as out_handle, open(original_path, 'rb') as src_handle:
            out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
            out_handle.write(blob_len.to_bytes(4, 'big'))
            if key_header:
                out_handle.write(key_header)
            out_handle.write(nonce)
            processed = 0
            while True:
                chunk = src_handle.read(chunk_size)
                if not chunk:
                    break
                out_handle.write(encryptor.update(chunk))
                processed += len(chunk)
                if progress_cb and size:
                    progress_cb(min(1.0, processed / size))
            encryptor.finalize()
            out_handle.write(encryptor.tag)
            out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
            out_handle.write(blob_len.to_bytes(4, 'big'))

    @staticmethod
    def _append_key_trailer(output_path: 'basefwx.pathlib.Path', key_header: bytes) -> None:
        if not key_header:
            raise ValueError('Missing JMG key header for no-archive mode')
        basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, key_header)

    @staticmethod
    def _load_base_key_from_key_trailer(path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[tuple[bytes, int]]':
        info = basefwx._extract_balanced_trailer_info(path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
        if info is None:
            return None
        blob_start, blob_len, _ = info
        with open(path, 'rb') as handle:
            handle.seek(blob_start)
            blob = handle.read(blob_len)
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is None:
            raise ValueError('Invalid JMG key trailer')
        header_len, base_key, _, _, profile_id = header
        if header_len != len(blob):
            raise ValueError('Invalid JMG key trailer payload')
        return (base_key, profile_id)

    @staticmethod
    def _load_base_key_from_key_trailer_bytes(file_bytes: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[tuple[bytes, int]]':
        trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
        if trailer is None:
            return None
        blob, _ = trailer
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is None:
            raise ValueError('Invalid JMG key trailer')
        header_len, base_key, _, _, profile_id = header
        if header_len != len(blob):
            raise ValueError('Invalid JMG key trailer payload')
        return (base_key, profile_id)

    @staticmethod
    def _decrypt_trailer(file_bytes: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[bytes]':
        trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_TRAILER_MAGIC)
        if trailer is None:
            return None
        blob, _ = trailer
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is not None:
            header_len, _, archive_key, _, profile_id = header
            archive_blob = blob[header_len:]
            archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        else:
            material = basefwx.MediaCipher._derive_media_material(password)
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
            archive_blob = blob
            archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
        return basefwx._aead_decrypt(archive_key, archive_blob, archive_info)

    @staticmethod
    def _decrypt_trailer_stream(path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output_path: 'basefwx.pathlib.Path', progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None) -> bool:
        header_seen = False
        try:
            magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
            footer_len = len(magic) + 4
            try:
                size = path.stat().st_size
            except Exception:
                return False
            if size < footer_len:
                return False
            with open(path, 'rb') as handle:
                handle.seek(size - footer_len)
                footer = handle.read(footer_len)
                if len(footer) != footer_len or footer[:len(magic)] != magic:
                    return False
                blob_len = int.from_bytes(footer[len(magic):], 'big')
                trailer_start = size - footer_len - blob_len - footer_len
                if trailer_start < 0:
                    return False
                handle.seek(trailer_start)
                header = handle.read(footer_len)
                if len(header) != footer_len or header[:len(magic)] != magic:
                    return False
                header_len = int.from_bytes(header[len(magic):], 'big')
                if header_len != blob_len:
                    return False
                blob_start = trailer_start + footer_len
                handle.seek(blob_start)
                header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
                prefix = handle.read(len(basefwx.JMG_KEY_MAGIC))
                if len(prefix) != len(basefwx.JMG_KEY_MAGIC):
                    return False
                archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
                if prefix == basefwx.JMG_KEY_MAGIC:
                    header_seen = True
                    version = handle.read(1)
                    if len(version) != 1:
                        return False
                    if version[0] not in {basefwx.JMG_KEY_VERSION_LEGACY, basefwx.JMG_KEY_VERSION}:
                        raise ValueError('Unsupported JMG key header version')
                    payload_len_bytes = handle.read(4)
                    if len(payload_len_bytes) != 4:
                        return False
                    payload_len = int.from_bytes(payload_len_bytes, 'big')
                    header_len = header_min + payload_len
                    payload = handle.read(payload_len)
                    if len(payload) != payload_len:
                        return False
                    if version[0] == basefwx.JMG_KEY_VERSION_LEGACY:
                        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
                        key_payload = payload
                    else:
                        if not payload:
                            return False
                        profile_id = basefwx._jmg_security_profile_id(payload[0])
                        key_payload = payload[1:]
                    user_blob, master_blob = basefwx._unpack_length_prefixed(key_payload, 2)
                    mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, True, mask_info=basefwx.JMG_MASK_INFO, aad=basefwx.JMG_MASK_AAD)
                    archive_key = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_archive_info_for_profile(profile_id), length=32)
                    archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
                    nonce = handle.read(basefwx.AEAD_NONCE_LEN)
                    if len(nonce) != basefwx.AEAD_NONCE_LEN:
                        return False
                    cipher_body_len = blob_len - header_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                else:
                    archive_key = basefwx._hkdf_sha256(basefwx.MediaCipher._derive_media_material(password), info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
                    nonce = prefix + handle.read(basefwx.AEAD_NONCE_LEN - len(prefix))
                    if len(nonce) != basefwx.AEAD_NONCE_LEN:
                        return False
                    cipher_body_len = blob_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                if cipher_body_len < 0:
                    return False
                cipher = basefwx.Cipher(basefwx.algorithms.AES(archive_key), basefwx.modes.GCM(nonce))
                decryptor = cipher.decryptor()
                decryptor.authenticate_additional_data(archive_info)
                chunk_size = 1024 * 1024
                with open(output_path, 'wb') as out_handle:
                    remaining = cipher_body_len
                    processed = 0
                    while remaining > 0:
                        chunk = handle.read(min(chunk_size, remaining))
                        if not chunk:
                            return False
                        out_handle.write(decryptor.update(chunk))
                        remaining -= len(chunk)
                        processed += len(chunk)
                        if progress_cb and cipher_body_len:
                            progress_cb(min(1.0, processed / cipher_body_len))
                    tag = handle.read(basefwx.AEAD_TAG_LEN)
                    if len(tag) != basefwx.AEAD_TAG_LEN:
                        return False
                    decryptor.finalize_with_tag(tag)
            return True
        except Exception:
            if header_seen:
                raise
            return False

    @staticmethod
    def _run_ffmpeg(cmd: 'list[str]', fallback_cmd: 'basefwx.typing.Optional[list[str]]'=None) -> None:

        def _run_once(run_cmd: 'list[str]') -> 'tuple[int, str, str]':
            proc = basefwx.subprocess.Popen([str(part) for part in run_cmd], stdout=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate()
                return (proc.returncode, stdout or '', stderr or '')
            except KeyboardInterrupt:
                with basefwx.contextlib.suppress(Exception):
                    proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    proc.wait(timeout=1.5)
                with basefwx.contextlib.suppress(Exception):
                    if proc.poll() is None:
                        proc.kill()
                with basefwx.contextlib.suppress(Exception):
                    proc.wait(timeout=1.0)
                raise
        code, _stdout, stderr = _run_once(cmd)
        if code != 0:
            if fallback_cmd and (not basefwx.MediaCipher._hwaccel_strict()):
                retry_code, _retry_stdout, retry_stderr = _run_once(fallback_cmd)
                if retry_code != 0:
                    raise RuntimeError(retry_stderr.strip() or 'ffmpeg failed')
                return
            raise RuntimeError(stderr.strip() or 'ffmpeg failed')
