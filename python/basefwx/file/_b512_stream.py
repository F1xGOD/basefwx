# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

from typing import BinaryIO, NamedTuple

from ._b512_common import basefwx
from ._b512_obfuscation import (
    _estimate_aead_blob_size,
    _resolve_payload_length_from_file_size,
)


def _remove_if_exists(path: str) -> None:
    try:
        basefwx.os.remove(path)
    except FileNotFoundError:
        return


def _b512_encode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, total_files: int=1, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, pack_flag: str='', output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, keep_input: bool=False) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx._ensure_size_limit(path)
    display_path = display_path or path
    output_path = output_path or path.with_suffix('.fwx')
    input_size = path.stat().st_size
    approx_b64_len = (input_size + 2) // 3 * 4
    force_stream = approx_b64_len > basefwx.HKDF_MAX_LEN
    size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.05, 'prepare', display_path)
    master_selection = basefwx._select_master_key(
        use_master and (not strip_metadata), master_pubkey
    )
    use_master_effective = master_selection.used_master
    heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
    heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
    obfuscate_payload = input_size <= basefwx.STREAM_THRESHOLD
    if basefwx.ENABLE_B512_AEAD and (input_size >= basefwx.STREAM_THRESHOLD or force_stream):
        return basefwx._b512_encode_path_stream(path, password, reporter, file_index, total_files, strip_metadata, use_master, master_pubkey, pack_flag=pack_flag, output_path=output_path, display_path=display_path, input_size=input_size, keep_input=keep_input)
    if force_stream:
        raise ValueError('b512file payload too large for non-AEAD mode; enable AEAD or use file streaming')
    data = path.read_bytes()
    if reporter:
        reporter.update(file_index, 0.25, 'base64', display_path)
    b64_payload = basefwx.base64.b64encode(data).decode('utf-8')
    ext_token = basefwx.b512encode(path.suffix or '', password, use_master=use_master_effective)
    data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
    if reporter:
        reporter.update(file_index, 0.65, 'b256', display_path)
    kdf_used = basefwx._resolve_kdf_label(None)
    use_aead = basefwx.ENABLE_B512_AEAD
    metadata_blob = basefwx._build_metadata('FWX512R', strip_metadata, use_master_effective, master_kem=master_selection.kem_label, aead='AESGCM' if use_aead else 'NONE', kdf=kdf_used, pack=pack_flag or None)
    body = f'{ext_token}{basefwx.FWX_DELIM}{data_token}'
    payload = f'{metadata_blob}{basefwx.META_DELIM}{body}' if metadata_blob else body
    payload_bytes = payload.encode('utf-8')
    mask_key = None
    aead_key = None
    ct_blob = None
    user_blob: bytes = b''
    master_blob: bytes = b''
    if use_aead:
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(password, use_master_effective, mask_info=basefwx.B512_FILE_MASK_INFO, require_password=not use_master_effective, aad=b'b512file', master_selection=master_selection)
        aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        ct_blob = basefwx._aead_encrypt(aead_key, payload_bytes, basefwx.B512_AEAD_INFO)
        output_bytes = basefwx._pack_length_prefixed(user_blob, master_blob, ct_blob)
    else:
        output_bytes = payload_bytes
    with open(output_path, 'wb') as handle:
        handle.write(output_bytes)
    approx_size = len(output_bytes)
    size_hint = (input_size, approx_size)
    if strip_metadata:
        basefwx._apply_strip_attributes(output_path)
    basefwx._remove_input(path, keep_input, output_path)
    if reporter:
        reporter.update(file_index, 1.0, 'done', output_path, size_hint=size_hint)
        reporter.finalize_file(file_index, output_path, size_hint=size_hint)
    basefwx._del('mask_key')
    basefwx._del('aead_key')
    basefwx._del('ct_blob')
    basefwx._del('payload_bytes')
    basefwx._del('output_bytes')
    basefwx._del('user_blob')
    basefwx._del('master_blob')
    return (output_path, approx_size)

def _b512_encode_path_stream(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, total_files: int=1, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, pack_flag: str='', output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, *, input_size: 'basefwx.typing.Optional[int]'=None, keep_input: bool=False) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx._ensure_size_limit(path)
    if strip_metadata:
        raise ValueError(
            'Streaming b512 encode requires metadata for format dispatch'
        )
    display_path = display_path or path
    output_path = output_path or path.with_suffix('.fwx')
    input_size = input_size if input_size is not None else path.stat().st_size
    if reporter:
        reporter.update(file_index, 0.05, 'prepare', display_path)
    if not basefwx.ENABLE_B512_AEAD:
        raise RuntimeError('Streaming b512 encode requires AEAD mode')
    chunk_size = basefwx.STREAM_CHUNK_SIZE
    master_selection = basefwx._select_master_key(
        use_master and (not strip_metadata), master_pubkey
    )
    use_master_effective = master_selection.used_master
    stream_salt = basefwx._StreamObfuscator.generate_salt()
    ext_bytes = (path.suffix or '').encode('utf-8')
    fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(input_size)
    obf_mode = 'fast' if fast_obf else 'yes'
    metadata_blob = basefwx._build_metadata('FWX512R', strip_metadata, use_master_effective, master_kem=master_selection.kem_label, mode='STREAM', obfuscation=obf_mode, pack=pack_flag or None)
    metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
    metadata_len = len(metadata_bytes)
    prefix_bytes = metadata_bytes + basefwx.META_DELIM.encode('utf-8') if metadata_blob else b''
    stream_header = bytearray()
    stream_header.extend(basefwx.STREAM_MAGIC)
    stream_header.extend(chunk_size.to_bytes(4, 'big'))
    stream_header.extend(input_size.to_bytes(8, 'big'))
    stream_header.extend(stream_salt)
    stream_header.extend(len(ext_bytes).to_bytes(2, 'big'))
    stream_header.extend(ext_bytes)
    stream_header_bytes = bytes(stream_header)
    plaintext_len = len(prefix_bytes) + len(stream_header_bytes) + input_size
    mask_key = None
    aead_key = None
    try:
        mask_key_bytes, user_blob, master_blob, _ = basefwx._prepare_mask_key(password, use_master_effective, mask_info=basefwx.B512_FILE_MASK_INFO, require_password=not use_master_effective, aad=b'b512file', master_selection=master_selection)
        mask_key = bytearray(mask_key_bytes)
        mask_key_bytes = None
        aead_key = bytearray(
            basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        )
    except BaseException:
        mask_key = basefwx._clear_secret(mask_key)
        aead_key = basefwx._clear_secret(aead_key)
        raise
    len_user = len(user_blob)
    len_master = len(master_blob)
    estimated_payload_len = 4 + metadata_len + basefwx.AEAD_NONCE_LEN + plaintext_len + basefwx.AEAD_TAG_LEN
    estimated_total_len = 4 + len_user + 4 + len_master + 4 + estimated_payload_len
    estimated_hint = (input_size, estimated_total_len)
    if reporter:
        reporter.update(file_index, 0.12, 'stream-setup', display_path, size_hint=estimated_hint)
    temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-b512-stream-', dir=str(output_path.parent))
    cleanup_paths: 'basefwx.typing.List[str]' = []
    processed_plain = 0

    def _seal_progress(done_plain: int) -> None:
        if not reporter:
            return
        fraction = 0.55 + 0.44 * (done_plain / plaintext_len if plaintext_len else 0.0)
        reporter.update(file_index, fraction, 'seal', display_path, size_hint=estimated_hint)

    def _obf_progress(done_bytes: int, total_bytes: int) -> None:
        if not reporter:
            return
        fraction = 0.2 + 0.7 * (done_bytes / total_bytes if total_bytes else 0.0)
        reporter.update(file_index, fraction, 'pb512-stream', display_path, size_hint=estimated_hint)
    result: 'basefwx.typing.Optional[basefwx.typing.Tuple[basefwx.pathlib.Path, int]]' = None
    try:
        payload_len = estimated_payload_len
        with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as final_tmp:
            cleanup_paths.append(final_tmp.name)
            final_tmp.write(len_user.to_bytes(4, 'big'))
            final_tmp.write(user_blob)
            final_tmp.write(len_master.to_bytes(4, 'big'))
            final_tmp.write(master_blob)
            final_tmp.write(payload_len.to_bytes(4, 'big'))
            final_tmp.write(metadata_len.to_bytes(4, 'big'))
            if metadata_bytes:
                final_tmp.write(metadata_bytes)
            nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
            final_tmp.write(nonce)
            encryptor = basefwx.Cipher(basefwx.algorithms.AES(aead_key), basefwx.modes.GCM(nonce)).encryptor()
            if metadata_bytes:
                encryptor.authenticate_additional_data(metadata_bytes)

            def _write_plain(data: bytes) -> None:
                nonlocal processed_plain
                if not data:
                    return
                ct = encryptor.update(data)
                if ct:
                    final_tmp.write(ct)
                processed_plain += len(data)
                _seal_progress(processed_plain)
            if prefix_bytes:
                _write_plain(prefix_bytes)
            _write_plain(stream_header_bytes)
            basefwx._StreamObfuscator.encode_file(path, None, password, stream_salt, chunk_size=chunk_size, fast=fast_obf, forward_chunk=_write_plain, progress_cb=_obf_progress)
            tail = encryptor.finalize()
            if tail:
                final_tmp.write(tail)
            final_tmp.write(encryptor.tag)
            final_tmp.flush()
            final_tmp_path = final_tmp.name
        actual_size = basefwx.os.path.getsize(final_tmp_path)
        actual_hint = (input_size, actual_size)
        basefwx.os.replace(final_tmp_path, output_path)
        cleanup_paths.remove(final_tmp_path)
        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
        basefwx._remove_input(path, keep_input, output_path)
        if reporter:
            reporter.update(file_index, 1.0, 'done', output_path, size_hint=actual_hint)
            reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
        else:
            human = basefwx._human_readable_size(actual_size)
            if not basefwx._SILENT_MODE:
                print(f'{output_path.name}: approx output size {human}')
        result = (output_path, actual_size)
    finally:
        mask_key = basefwx._clear_secret(mask_key)
        aead_key = basefwx._clear_secret(aead_key)
        for temp_path in cleanup_paths:
            _remove_if_exists(temp_path)
        temp_dir.cleanup()
    if result is None:
        raise RuntimeError('Streaming b512 encode failed')
    return result


def _preview_b512_length_prefixed_container(
    path: 'basefwx.pathlib.Path',
    input_size: int,
) -> 'basefwx.typing.Optional[basefwx.typing.Tuple[str, basefwx.typing.Dict[str, basefwx.typing.Any]]]':
    """Preview an exact three-part container without reading payloads into memory."""
    if input_size < 12:
        return None
    with open(path, 'rb') as preview:
        len_user_bytes = preview.read(4)
        if len(len_user_bytes) != 4:
            return None
        len_user = int.from_bytes(len_user_bytes, 'big')
        user_end = preview.tell() + len_user
        if user_end > input_size - 8:
            return None
        preview.seek(user_end)

        len_master_bytes = preview.read(4)
        if len(len_master_bytes) != 4:
            return None
        len_master = int.from_bytes(len_master_bytes, 'big')
        master_end = preview.tell() + len_master
        if master_end > input_size - 4:
            return None
        preview.seek(master_end)

        len_payload_bytes = preview.read(4)
        if len(len_payload_bytes) != 4:
            return None
        len_payload = int.from_bytes(len_payload_bytes, 'big')
        payload_start = preview.tell()
        if payload_start + len_payload != input_size:
            return None

        # From this point the file is structurally an exact length-prefixed
        # container. Framing policy failures must not become legacy text.
        if len_user > basefwx.LENGTH_PREFIXED_MAX:
            raise ValueError('Ciphertext user key transport length invalid')
        if len_master > basefwx.LENGTH_PREFIXED_MAX:
            raise ValueError('Ciphertext master key transport length invalid')
        if len_user + len_master > basefwx.LENGTH_PREFIXED_MAX:
            raise ValueError(
                'Ciphertext key transport header exceeds 64 MiB cap'
            )
        if len_payload < 4:
            return '', {}

        metadata_len_bytes = preview.read(4)
        if len(metadata_len_bytes) != 4:
            return '', {}
        metadata_len = int.from_bytes(metadata_len_bytes, 'big')
        if (
            metadata_len > basefwx.METADATA_MAX
            or metadata_len > len_payload - 4
        ):
            return '', {}
        if (
            len_user + len_master + metadata_len
            > basefwx.LENGTH_PREFIXED_MAX
        ):
            raise ValueError('Ciphertext header exceeds 64 MiB cap')
        metadata_bytes = preview.read(metadata_len)
        if len(metadata_bytes) != metadata_len:
            return '', {}
        try:
            metadata_blob = (
                metadata_bytes.decode('utf-8') if metadata_bytes else ''
            )
        except UnicodeDecodeError:
            return '', {}
        metadata = basefwx._decode_metadata(metadata_blob)
        if not isinstance(metadata, dict):
            return '', {}
        if (metadata.get('ENC-MODE') or '').lower() != 'stream':
            return '', {}
        return metadata_blob, metadata


def _b512_decode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, total_files: int=1, strip_metadata: bool=False, use_master: bool=True) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx.os.chmod(path, 384)
    input_size = path.stat().st_size
    size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.1, 'read', path)
    metadata_blob_preview = ''
    meta_preview: 'basefwx.typing.Dict[str, basefwx.typing.Any]' = {}
    recognized_binary = False
    if basefwx.ENABLE_B512_AEAD:
        preview_result = _preview_b512_length_prefixed_container(
            path, input_size
        )
        if preview_result is not None:
            metadata_blob_preview, meta_preview = preview_result
            recognized_binary = True
    if (meta_preview.get('ENC-MODE') or '').lower() == 'stream':
        return basefwx._b512_decode_path_stream(path, password, reporter, file_index, strip_metadata, use_master, meta_preview, metadata_blob_preview, input_size=input_size)
    if input_size > basefwx.LENGTH_PREFIXED_MAX:
        raise ValueError(
            'Non-stream ciphertext exceeds 64 MiB length-prefixed cap'
        )
    raw_bytes = path.read_bytes()
    user_blob: bytes = b''
    master_blob: bytes = b''
    ct_blob: bytes = b''
    use_master_effective = use_master and (not strip_metadata)
    binary_mode = False
    try:
        user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(
            raw_bytes, 3
        )
        binary_mode = True
    except ValueError:
        if recognized_binary:
            raise
        binary_mode = False
    if binary_mode:
        mask_key = None
        aead_key = None
        payload_bytes = None
        try:
            mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, use_master_effective, mask_info=basefwx.B512_FILE_MASK_INFO, aad=b'b512file', legacy_user_aad=basefwx.B512_AEAD_INFO)
            aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
            payload_bytes = basefwx._aead_decrypt(aead_key, ct_blob, basefwx.B512_AEAD_INFO)
            content = payload_bytes.decode('utf-8')
        finally:
            basefwx._del('mask_key')
            basefwx._del('aead_key')
            basefwx._del('payload_bytes')
    else:
        content = raw_bytes.decode('utf-8')
    basefwx._del('user_blob')
    basefwx._del('master_blob')
    basefwx._del('ct_blob')
    metadata_blob, content_core = basefwx._split_metadata(content)
    meta = basefwx._decode_metadata(metadata_blob)
    master_hint = meta.get('ENC-MASTER') if meta else None
    if master_hint == 'no':
        use_master_effective = False
    basefwx._warn_on_metadata(meta, 'FWX512R')
    header, payload = basefwx._split_with_delims(content_core, (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM), 'FWX container')
    if reporter:
        reporter.update(file_index, 0.35, 'b256', path)
    ext = basefwx.b512decode(header, password, use_master=use_master_effective)
    data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)
    if reporter:
        reporter.update(file_index, 0.65, 'base64', path)
    decoded_bytes = basefwx.base64.b64decode(data_b64)
    pack_flag = basefwx._pack_flag_from_meta(meta, ext)
    target = path.with_suffix('')
    if ext:
        target = target.with_suffix(ext)
    with open(target, 'wb') as handle:
        handle.write(decoded_bytes)
    basefwx.os.remove(path)
    if pack_flag:
        target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
    elif strip_metadata:
        basefwx._apply_strip_attributes(target)
    output_len = len(decoded_bytes)
    size_hint = (input_size, output_len)
    if reporter:
        reporter.update(file_index, 1.0, 'done', target, size_hint=size_hint)
        reporter.finalize_file(file_index, target, size_hint=size_hint)
    basefwx._del('content')
    basefwx._del('decoded_bytes')
    return (target, output_len)


class _B512StreamEnvelope(NamedTuple):
    user_blob: bytes
    master_blob: bytes
    metadata_bytes: bytes
    metadata: dict
    nonce: bytes
    tag: bytes
    body_length: int


def _read_required(handle: BinaryIO, length: int, message: str) -> bytes:
    data = handle.read(length)
    if len(data) != length:
        raise ValueError(message)
    return data


def _read_b512_stream_envelope(
    handle: BinaryIO,
    path: 'basefwx.pathlib.Path',
    input_size: int,
    metadata_preview: dict,
    metadata_blob_preview: str,
) -> _B512StreamEnvelope:
    len_user = int.from_bytes(
        _read_required(handle, 4, 'Ciphertext payload truncated'),
        'big',
    )
    if len_user > basefwx.LENGTH_PREFIXED_MAX or len_user > input_size - handle.tell():
        raise ValueError('Ciphertext user key transport length invalid')
    user_blob = _read_required(handle, len_user, 'Ciphertext payload truncated')

    len_master = int.from_bytes(
        _read_required(handle, 4, 'Ciphertext payload truncated'),
        'big',
    )
    if len_master > basefwx.LENGTH_PREFIXED_MAX or len_master > input_size - handle.tell():
        raise ValueError('Ciphertext master key transport length invalid')
    if len_user + len_master > basefwx.LENGTH_PREFIXED_MAX:
        raise ValueError('Ciphertext key transport header exceeds 64 MiB cap')
    master_blob = _read_required(handle, len_master, 'Ciphertext payload truncated')

    len_payload = int.from_bytes(
        _read_required(handle, 4, 'Ciphertext payload truncated'),
        'big',
    )
    len_payload = basefwx._resolve_payload_length_from_file_size(
        path,
        len_user,
        len_master,
        len_payload,
    )
    minimum_payload = 4 + basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN
    if len_payload < minimum_payload:
        raise ValueError('Ciphertext payload truncated')

    metadata_len = int.from_bytes(
        _read_required(handle, 4, 'Ciphertext payload truncated'),
        'big',
    )
    if (
        metadata_len > basefwx.METADATA_MAX
        or metadata_len > len_payload - 4
        or metadata_len > input_size - handle.tell()
    ):
        raise ValueError('Ciphertext metadata length invalid')
    if len_user + len_master + metadata_len > basefwx.LENGTH_PREFIXED_MAX:
        raise ValueError('Ciphertext header exceeds 64 MiB cap')
    metadata_bytes = _read_required(
        handle,
        metadata_len,
        'Ciphertext payload truncated',
    )

    metadata_blob = metadata_blob_preview
    metadata = metadata_preview
    if metadata_blob:
        if metadata_bytes != metadata_blob.encode('utf-8'):
            raise ValueError('Metadata integrity mismatch detected')
    else:
        try:
            metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ''
        except UnicodeDecodeError:
            metadata_blob = ''
        metadata = basefwx._decode_metadata(metadata_blob)

    nonce = _read_required(
        handle,
        basefwx.AEAD_NONCE_LEN,
        'Ciphertext payload truncated',
    )
    body_length = (
        len_payload
        - 4
        - metadata_len
        - basefwx.AEAD_NONCE_LEN
        - basefwx.AEAD_TAG_LEN
    )
    if body_length < 0:
        raise ValueError('Ciphertext payload truncated')
    body_offset = handle.tell()
    handle.seek(body_length, basefwx.os.SEEK_CUR)
    tag = _read_required(
        handle,
        basefwx.AEAD_TAG_LEN,
        'Ciphertext payload truncated',
    )
    handle.seek(body_offset)
    return _B512StreamEnvelope(
        user_blob,
        master_blob,
        metadata_bytes,
        metadata,
        nonce,
        tag,
        body_length,
    )


def _decrypt_b512_stream_body(
    handle: BinaryIO,
    envelope: _B512StreamEnvelope,
    password: str,
    use_master: bool,
    temp_dir: str,
    cleanup_paths: 'basefwx.typing.List[str]',
    reporter: 'basefwx._ProgressReporter',
    file_index: int,
    path: 'basefwx.pathlib.Path',
) -> str:
    mask_key = None
    aead_key = None
    try:
        mask_key_bytes = basefwx._recover_mask_key_from_blob(
            envelope.user_blob,
            envelope.master_blob,
            password,
            use_master,
            mask_info=basefwx.B512_FILE_MASK_INFO,
            aad=b'b512file',
            legacy_user_aad=basefwx.B512_AEAD_INFO,
        )
        mask_key = bytearray(mask_key_bytes)
        mask_key_bytes = None
        aead_key = bytearray(
            basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        )
        decryptor = basefwx.Cipher(
            basefwx.algorithms.AES(aead_key),
            basefwx.modes.GCM(envelope.nonce, envelope.tag),
        ).decryptor()
        if envelope.metadata_bytes:
            decryptor.authenticate_additional_data(envelope.metadata_bytes)
        if reporter:
            reporter.update(file_index, 0.35, 'seal', path)
        with basefwx.tempfile.NamedTemporaryFile(
            'w+b',
            dir=temp_dir,
            delete=False,
        ) as plain_tmp:
            cleanup_paths.append(plain_tmp.name)
            remaining = envelope.body_length
            processed = 0
            while remaining > 0:
                take = min(basefwx.STREAM_CHUNK_SIZE, remaining)
                chunk = _read_required(handle, take, 'Ciphertext truncated')
                plain_chunk = decryptor.update(chunk)
                if plain_chunk:
                    plain_tmp.write(plain_chunk)
                remaining -= take
                processed += take
                if reporter:
                    fraction = 0.35 + 0.25 * (
                        processed / envelope.body_length
                        if envelope.body_length
                        else 1.0
                    )
                    reporter.update(file_index, fraction, 'seal', path)
            final_chunk = decryptor.finalize()
            if final_chunk:
                plain_tmp.write(final_chunk)
            return plain_tmp.name
    finally:
        mask_key = basefwx._clear_secret(mask_key)
        aead_key = basefwx._clear_secret(aead_key)


def _restore_b512_plaintext_stream(
    plaintext_path: str,
    envelope: _B512StreamEnvelope,
    password: str,
    use_master: bool,
    temp_dir: str,
    cleanup_paths: 'basefwx.typing.List[str]',
    reporter: 'basefwx._ProgressReporter',
    file_index: int,
    path: 'basefwx.pathlib.Path',
) -> 'tuple[str, int, bytes]':
    with open(plaintext_path, 'rb') as plain_handle:
        if envelope.metadata_bytes:
            expected_prefix = envelope.metadata_bytes
            prefix = _read_required(
                plain_handle,
                len(expected_prefix),
                'Metadata integrity mismatch detected',
            )
            if prefix != expected_prefix:
                raise ValueError('Metadata integrity mismatch detected')
            delimiter = _read_required(
                plain_handle,
                len(basefwx.META_DELIM.encode('utf-8')),
                'Malformed streaming payload: missing metadata delimiter',
            )
            if delimiter != basefwx.META_DELIM.encode('utf-8'):
                raise ValueError('Malformed streaming payload: missing metadata delimiter')
        stream_magic = _read_required(
            plain_handle,
            len(basefwx.STREAM_MAGIC),
            'Malformed streaming payload: magic mismatch',
        )
        if stream_magic != basefwx.STREAM_MAGIC:
            raise ValueError('Malformed streaming payload: magic mismatch')
        chunk_size_value = int.from_bytes(
            _read_required(
                plain_handle,
                4,
                'Malformed streaming payload: missing chunk size',
            ),
            'big',
        )
        if chunk_size_value <= 0 or chunk_size_value > 16 << 20:
            chunk_size_value = basefwx.STREAM_CHUNK_SIZE
        original_size = int.from_bytes(
            _read_required(
                plain_handle,
                8,
                'Malformed streaming payload: missing original size',
            ),
            'big',
        )
        stream_salt = _read_required(
            plain_handle,
            basefwx._StreamObfuscator._SALT_LEN,
            'Malformed streaming payload: missing salt',
        )
        ext_len = int.from_bytes(
            _read_required(
                plain_handle,
                2,
                'Malformed streaming payload: missing extension length',
            ),
            'big',
        )
        ext_bytes = _read_required(
            plain_handle,
            ext_len,
            'Malformed streaming payload: truncated extension',
        )
        if not password and not use_master:
            raise ValueError('Password required for streaming b512 decode')
        fast_obf = (envelope.metadata.get('ENC-OBF') or 'yes').lower() == 'fast'
        decoder = basefwx._StreamObfuscator.for_password(
            password,
            stream_salt,
            fast=fast_obf,
        )
        with basefwx.tempfile.NamedTemporaryFile(
            'w+b',
            dir=temp_dir,
            delete=False,
        ) as clear_tmp:
            cleanup_paths.append(clear_tmp.name)
            processed = 0
            while processed < original_size:
                to_read = min(chunk_size_value, original_size - processed)
                chunk = _read_required(
                    plain_handle,
                    to_read,
                    'Streaming payload truncated',
                )
                plain_chunk = decoder.decode_chunk(chunk)
                clear_tmp.write(plain_chunk)
                processed += len(plain_chunk)
                if reporter:
                    fraction = 0.7 + 0.2 * (
                        processed / original_size if original_size else 1.0
                    )
                    reporter.update(file_index, fraction, 'deobfuscate', path)
            if plain_handle.read(1):
                raise ValueError(
                    'Streaming payload contained unexpected trailing data'
                )
            return clear_tmp.name, original_size, ext_bytes


def _b512_decode_path_stream(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True, meta_preview: 'basefwx.typing.Optional[basefwx.typing.Dict[str, basefwx.typing.Any]]'=None, metadata_blob_preview: str='', *, input_size: 'basefwx.typing.Optional[int]'=None) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    if not basefwx.ENABLE_B512_AEAD:
        raise RuntimeError('Streaming b512 decode requires AEAD mode')
    basefwx._ensure_existing_file(path)
    basefwx.os.chmod(path, 0o600)
    input_size = input_size if input_size is not None else path.stat().st_size
    metadata_preview = meta_preview or {}
    use_master_effective = use_master and not strip_metadata
    if metadata_preview.get('ENC-MASTER') == 'no':
        use_master_effective = False
    temp_dir = basefwx.tempfile.TemporaryDirectory(
        prefix='basefwx-b512-dec-',
        dir=str(path.parent),
    )
    cleanup_paths: 'basefwx.typing.List[str]' = []
    try:
        with open(path, 'rb') as handle:
            envelope = _read_b512_stream_envelope(
                handle,
                path,
                input_size,
                metadata_preview,
                metadata_blob_preview or '',
            )
            plaintext_path = _decrypt_b512_stream_body(
                handle,
                envelope,
                password,
                use_master_effective,
                temp_dir.name,
                cleanup_paths,
                reporter,
                file_index,
                path,
            )
        decoded_path, original_size, ext_bytes = _restore_b512_plaintext_stream(
            plaintext_path,
            envelope,
            password,
            use_master_effective,
            temp_dir.name,
            cleanup_paths,
            reporter,
            file_index,
            path,
        )
        target = path.with_suffix('')
        ext_text = ''
        if ext_bytes:
            try:
                ext_text = ext_bytes.decode('utf-8')
            except UnicodeDecodeError:
                ext_text = ''
            if ext_text:
                target = target.with_suffix(ext_text)
        pack_flag = basefwx._pack_flag_from_meta(envelope.metadata, ext_text)
        basefwx.os.replace(decoded_path, target)
        cleanup_paths.remove(decoded_path)
        basefwx.os.remove(path)
        if plaintext_path and plaintext_path in cleanup_paths:
            basefwx.os.remove(plaintext_path)
            cleanup_paths.remove(plaintext_path)
        if pack_flag:
            target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
        elif strip_metadata:
            basefwx._apply_strip_attributes(target)
        output_len = original_size
        size_hint = (input_size, output_len)
        if reporter:
            reporter.update(file_index, 1.0, 'done', target, size_hint=size_hint)
            reporter.finalize_file(file_index, target, size_hint=size_hint)
        return (target, output_len)
    finally:
        for temp_path in cleanup_paths:
            _remove_if_exists(temp_path)
        temp_dir.cleanup()


def _aes_heavy_encode_path_stream(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, pack_flag: str='', output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, *, input_size: 'basefwx.typing.Optional[int]'=None, keep_input: bool=False) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx._ensure_size_limit(path)
    if strip_metadata:
        raise ValueError(
            'Streaming AES-heavy encode requires metadata for format dispatch'
        )
    heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
    basefwx._require_peer_pbkdf2_within_limits(heavy_iters)
    display_path = display_path or path
    output_path = output_path or path.with_suffix('.fwx')
    input_size = input_size if input_size is not None else path.stat().st_size
    if password == '':
        raise ValueError('Password required for AES heavy streaming mode')
    if reporter:
        reporter.update(file_index, 0.05, 'prepare', display_path)
    chunk_size = basefwx.STREAM_CHUNK_SIZE
    master_selection = basefwx._select_master_key(
        use_master and (not strip_metadata), master_pubkey
    )
    use_master_effective = master_selection.used_master
    kdf_used = basefwx._resolve_kdf_label(None)
    heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
    stream_salt = basefwx._StreamObfuscator.generate_salt()
    obfuscate_payload = basefwx.ENABLE_OBFUSCATION
    fast_obf = (
        obfuscate_payload
        and not strip_metadata
        and basefwx._use_fast_obfuscation(input_size)
    )
    obf_mode = (
        'no'
        if not obfuscate_payload
        else ('fast' if fast_obf else 'yes')
    )
    metadata_blob = basefwx._build_metadata(
        'AES-HEAVY',
        strip_metadata,
        use_master_effective,
        master_kem=master_selection.kem_label,
        kdf=kdf_used,
        mode='STREAM',
        obfuscation=obf_mode,
        kdf_iters=heavy_iters,
        argon2_time_cost=heavy_argon_time,
        argon2_memory_cost=heavy_argon_mem,
        argon2_parallelism=heavy_argon_par,
        pack=pack_flag or None,
        key_separation='v1',
    )
    metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
    aad = metadata_bytes if metadata_bytes else b''
    prefix_bytes = b''
    if metadata_blob:
        prefix_bytes = metadata_bytes + basefwx.META_DELIM.encode('utf-8')
    ext_bytes = (path.suffix or '').encode('utf-8')
    stream_header = bytearray()
    stream_header.extend(basefwx.STREAM_MAGIC)
    stream_header.extend(chunk_size.to_bytes(4, 'big'))
    stream_header.extend(input_size.to_bytes(8, 'big'))
    stream_header.extend(stream_salt)
    stream_header.extend(len(ext_bytes).to_bytes(2, 'big'))
    stream_header.extend(ext_bytes)
    stream_header_bytes = bytes(stream_header)
    plaintext_len = len(prefix_bytes) + len(stream_header_bytes) + input_size
    metadata_len = len(metadata_bytes)
    estimated_len = basefwx._estimate_aead_blob_size(plaintext_len, metadata_len, include_user=bool(password), include_master=use_master_effective)
    estimated_hint = (input_size, estimated_len)
    if reporter:
        reporter.update(file_index, 0.12, 'stream-setup', display_path, size_hint=estimated_hint)
    if use_master_effective:
        if master_selection.pq_public is not None:
            kem_ciphertext, kem_shared = basefwx._kem_encrypt(
                master_selection.pq_public
            )
            master_payload = kem_ciphertext
        else:
            master_payload, kem_shared = basefwx._ec_kem_enc(
                master_selection.ec_public
            )
        ephemeral_key = basefwx._kem_derive_key(kem_shared)
    else:
        master_payload = b''
        ephemeral_key = basefwx.os.urandom(32)
    user_derived_key = None
    user_salt = b''
    if password:
        user_derived_key, user_salt = basefwx._derive_user_key(password, salt=None, iterations=heavy_iters, kdf=kdf_used, argon2_time_cost=heavy_argon_time, argon2_memory_cost=heavy_argon_mem, argon2_parallelism=heavy_argon_par)
        wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
        ephemeral_enc_user = user_salt + wrapped_ephemeral
    else:
        ephemeral_enc_user = b''
    key_separation = (
        basefwx._decode_metadata(metadata_blob).get('ENC-KSEP')
        if metadata_blob
        else None
    )
    if key_separation not in (None, '', 'v1'):
        raise ValueError('Unsupported payload key-separation version')
    use_derived_keys = key_separation == 'v1'
    payload_aead_key = (
        basefwx._hkdf_sha256(
            ephemeral_key,
            info=basefwx.FWXAES_PAYLOAD_AEAD_INFO,
            length=32,
        )
        if use_derived_keys
        else ephemeral_key
    )
    payload_obf_key = (
        basefwx._hkdf_sha256(
            ephemeral_key,
            info=basefwx.FWXAES_PAYLOAD_OBF_INFO,
            length=32,
        )
        if use_derived_keys
        else None
    )
    nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
    encryptor = basefwx.Cipher(
        basefwx.algorithms.AES(payload_aead_key),
        basefwx.modes.GCM(nonce),
    ).encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-stream-', dir=str(output_path.parent))
    cleanup_paths: 'basefwx.typing.List[str]' = []
    processed_plain = 0
    total_plain = plaintext_len

    def _aes_progress(done_plain: int, total_plain_bytes: int) -> None:
        if not reporter:
            return
        fraction = 0.55 + 0.44 * (done_plain / total_plain_bytes if total_plain_bytes else 0.0)
        reporter.update(file_index, fraction, 'AES512', display_path, size_hint=estimated_hint)

    def _obf_progress(done_bytes: int, total_bytes: int) -> None:
        if not reporter:
            return
        fraction = 0.2 + 0.7 * (done_bytes / total_bytes if total_bytes else 0.0)
        reporter.update(file_index, fraction, 'pb512-stream', display_path, size_hint=estimated_hint)
    try:
        with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as cipher_tmp:
            cleanup_paths.append(cipher_tmp.name)
            len_user = len(ephemeral_enc_user)
            len_master = len(master_payload)
            cipher_tmp.write(len_user.to_bytes(4, 'big'))
            cipher_tmp.write(ephemeral_enc_user)
            cipher_tmp.write(len_master.to_bytes(4, 'big'))
            cipher_tmp.write(master_payload)
            payload_len_pos = cipher_tmp.tell()
            cipher_tmp.write(b'\x00\x00\x00\x00')
            payload_start = cipher_tmp.tell()
            cipher_tmp.write(metadata_len.to_bytes(4, 'big'))
            if metadata_bytes:
                cipher_tmp.write(metadata_bytes)
            cipher_tmp.write(nonce)

            def _write_plain(data: bytes) -> None:
                nonlocal processed_plain
                if not data:
                    return
                ct = encryptor.update(data)
                if ct:
                    cipher_tmp.write(ct)
                processed_plain += len(data)
                _aes_progress(processed_plain, total_plain)
            if prefix_bytes:
                _write_plain(prefix_bytes)
            _write_plain(stream_header_bytes)
            if obfuscate_payload:
                basefwx._StreamObfuscator.encode_file(
                    path,
                    None,
                    password,
                    stream_salt,
                    chunk_size=chunk_size,
                    fast=fast_obf,
                    forward_chunk=_write_plain,
                    progress_cb=lambda done, total: _obf_progress(done, total),
                    key=payload_obf_key,
                )
            else:
                processed_input = 0
                with open(path, 'rb') as source:
                    while True:
                        chunk = source.read(chunk_size)
                        if not chunk:
                            break
                        _write_plain(chunk)
                        processed_input += len(chunk)
                        _obf_progress(processed_input, input_size)
            tail = encryptor.finalize()
            if tail:
                cipher_tmp.write(tail)
            cipher_tmp.write(encryptor.tag)
            payload_end = cipher_tmp.tell()
            payload_len = payload_end - payload_start
            cipher_tmp.seek(payload_len_pos)
            cipher_tmp.write(payload_len.to_bytes(4, 'big'))
            cipher_tmp.flush()
            cipher_tmp_path = cipher_tmp.name
        actual_size = basefwx.os.path.getsize(cipher_tmp_path)
        actual_hint = (input_size, actual_size)
        basefwx.os.replace(cipher_tmp_path, output_path)
        cleanup_paths.remove(cipher_tmp_path)
        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
        basefwx._remove_input(path, keep_input, output_path)
        if reporter:
            reporter.update(file_index, 1.0, 'done', output_path, size_hint=actual_hint)
            reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
        else:
            human = basefwx._human_readable_size(actual_size)
            if not basefwx._SILENT_MODE:
                print(f'{output_path.name}: approx output size {human}')
        return (output_path, actual_size)
    finally:
        basefwx._del('ephemeral_key')
        basefwx._del('payload_aead_key')
        basefwx._del('payload_obf_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        for temp_path in cleanup_paths:
            _remove_if_exists(temp_path)
        temp_dir.cleanup()

def b512file_encode(file: str, code: str, strip_metadata: bool=False, use_master: bool=True, keep_input: bool=False):
    try:
        pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master and (not strip_metadata), None)
        effective_use_master = (use_master and (not strip_metadata)) and master_available
        password = basefwx._resolve_password(code, use_master=effective_use_master)
        path = basefwx._normalize_path(file)
        basefwx._b512_encode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master, master_pubkey=pubkey_bytes, keep_input=keep_input)
        return 'SUCCESS!'
    except Exception as exc:
        print(f'Failed to encode {file}: {exc}')
        return 'FAIL!'

def b512file(files: 'basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]', password: str, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, silent: bool=False, compress: bool=False, keep_input: bool=False):
    paths = basefwx._coerce_file_list(files)
    pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master and (not strip_metadata), master_pubkey)
    encode_use_master = (use_master and (not strip_metadata)) and master_available
    decode_use_master = use_master and (not strip_metadata)
    try:
        resolved_password = basefwx._resolve_password(password, use_master=encode_use_master)
    except Exception as exc:
        if not silent:
            print(f'Password resolution failed: {exc}')
        return 'FAIL!' if len(paths) == 1 else {str(p): 'FAIL!' for p in paths}
    previous_silent = basefwx._SILENT_MODE
    basefwx._SILENT_MODE = silent
    try:
        reporter = basefwx._ProgressReporter(len(paths)) if not silent else None
        results: dict[str, str] = {}

        def _process_with_reporter(idx: int, path: 'basefwx.pathlib.Path') -> tuple[str, str]:
            try:
                if not path.exists():
                    if reporter:
                        reporter.fail_file(idx, path, 'error: input file not found')
                    return (str(path), 'FAIL!')
                if path.suffix.lower() == '.fwx' and path.is_file():
                    basefwx._b512_decode_path(path, resolved_password, reporter, idx, len(paths), strip_metadata, decode_use_master)
                else:
                    pack_ctx = basefwx._pack_input_to_archive(path, compress, reporter, idx)
                    pack_flag = pack_ctx[1] if pack_ctx else ''
                    pack_temp = pack_ctx[2] if pack_ctx else None
                    source_path = pack_ctx[0] if pack_ctx else path
                    try:
                        basefwx._b512_encode_path(source_path, resolved_password, reporter, idx, len(paths), strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        if pack_ctx:
                            basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                    finally:
                        if pack_temp is not None:
                            pack_temp.cleanup()
                return (str(path), 'SUCCESS!')
            except Exception as exc:
                if reporter:
                    reporter.fail_file(idx, path, f'error: {exc}')
                return (str(path), 'FAIL!')

        def _process_without_reporter(path: 'basefwx.pathlib.Path') -> tuple[str, str]:
            try:
                if not path.exists():
                    return (str(path), 'FAIL!')
                if path.suffix.lower() == '.fwx' and path.is_file():
                    basefwx._b512_decode_path(path, resolved_password, None, 0, len(paths), strip_metadata, decode_use_master)
                else:
                    pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
                    pack_flag = pack_ctx[1] if pack_ctx else ''
                    pack_temp = pack_ctx[2] if pack_ctx else None
                    source_path = pack_ctx[0] if pack_ctx else path
                    try:
                        basefwx._b512_encode_path(source_path, resolved_password, None, 0, len(paths), strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        if pack_ctx:
                            basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                    finally:
                        if pack_temp is not None:
                            pack_temp.cleanup()
                return (str(path), 'SUCCESS!')
            except Exception:
                return (str(path), 'FAIL!')
        use_parallel = len(paths) > 1 and basefwx._CPU_COUNT > 1
        if use_parallel:
            max_workers = min(len(paths), basefwx._CPU_COUNT)
            if reporter:
                items = list(enumerate(paths))

                def _dispatch(item: 'tuple[int, basefwx.pathlib.Path]') -> tuple[str, str]:
                    idx, path = item
                    return _process_with_reporter(idx, path)
                with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for file_id, status in executor.map(_dispatch, items):
                        results[file_id] = status
            else:
                with basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    for file_id, status in executor.map(_process_without_reporter, paths):
                        results[file_id] = status
        else:
            for idx, path in enumerate(paths):
                file_id, status = _process_with_reporter(idx, path)
                results[file_id] = status
        if reporter:
            reporter.reset_terminal_state()
        if len(paths) == 1:
            final_result = next(iter(results.values()))
        else:
            final_result = results
    finally:
        basefwx._SILENT_MODE = previous_silent
    return final_result

def b512file_decode(file: str, code: str, strip_metadata: bool=False, use_master: bool=True):
    try:
        effective_use_master = use_master and (not strip_metadata)
        password = basefwx._resolve_password(code, use_master=effective_use_master)
        path = basefwx._normalize_path(file)
        basefwx._b512_decode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master)
        return 'SUCCESS!'
    except Exception as exc:
        print(f'Failed to decode {file}: {exc}')
        return 'FAIL!'
