# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _aes_light_encode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, pack_flag: str='', output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, keep_input: bool=False) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx._ensure_size_limit(path)
    display_path = display_path or path
    output_path = output_path or path.with_suffix('.fwx')
    input_size = path.stat().st_size
    size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.05, 'prepare', path)
    pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master and (not strip_metadata), master_pubkey)
    use_master_effective = (use_master and (not strip_metadata)) and master_available
    obfuscate_payload = input_size <= basefwx.STREAM_THRESHOLD
    chunk_size = max(3, basefwx.STREAM_CHUNK_SIZE)
    buffer = bytearray()
    processed = 0
    total = input_size
    b64_parts: 'basefwx.typing.List[str]' = []
    with open(path, 'rb') as src_handle:
        while True:
            chunk = src_handle.read(chunk_size)
            if not chunk:
                break
            buffer.extend(chunk)
            processed += len(chunk)
            take_len = len(buffer) // 3 * 3
            if take_len:
                part = basefwx.base64.b64encode(buffer[:take_len]).decode('ascii')
                b64_parts.append(part)
                del buffer[:take_len]
            if reporter and total:
                fraction = 0.05 + 0.2 * (processed / total)
                reporter.update(file_index, fraction, 'base64', display_path)
    if buffer:
        b64_parts.append(basefwx.base64.b64encode(buffer).decode('ascii'))
    b64_payload = ''.join(b64_parts)
    basefwx._del('b64_parts')
    basefwx._del('buffer')
    if reporter:
        reporter.update(file_index, 0.25, 'base64', display_path)
    kdf_used = (basefwx.USER_KDF or 'argon2id').lower()
    fast_obf = obfuscate_payload and (not strip_metadata) and basefwx._use_fast_obfuscation(input_size)
    obf_mode = 'fast' if fast_obf else 'yes' if obfuscate_payload else 'no'
    metadata_blob = basefwx._build_metadata('AES-LIGHT', strip_metadata, use_master_effective, kdf=kdf_used, obfuscation=obf_mode, pack=pack_flag or None)
    body = (path.suffix or '') + basefwx.FWX_DELIM + b64_payload
    plaintext = f'{metadata_blob}{basefwx.META_DELIM}{body}' if metadata_blob else body
    plain_bytes_len = len(plaintext.encode('utf-8'))
    est_cipher_len = basefwx.AEAD_NONCE_LEN + plain_bytes_len + basefwx.AEAD_TAG_LEN
    progress_cb = None
    if reporter:
        enc_hint = (input_size, est_cipher_len)

        def _enc_progress(done: int, total: int) -> None:
            fraction = 0.55 + 0.41 * (done / total if total else 0.0)
            reporter.update(file_index, fraction, 'AES512', display_path, size_hint=enc_hint)
        progress_cb = _enc_progress
    ciphertext = basefwx.encryptAES(plaintext, password, use_master=use_master_effective, metadata_blob=metadata_blob, master_public_key=pubkey_bytes if use_master_effective else None, kdf=kdf_used, progress_callback=progress_cb, obfuscate=obfuscate_payload, fast_obfuscation=fast_obf)
    compressor = basefwx.zlib.compressobj()
    compressed_parts: 'basefwx.typing.List[bytes]' = []
    total_cipher = len(ciphertext)
    processed_cipher = 0
    chunk_size_enc = basefwx.STREAM_CHUNK_SIZE
    for offset in range(0, total_cipher, chunk_size_enc):
        chunk = ciphertext[offset:offset + chunk_size_enc]
        comp = compressor.compress(chunk)
        if comp:
            compressed_parts.append(comp)
        processed_cipher += len(chunk)
        if reporter and total_cipher:
            fraction = 0.8 + 0.12 * (processed_cipher / total_cipher)
            reporter.update(file_index, min(fraction, 0.92), 'compress', display_path)
    tail = compressor.flush()
    if tail:
        compressed_parts.append(tail)
    compressed = b''.join(compressed_parts)
    basefwx._del('compressed_parts')
    output_len = len(compressed)
    size_hint = (input_size, output_len)
    if reporter:
        reporter.update(file_index, 0.92, 'compress', display_path, size_hint=size_hint)
    with open(output_path, 'wb') as handle:
        handle.write(compressed)
    basefwx._del('ciphertext')
    basefwx._del('compressed')
    if strip_metadata:
        basefwx._apply_strip_attributes(output_path)
        basefwx.os.chmod(output_path, 0)
    basefwx._remove_input(path, keep_input, output_path)
    if reporter:
        reporter.update(file_index, 1.0, 'done', output_path, size_hint=size_hint)
        reporter.finalize_file(file_index, output_path, size_hint=size_hint)
    return (output_path, output_len)


def _aes_light_decode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx.os.chmod(path, 384)
    input_size = path.stat().st_size
    size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.05, 'read', path)
    compressed = path.read_bytes()
    if reporter:
        reporter.update(file_index, 0.25, 'decompress', path)
    try:
        ciphertext = basefwx.zlib.decompress(compressed)
    except basefwx.zlib.error as exc:
        raise ValueError('Compressed FWX payload is corrupted') from exc
    decrypt_progress = None
    if reporter:

        def _dec_progress(done: int, total: int) -> None:
            fraction = 0.55 + 0.2 * (done / total if total else 0.0)
            reporter.update(file_index, fraction, 'AES512', path)
        decrypt_progress = _dec_progress
    use_master_effective = use_master and (not strip_metadata)
    plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective, progress_callback=decrypt_progress)
    metadata_blob, payload = basefwx._split_metadata(plaintext)
    meta = basefwx._decode_metadata(metadata_blob)
    if meta.get('ENC-MASTER') == 'no':
        use_master_effective = False
    basefwx._warn_on_metadata(meta, 'AES-LIGHT')
    basefwx._warn_on_metadata(meta, 'AES-LIGHT')
    try:
        ext, b64_payload = basefwx._split_with_delims(payload, (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM), 'FWX payload')
    except ValueError as exc:
        raise ValueError('Malformed FWX light payload') from exc
    if reporter:
        reporter.update(file_index, 0.75, 'base64', path)
    raw = basefwx.base64.b64decode(b64_payload)
    pack_flag = basefwx._pack_flag_from_meta(meta, ext)
    target = path.with_suffix('')
    if ext:
        target = target.with_suffix(ext)
    with open(target, 'wb') as handle:
        handle.write(raw)
    basefwx.os.remove(path)
    if pack_flag:
        target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
    elif strip_metadata:
        basefwx._apply_strip_attributes(target)
    output_len = len(raw)
    size_hint = (input_size, output_len)
    if reporter:
        reporter.update(file_index, 1.0, 'done', target, size_hint=size_hint)
        reporter.finalize_file(file_index, target, size_hint=size_hint)
    return (target, output_len)


def _aes_heavy_encode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, pack_flag: str='', output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, keep_input: bool=False) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx._ensure_size_limit(path)
    display_path = display_path or path
    output_path = output_path or path.with_suffix('.fwx')
    input_size = path.stat().st_size
    approx_b64_len = (input_size + 2) // 3 * 4
    if input_size >= basefwx.STREAM_THRESHOLD or approx_b64_len > basefwx.HKDF_MAX_LEN:
        return basefwx._aes_heavy_encode_path_stream(path, password, reporter, file_index, strip_metadata, use_master, master_pubkey, pack_flag=pack_flag, output_path=output_path, display_path=display_path, input_size=input_size, keep_input=keep_input)
    estimated_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.05, 'prepare', display_path)
    pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master and (not strip_metadata), master_pubkey)
    use_master_effective = (use_master and (not strip_metadata)) and master_available
    heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
    heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
    raw = path.read_bytes()
    if reporter:
        reporter.update(file_index, 0.25, 'base64', display_path)
    b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
    ext_token = basefwx.pb512encode(path.suffix or '', password, use_master=use_master_effective)
    data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)
    if reporter:
        reporter.update(file_index, 0.55, 'pb512', display_path)
    kdf_used = (basefwx.USER_KDF or 'argon2id').lower()
    fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(input_size)
    obf_mode = 'fast' if fast_obf else 'yes'
    metadata_blob = basefwx._build_metadata('AES-HEAVY', strip_metadata, use_master_effective, kdf=kdf_used, obfuscation=obf_mode, kdf_iters=heavy_iters, argon2_time_cost=heavy_argon_time, argon2_memory_cost=heavy_argon_mem, argon2_parallelism=heavy_argon_par, pack=pack_flag or None)
    body = f'{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}'
    plaintext = f'{metadata_blob}{basefwx.META_DELIM}{body}' if metadata_blob else body
    metadata_bytes_len = len(metadata_blob.encode('utf-8')) if metadata_blob else 0
    plaintext_bytes_len = len(plaintext.encode('utf-8'))
    estimated_len = basefwx._estimate_aead_blob_size(plaintext_bytes_len, metadata_bytes_len, include_user=bool(password), include_master=use_master_effective)
    estimated_hint = (input_size, estimated_len)
    progress_cb = None
    if reporter:

        def _enc_progress(done: int, total: int) -> None:
            fraction = 0.55 + 0.4 * (done / total if total else 0.0)
            reporter.update(file_index, fraction, 'AES512', display_path, size_hint=estimated_hint)
        progress_cb = _enc_progress
    ciphertext = basefwx.encryptAES(plaintext, password, use_master=use_master_effective, metadata_blob=metadata_blob, master_public_key=pubkey_bytes if use_master_effective else None, kdf=kdf_used, progress_callback=progress_cb, kdf_iterations=heavy_iters, argon2_time_cost=heavy_argon_time, argon2_memory_cost=heavy_argon_mem, argon2_parallelism=heavy_argon_par, fast_obfuscation=fast_obf)
    approx_size = len(ciphertext)
    actual_hint = (input_size, approx_size)
    with open(output_path, 'wb') as handle:
        handle.write(ciphertext)
    if strip_metadata:
        basefwx._apply_strip_attributes(output_path)
        basefwx.os.chmod(output_path, 0)
    basefwx._remove_input(path, keep_input, output_path)
    if reporter:
        reporter.update(file_index, 1.0, 'done', output_path, size_hint=actual_hint)
        reporter.finalize_file(file_index, output_path, size_hint=actual_hint)
    else:
        human = basefwx._human_readable_size(approx_size)
        if not basefwx._SILENT_MODE:
            print(f'{output_path.name}: approx output size {human}')
    return (output_path, approx_size)


def _aes_heavy_decode_path(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    basefwx._ensure_existing_file(path)
    basefwx.os.chmod(path, 384)
    input_size = path.stat().st_size
    size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]' = None
    if reporter:
        reporter.update(file_index, 0.05, 'read', path)
    metadata_blob_preview = ''
    meta_preview: 'basefwx.typing.Dict[str, basefwx.typing.Any]' = {}
    with open(path, 'rb') as preview:
        len_user_bytes = preview.read(4)
        if len(len_user_bytes) < 4:
            raise ValueError('Ciphertext payload truncated')
        len_user = int.from_bytes(len_user_bytes, 'big')
        preview.seek(len_user, basefwx.os.SEEK_CUR)
        len_master_bytes = preview.read(4)
        if len(len_master_bytes) < 4:
            raise ValueError('Ciphertext payload truncated')
        len_master = int.from_bytes(len_master_bytes, 'big')
        preview.seek(len_master, basefwx.os.SEEK_CUR)
        len_payload_bytes = preview.read(4)
        if len(len_payload_bytes) < 4:
            raise ValueError('Ciphertext payload truncated')
        len_payload = int.from_bytes(len_payload_bytes, 'big')
        if len_payload < 4:
            raise ValueError('Ciphertext payload truncated')
        metadata_len_bytes = preview.read(4)
        if len(metadata_len_bytes) < 4:
            raise ValueError('Ciphertext payload truncated')
        metadata_len = int.from_bytes(metadata_len_bytes, 'big')
        metadata_bytes_preview = preview.read(metadata_len)
        try:
            metadata_blob_preview = metadata_bytes_preview.decode('utf-8') if metadata_bytes_preview else ''
        except UnicodeDecodeError:
            metadata_blob_preview = ''
        meta_preview = basefwx._decode_metadata(metadata_blob_preview)
    mode_hint = (meta_preview.get('ENC-MODE') or '').lower()
    if mode_hint == 'stream':
        return basefwx._aes_heavy_decode_path_stream(path, password, reporter, file_index, strip_metadata, use_master, meta_preview, metadata_blob_preview, input_size=input_size)
    ciphertext = path.read_bytes()
    use_master_effective = use_master and (not strip_metadata)
    decrypt_progress = None
    if reporter:

        def _dec_progress(done: int, total: int) -> None:
            fraction = 0.35 + 0.25 * (done / total if total else 0.0)
            reporter.update(file_index, fraction, 'AES512', path)
        decrypt_progress = _dec_progress
    plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective, progress_callback=decrypt_progress)
    metadata_blob, payload = basefwx._split_metadata(plaintext)
    meta = basefwx._decode_metadata(metadata_blob)
    if meta.get('ENC-MASTER') == 'no':
        use_master_effective = False
    basefwx._warn_on_metadata(meta, 'AES-HEAVY')
    ext_token, data_token = basefwx._split_with_delims(payload, (basefwx.FWX_HEAVY_DELIM, basefwx.LEGACY_FWX_HEAVY_DELIM), 'FWX heavy')
    if reporter:
        reporter.update(file_index, 0.6, 'pb512', path)
    ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
    data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)
    if reporter:
        reporter.update(file_index, 0.8, 'base64', path)
    raw = basefwx.base64.b64decode(data_b64)
    pack_flag = basefwx._pack_flag_from_meta(meta, ext)
    target = path.with_suffix('')
    if ext:
        target = target.with_suffix(ext)
    with open(target, 'wb') as handle:
        handle.write(raw)
    basefwx.os.remove(path)
    if pack_flag:
        target = basefwx._maybe_unpack_output(target, pack_flag, reporter, file_index, strip_metadata)
    elif strip_metadata:
        basefwx._apply_strip_attributes(target)
    output_len = len(raw)
    size_hint = (input_size, output_len)
    if reporter:
        reporter.update(file_index, 1.0, 'done', target, size_hint=size_hint)
        reporter.finalize_file(file_index, target, size_hint=size_hint)
    return (target, output_len)


def _aes_heavy_decode_path_stream(path: 'basefwx.pathlib.Path', password: str, reporter: 'basefwx._ProgressReporter'=None, file_index: int=0, strip_metadata: bool=False, use_master: bool=True, meta_preview: 'basefwx.typing.Optional[basefwx.typing.Dict[str, basefwx.typing.Any]]'=None, metadata_blob_preview: str='', *, input_size: 'basefwx.typing.Optional[int]'=None) -> 'basefwx.typing.Tuple[basefwx.pathlib.Path, int]':
    if not password:
        raise ValueError('Password required for AES heavy streaming mode')
    basefwx._ensure_existing_file(path)
    basefwx.os.chmod(path, 384)
    input_size = input_size if input_size is not None else path.stat().st_size
    meta = meta_preview or {}
    metadata_blob = metadata_blob_preview or ''
    use_master_effective = use_master and (not strip_metadata)
    if meta.get('ENC-MASTER') == 'no':
        use_master_effective = False
    basefwx._warn_on_metadata(meta, 'AES-HEAVY')
    temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-stream-dec-', dir=str(path.parent))
    cleanup_paths: 'basefwx.typing.List[str]' = []
    plaintext_path: 'basefwx.typing.Optional[str]' = None
    decoded_path: 'basefwx.typing.Optional[str]' = None
    metadata_bytes: bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
    aad = metadata_bytes if metadata_bytes else b''

    def _parse_int(value: 'basefwx.typing.Any', default: 'basefwx.typing.Optional[int]') -> 'basefwx.typing.Optional[int]':
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    kdf_hint = (meta.get('ENC-KDF') or basefwx.USER_KDF or 'argon2id').lower()
    kdf_iter_hint = _parse_int(meta.get('ENC-KDF-ITER'), basefwx.USER_KDF_ITERATIONS)
    argon2_time_hint = _parse_int(meta.get('ENC-ARGON2-TC'), None)
    argon2_mem_hint = _parse_int(meta.get('ENC-ARGON2-MEM'), None)
    argon2_par_hint = _parse_int(meta.get('ENC-ARGON2-PAR'), None)
    try:
        with open(path, 'rb') as handle:
            len_user_bytes = handle.read(4)
            if len(len_user_bytes) < 4:
                raise ValueError('Ciphertext payload truncated')
            len_user = int.from_bytes(len_user_bytes, 'big')
            user_blob = handle.read(len_user)
            if len(user_blob) != len_user:
                raise ValueError('Ciphertext payload truncated')
            len_master_bytes = handle.read(4)
            if len(len_master_bytes) < 4:
                raise ValueError('Ciphertext payload truncated')
            len_master = int.from_bytes(len_master_bytes, 'big')
            master_blob = handle.read(len_master)
            if len(master_blob) != len_master:
                raise ValueError('Ciphertext payload truncated')
            len_payload_bytes = handle.read(4)
            if len(len_payload_bytes) < 4:
                raise ValueError('Ciphertext payload truncated')
            len_payload = int.from_bytes(len_payload_bytes, 'big')
            len_payload = basefwx._resolve_payload_length_from_file_size(path, len_user, len_master, len_payload)
            if len_payload < 4 + basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN:
                raise ValueError('Ciphertext payload truncated')
            metadata_len_bytes = handle.read(4)
            if len(metadata_len_bytes) < 4:
                raise ValueError('Ciphertext payload truncated')
            metadata_len = int.from_bytes(metadata_len_bytes, 'big')
            metadata_bytes_disk = handle.read(metadata_len)
            if len(metadata_bytes_disk) != metadata_len:
                raise ValueError('Ciphertext payload truncated')
            if metadata_bytes:
                if metadata_bytes_disk != metadata_bytes:
                    raise ValueError('Metadata integrity mismatch detected')
            else:
                metadata_bytes = metadata_bytes_disk
                aad = metadata_bytes if metadata_bytes else b''
            nonce = handle.read(basefwx.AEAD_NONCE_LEN)
            if len(nonce) != basefwx.AEAD_NONCE_LEN:
                raise ValueError('Ciphertext payload truncated')
            cipher_body_len = len_payload - 4 - len(metadata_bytes) - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
            if cipher_body_len < 0:
                raise ValueError('Ciphertext payload truncated')
            cipher_body_start = handle.tell()
            handle.seek(cipher_body_len, basefwx.os.SEEK_CUR)
            tag = handle.read(basefwx.AEAD_TAG_LEN)
            if len(tag) != basefwx.AEAD_TAG_LEN:
                raise ValueError('Ciphertext payload truncated')
            handle.seek(cipher_body_start)

            def _unwrap_with_user() -> bytes:
                if not password:
                    raise ValueError('User password required to decrypt this payload')
                min_len = basefwx.USER_KDF_SALT_SIZE + 13
                if len(user_blob) < min_len:
                    raise ValueError('Corrupted user key blob: missing salt or AEAD data')
                user_salt = user_blob[:basefwx.USER_KDF_SALT_SIZE]
                wrapped_ephemeral = user_blob[basefwx.USER_KDF_SALT_SIZE:]
                user_derived_key, _ = basefwx._derive_user_key(password, salt=user_salt, iterations=kdf_iter_hint or basefwx.USER_KDF_ITERATIONS, kdf=kdf_hint, argon2_time_cost=argon2_time_hint, argon2_memory_cost=argon2_mem_hint, argon2_parallelism=argon2_par_hint)
                return basefwx._aead_decrypt(user_derived_key, wrapped_ephemeral, aad)
            ephemeral_key = None
            if len(master_blob) > 0 and use_master_effective:
                try:
                    private_key = basefwx._load_master_pq_private()
                    kem_shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
                    ephemeral_key = basefwx._kem_derive_key(kem_shared)
                except FileNotFoundError:
                    if len(user_blob) > 0 and password:
                        ephemeral_key = _unwrap_with_user()
                    else:
                        raise
            elif len(master_blob) > 0 and (not use_master_effective):
                if len(user_blob) > 0 and password:
                    ephemeral_key = _unwrap_with_user()
                else:
                    raise ValueError('Master key required to decrypt this payload')
            elif len(user_blob) > 0:
                ephemeral_key = _unwrap_with_user()
            else:
                raise ValueError('Ciphertext missing key transport data')
            decryptor = basefwx.Cipher(basefwx.algorithms.AES(ephemeral_key), basefwx.modes.GCM(nonce, tag)).decryptor()
            if aad:
                decryptor.authenticate_additional_data(aad)
            if reporter:
                reporter.update(file_index, 0.35, 'AES512', path)
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as plain_tmp:
                cleanup_paths.append(plain_tmp.name)
                plaintext_path = plain_tmp.name
                remaining = cipher_body_len
                chunk_size = basefwx.STREAM_CHUNK_SIZE
                processed = 0
                while remaining > 0:
                    take = min(chunk_size, remaining)
                    chunk = handle.read(take)
                    if len(chunk) != take:
                        raise ValueError('Ciphertext truncated')
                    plain_chunk = decryptor.update(chunk)
                    if plain_chunk:
                        plain_tmp.write(plain_chunk)
                    remaining -= take
                    processed += take
                    if reporter:
                        fraction = 0.35 + 0.25 * (processed / cipher_body_len if cipher_body_len else 1.0)
                        reporter.update(file_index, fraction, 'AES512', path)
                final_chunk = decryptor.finalize()
                if final_chunk:
                    plain_tmp.write(final_chunk)
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        if plaintext_path is None:
            raise RuntimeError('Streaming decrypt failed to produce plaintext')
        with open(plaintext_path, 'rb') as plain_handle:
            if metadata_bytes:
                expected_prefix = metadata_bytes
                prefix = plain_handle.read(len(expected_prefix))
                if prefix != expected_prefix:
                    raise ValueError('Metadata integrity mismatch detected')
                delim_bytes = basefwx.META_DELIM.encode('utf-8')
                delim = plain_handle.read(len(delim_bytes))
                if delim != delim_bytes:
                    raise ValueError('Malformed streaming payload: missing metadata delimiter')
            stream_magic = plain_handle.read(len(basefwx.STREAM_MAGIC))
            if stream_magic != basefwx.STREAM_MAGIC:
                raise ValueError('Malformed streaming payload: magic mismatch')
            chunk_size_bytes = plain_handle.read(4)
            if len(chunk_size_bytes) != 4:
                raise ValueError('Malformed streaming payload: missing chunk size')
            chunk_size_value = int.from_bytes(chunk_size_bytes, 'big')
            if chunk_size_value <= 0 or chunk_size_value > 16 << 20:
                chunk_size_value = basefwx.STREAM_CHUNK_SIZE
            original_size_bytes = plain_handle.read(8)
            if len(original_size_bytes) != 8:
                raise ValueError('Malformed streaming payload: missing original size')
            original_size = int.from_bytes(original_size_bytes, 'big')
            stream_salt = plain_handle.read(basefwx._StreamObfuscator._SALT_LEN)
            if len(stream_salt) != basefwx._StreamObfuscator._SALT_LEN:
                raise ValueError('Malformed streaming payload: missing salt')
            ext_len_bytes = plain_handle.read(2)
            if len(ext_len_bytes) != 2:
                raise ValueError('Malformed streaming payload: missing extension length')
            ext_len = int.from_bytes(ext_len_bytes, 'big')
            ext_bytes = plain_handle.read(ext_len)
            if len(ext_bytes) != ext_len:
                raise ValueError('Malformed streaming payload: truncated extension')
            data_start = plain_handle.tell()
            with basefwx.tempfile.NamedTemporaryFile('w+b', dir=temp_dir.name, delete=False) as clear_tmp:
                cleanup_paths.append(clear_tmp.name)
                decoded_path = clear_tmp.name
                processed = 0
                obf_hint = (meta.get('ENC-OBF') or 'yes').lower()
                fast_obf = obf_hint == 'fast'
                decoder = basefwx._StreamObfuscator.for_password(password, stream_salt, fast=fast_obf)
                while processed < original_size:
                    to_read = min(chunk_size_value, original_size - processed)
                    chunk = plain_handle.read(to_read)
                    if len(chunk) != to_read:
                        raise ValueError('Streaming payload truncated')
                    clear_chunk = decoder.decode_chunk(chunk)
                    clear_tmp.write(clear_chunk)
                    processed += len(clear_chunk)
                    if reporter:
                        fraction = 0.7 + 0.2 * (processed / original_size if original_size else 1.0)
                        reporter.update(file_index, fraction, 'deobfuscate', path)
                leftover = plain_handle.read(1)
                if leftover:
                    raise ValueError('Streaming payload contained unexpected trailing data')
        target = path.with_suffix('')
        ext_text = ''
        if ext_bytes:
            try:
                ext_text = ext_bytes.decode('utf-8')
            except UnicodeDecodeError:
                ext_text = ''
            if ext_text:
                target = target.with_suffix(ext_text)
        pack_flag = basefwx._pack_flag_from_meta(meta, ext_text)
        if decoded_path is None:
            raise RuntimeError('Missing decoded payload')
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
            try:
                basefwx.os.remove(temp_path)
            except FileNotFoundError:
                pass
        temp_dir.cleanup()


def AESfile(files: 'basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]', password: str='', light: bool=True, strip_metadata: bool=False, use_master: bool=True, master_pubkey: 'basefwx.typing.Optional[bytes]'=None, silent: bool=False, compress: bool=False, keep_input: bool=False):
    basefwx.sys.set_int_max_str_digits(2000000000)
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
                        reporter.update(idx, 0.0, 'missing', path)
                        reporter.finalize_file(idx, path)
                    return (str(path), 'FAIL!')
                if path.suffix.lower() == '.fwx' and path.is_file():
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                else:
                    pack_ctx = basefwx._pack_input_to_archive(path, compress, reporter, idx)
                    pack_flag = pack_ctx[1] if pack_ctx else ''
                    pack_temp = pack_ctx[2] if pack_ctx else None
                    source_path = pack_ctx[0] if pack_ctx else path
                    try:
                        if light:
                            basefwx._aes_light_encode_path(source_path, resolved_password, reporter, idx, strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        else:
                            basefwx._aes_heavy_encode_path(source_path, resolved_password, reporter, idx, strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        if pack_ctx:
                            basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                    finally:
                        if pack_temp is not None:
                            pack_temp.cleanup()
                return (str(path), 'SUCCESS!')
            except KeyboardInterrupt:
                if reporter:
                    reporter.update(idx, 0.0, 'cancelled', path)
                    reporter.finalize_file(idx, path)
                raise
            except Exception as exc:
                if reporter:
                    reporter.update(idx, 0.0, f'error: {exc}', path)
                    reporter.finalize_file(idx, path)
                return (str(path), 'FAIL!')

        def _process_without_reporter(path: 'basefwx.pathlib.Path') -> tuple[str, str]:
            try:
                if not path.exists():
                    return (str(path), 'FAIL!')
                if path.suffix.lower() == '.fwx' and path.is_file():
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, None, 0, strip_metadata, decode_use_master)
                else:
                    pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
                    pack_flag = pack_ctx[1] if pack_ctx else ''
                    pack_temp = pack_ctx[2] if pack_ctx else None
                    source_path = pack_ctx[0] if pack_ctx else path
                    try:
                        if light:
                            basefwx._aes_light_encode_path(source_path, resolved_password, None, 0, strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        else:
                            basefwx._aes_heavy_encode_path(source_path, resolved_password, None, 0, strip_metadata, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=path.with_suffix('.fwx'), display_path=path, keep_input=keep_input)
                        if pack_ctx:
                            basefwx._remove_input(path, keep_input, output_path=path.with_suffix('.fwx'))
                    finally:
                        if pack_temp is not None:
                            pack_temp.cleanup()
                return (str(path), 'SUCCESS!')
            except KeyboardInterrupt:
                raise
            except Exception:
                return (str(path), 'FAIL!')
        use_parallel = len(paths) > 1 and basefwx._CPU_COUNT > 1
        if use_parallel:
            max_workers = min(len(paths), basefwx._CPU_COUNT)
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            futures: 'dict[basefwx.concurrent.futures.Future, tuple[int | None, basefwx.pathlib.Path]]' = {}
            shutdown_now = False
            try:
                if reporter:
                    for idx, path in enumerate(paths):
                        futures[executor.submit(_process_with_reporter, idx, path)] = (idx, path)
                else:
                    for path in paths:
                        futures[executor.submit(_process_without_reporter, path)] = (None, path)
                try:
                    for future in basefwx.concurrent.futures.as_completed(futures):
                        file_id, status = future.result()
                        results[file_id] = status
                except KeyboardInterrupt:
                    shutdown_now = True
                    for future, meta in futures.items():
                        if not future.done():
                            future.cancel()
                            idx, rest_path = meta
                            if reporter and idx is not None:
                                reporter.update(idx, 0.0, 'cancelled', rest_path)
                                reporter.finalize_file(idx, rest_path)
                            results[str(rest_path)] = 'CANCELLED'
                    executor.shutdown(wait=False, cancel_futures=True)
                    if len(paths) == 1:
                        return 'CANCELLED'
                    return results
            finally:
                executor.shutdown(wait=not shutdown_now, cancel_futures=True)
        else:
            try:
                for idx, path in enumerate(paths):
                    try:
                        file_id, status = _process_with_reporter(idx, path)
                        results[file_id] = status
                    except KeyboardInterrupt:
                        results[str(path)] = 'CANCELLED'
                        raise
            except KeyboardInterrupt:
                for idx, rest_path in enumerate(paths):
                    key = str(rest_path)
                    if key not in results:
                        if reporter:
                            reporter.update(idx, 0.0, 'cancelled', rest_path)
                            reporter.finalize_file(idx, rest_path)
                        results[key] = 'CANCELLED'
                if len(paths) == 1:
                    return 'CANCELLED'
                return results
        if reporter:
            reporter.reset_terminal_state()
        if len(paths) == 1:
            return next(iter(results.values()))
        return results
    finally:
        basefwx._SILENT_MODE = previous_silent
