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

def an7_file(input_path: 'basefwx.typing.Union[str, basefwx.pathlib.Path]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, out: 'basefwx.typing.Optional[basefwx.typing.Union[str, basefwx.pathlib.Path]]'=None, keep_input: bool=False, force_any: bool=False) -> str:
    path = basefwx._normalize_path(input_path)
    basefwx._ensure_existing_file(path)
    if not force_any and path.suffix.lower() != '.fwx':
        raise ValueError('an7 accepts only .fwx input by default (use --force-any to override)')
    resolved_password = basefwx._resolve_password(password, use_master=False)
    pw = basefwx._coerce_password_bytes(resolved_password)
    if not pw:
        raise ValueError('Password is required for an7')
    output_path = basefwx._an7_resolve_output_path(path, out)
    if basefwx._an7_same_path(path, output_path):
        raise ValueError('Output path must differ from input path')
    temp_path = basefwx._an7_make_temp_path(output_path)
    payload_len = path.stat().st_size
    total_chunks = basefwx._an7_total_chunks(payload_len, basefwx.AN7_CHUNK_SIZE)
    salt = basefwx.os.urandom(basefwx.AN7_SALT_LEN)
    keys = basefwx._an7_derive_keys(pw, salt)
    stream_nonce = basefwx.os.urandom(basefwx.AN7_TRAILER_NONCE_LEN)
    sha = basefwx.hashlib.sha256()
    try:
        with open(path, 'rb') as src, open(temp_path, 'wb') as dst:
            superblocks = basefwx._an7_total_chunks(total_chunks, basefwx.AN7_SUPERBLOCK_CHUNKS)
            for super_idx in range(superblocks):
                start_chunk = super_idx * basefwx.AN7_SUPERBLOCK_CHUNKS
                block_chunks = min(basefwx.AN7_SUPERBLOCK_CHUNKS, total_chunks - start_chunk)
                chunks: 'list[bytes]' = [b''] * block_chunks
                for local in range(block_chunks):
                    global_chunk = start_chunk + local
                    chunk_len = basefwx._an7_chunk_bytes_at(payload_len, basefwx.AN7_CHUNK_SIZE, global_chunk)
                    chunk = basefwx._an7_read_exact(src, chunk_len, 'AN7 failed to read source payload chunk')
                    sha.update(chunk)
                    transformed = basefwx._an7_apply_xor_transform(chunk, keys['stream'], stream_nonce, global_chunk)
                    if local % 2 == 1:
                        flipped = bytearray(transformed)
                        start = basefwx._an7_flip_start(keys['perm'], global_chunk, basefwx.AN7_FLIP_STRIDE)
                        basefwx._an7_apply_sparse_flip(flipped, start, basefwx.AN7_FLIP_STRIDE)
                        transformed = bytes(flipped)
                    chunks[local] = transformed
                order = basefwx._an7_build_permutation(keys['perm'], super_idx, block_chunks)
                for pos in range(block_chunks):
                    dst.write(chunks[order[pos]])
            trailer_info = {'format_version': basefwx.AN7_TRAILER_VERSION.decode('ascii'), 'original_basename': path.stem, 'original_extension': path.suffix, 'original_size': payload_len, 'chunk_size': basefwx.AN7_CHUNK_SIZE, 'superblock_chunks': basefwx.AN7_SUPERBLOCK_CHUNKS, 'flip_stride': basefwx.AN7_FLIP_STRIDE, 'stream_nonce': stream_nonce, 'sha256_original': sha.digest(), 'created_utc': basefwx.datetime.now(basefwx.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
            trailer_plain = basefwx._an7_serialize_trailer(trailer_info)
            trailer_nonce = basefwx.os.urandom(basefwx.AN7_TRAILER_NONCE_LEN)
            trailer_cipher_and_tag = basefwx.AESGCM(keys['meta']).encrypt(trailer_nonce, trailer_plain, None)
            encrypted_trailer = trailer_nonce + trailer_cipher_and_tag
            trailer_len = len(encrypted_trailer)
            trailer_crc32 = basefwx.zlib.crc32(encrypted_trailer) & 4294967295
            dst.write(encrypted_trailer)
            tail_plain = basefwx.struct.pack('<QQI', trailer_len, payload_len, trailer_crc32)
            tail_nonce = basefwx.os.urandom(basefwx.AN7_TAIL_NONCE_LEN)
            tail_cipher_and_tag = basefwx.AESGCM(keys['tail']).encrypt(tail_nonce, tail_plain, None)
            if len(tail_cipher_and_tag) != basefwx.AN7_TAIL_CIPHER_LEN + basefwx.AN7_TAIL_TAG_LEN:
                raise RuntimeError('AN7 tail encrypt produced unexpected length')
            footer = salt + tail_nonce + tail_cipher_and_tag[:basefwx.AN7_TAIL_CIPHER_LEN] + tail_cipher_and_tag[basefwx.AN7_TAIL_CIPHER_LEN:]
            dst.write(footer)
            dst.flush()
        basefwx._an7_commit_temp_file(temp_path, output_path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    basefwx._remove_input(path, keep_input, output_path)
    return str(output_path)


def dean7_file(input_path: 'basefwx.typing.Union[str, basefwx.pathlib.Path]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, out: 'basefwx.typing.Optional[basefwx.typing.Union[str, basefwx.pathlib.Path]]'=None, keep_input: bool=False) -> 'dict[str, basefwx.typing.Any]':
    path = basefwx._normalize_path(input_path)
    basefwx._ensure_existing_file(path)
    resolved_password = basefwx._resolve_password(password, use_master=False)
    pw = basefwx._coerce_password_bytes(resolved_password)
    if not pw:
        raise ValueError('Password is required for dean7')
    file_size = path.stat().st_size
    if file_size < basefwx.AN7_FOOTER_SIZE:
        raise ValueError('Input is too small to be an AN7 file')
    with open(path, 'rb') as src:
        src.seek(file_size - basefwx.AN7_FOOTER_SIZE)
        footer_buf = basefwx._an7_read_exact(src, basefwx.AN7_FOOTER_SIZE, 'Failed to read AN7 footer')
    context = basefwx._an7_parse_footer_and_derive(footer_buf, pw)
    keys = context['keys']
    footer = context['footer']
    trailer_len = int(footer['trailer_len'])
    payload_len = int(footer['payload_len'])
    trailer_crc32 = int(footer['trailer_crc32'])
    if trailer_len < basefwx.AN7_TRAILER_NONCE_LEN + basefwx.AEAD_TAG_LEN or payload_len > file_size or payload_len + trailer_len + basefwx.AN7_FOOTER_SIZE != file_size:
        raise ValueError('AN7 footer length fields are invalid')
    with open(path, 'rb') as src:
        src.seek(payload_len)
        encrypted_trailer = basefwx._an7_read_exact(src, trailer_len, 'Failed to read AN7 encrypted trailer')
    if basefwx.zlib.crc32(encrypted_trailer) & 4294967295 != trailer_crc32:
        raise ValueError('AN7 trailer CRC mismatch')
    trailer_nonce = encrypted_trailer[:basefwx.AN7_TRAILER_NONCE_LEN]
    trailer_cipher_and_tag = encrypted_trailer[basefwx.AN7_TRAILER_NONCE_LEN:]
    trailer_plain = basefwx.AESGCM(keys['meta']).decrypt(trailer_nonce, trailer_cipher_and_tag, None)
    trailer = basefwx._an7_parse_trailer(trailer_plain)
    if int(trailer['chunk_size']) <= 0 or int(trailer['superblock_chunks']) <= 0 or int(trailer['flip_stride']) <= 0 or (len(trailer['stream_nonce']) != basefwx.AN7_TRAILER_NONCE_LEN):
        raise ValueError('AN7 trailer contains invalid transform parameters')
    if int(trailer['original_size']) != payload_len:
        raise ValueError('AN7 payload size mismatch')
    output_path = basefwx._an7_resolve_dean_output_path(path, trailer, out)
    if basefwx._an7_same_path(path, output_path):
        raise ValueError('Output path must differ from input path')
    temp_path = basefwx._an7_make_temp_path(output_path)
    bytes_read = 0
    bytes_written = 0
    sha = basefwx.hashlib.sha256()
    chunk_size = int(trailer['chunk_size'])
    superblock_chunks = int(trailer['superblock_chunks'])
    flip_stride = int(trailer['flip_stride'])
    total_chunks = basefwx._an7_total_chunks(payload_len, chunk_size)
    try:
        with open(path, 'rb') as src, open(temp_path, 'wb') as dst:
            superblocks = basefwx._an7_total_chunks(total_chunks, superblock_chunks)
            for super_idx in range(superblocks):
                start_chunk = super_idx * superblock_chunks
                block_chunks = min(superblock_chunks, total_chunks - start_chunk)
                chunk_sizes = [basefwx._an7_chunk_bytes_at(payload_len, chunk_size, start_chunk + idx) for idx in range(block_chunks)]
                chunks: 'list[bytes]' = [b''] * block_chunks
                order = basefwx._an7_build_permutation(keys['perm'], super_idx, block_chunks)
                for pos in range(block_chunks):
                    original_slot = order[pos]
                    chunk_len = chunk_sizes[original_slot]
                    chunk = basefwx._an7_read_exact(src, chunk_len, 'AN7 payload is truncated')
                    bytes_read += len(chunk)
                    chunks[original_slot] = chunk
                for local in range(block_chunks):
                    global_chunk = start_chunk + local
                    transformed = bytearray(chunks[local])
                    if local % 2 == 1:
                        start = basefwx._an7_flip_start(keys['perm'], global_chunk, flip_stride)
                        basefwx._an7_apply_sparse_flip(transformed, start, flip_stride)
                    clear_chunk = basefwx._an7_apply_xor_transform(bytes(transformed), keys['stream'], trailer['stream_nonce'], global_chunk)
                    sha.update(clear_chunk)
                    dst.write(clear_chunk)
                    bytes_written += len(clear_chunk)
            dst.flush()
        if bytes_read != payload_len or bytes_written != payload_len:
            raise ValueError('AN7 payload length verification failed')
        if sha.digest() != trailer['sha256_original']:
            raise ValueError('AN7 payload hash mismatch')
        basefwx._an7_commit_temp_file(temp_path, output_path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    basefwx._remove_input(path, keep_input, output_path)
    return {'output_path': str(output_path), 'restored_name': output_path.name, 'bytes_written': bytes_written}
