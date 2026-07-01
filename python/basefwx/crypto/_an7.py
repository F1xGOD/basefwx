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

def _an7_read_exact(handle: 'basefwx.typing.BinaryIO', size: int, error: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise ValueError(error)
    return data


def _an7_random_digits10() -> str:
    return f'{basefwx.secrets.randbelow(basefwx.N10_MOD):010d}'


def _an7_same_path(a: 'basefwx.pathlib.Path', b: 'basefwx.pathlib.Path') -> bool:
    return basefwx._normalize_path(a) == basefwx._normalize_path(b)


def _an7_ensure_collision_suffix(path: 'basefwx.pathlib.Path') -> 'basefwx.pathlib.Path':
    if not path.exists():
        return path
    base = str(path)
    idx = 1
    while idx < 1 << 31:
        candidate = basefwx.pathlib.Path(f'{base}.{idx}')
        if not candidate.exists():
            return candidate
        idx += 1
    raise RuntimeError('Unable to resolve output path collision')


def _an7_make_temp_path(final_path: 'basefwx.pathlib.Path') -> 'basefwx.pathlib.Path':
    parent = final_path.parent
    for _ in range(128):
        candidate = parent / f'{final_path.name}.tmp.{basefwx._an7_random_digits10()}'
        if not candidate.exists():
            return candidate
    raise RuntimeError('Failed to allocate temp output file path')


def _an7_commit_temp_file(temp_path: 'basefwx.pathlib.Path', final_path: 'basefwx.pathlib.Path') -> None:
    try:
        basefwx.os.replace(temp_path, final_path)
        return
    except OSError:
        pass
    basefwx.shutil.copy2(str(temp_path), str(final_path))
    try:
        temp_path.unlink()
    except FileNotFoundError:
        pass


def _an7_chunk_bytes_at(payload_len: int, chunk_size: int, chunk_index: int) -> int:
    if payload_len <= 0:
        return 0
    offset = chunk_index * chunk_size
    if offset >= payload_len:
        return 0
    remain = payload_len - offset
    return min(chunk_size, remain)


def _an7_total_chunks(payload_len: int, chunk_size: int) -> int:
    if payload_len <= 0:
        return 0
    return (payload_len + chunk_size - 1) // chunk_size


def _an7_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return basefwx.stdlib_hmac.new(key, data, basefwx.hashlib.sha256).digest()


def _an7_build_label(prefix: bytes, nonce: bytes, index: int) -> bytes:
    return prefix + nonce + basefwx.struct.pack('<Q', index)


def _an7_derive_ctr_iv(stream_key: bytes, stream_nonce: bytes, chunk_index: int) -> bytes:
    label = basefwx._an7_build_label(b'ctr:', stream_nonce, chunk_index)
    digest = basefwx._an7_hmac_sha256(stream_key, label)
    return digest[:16]


def _an7_apply_xor_transform(chunk: bytes, stream_key: bytes, stream_nonce: bytes, chunk_index: int) -> bytes:
    if not chunk:
        return chunk
    iv = basefwx._an7_derive_ctr_iv(stream_key, stream_nonce, chunk_index)
    cipher = basefwx.Cipher(basefwx.algorithms.AES(stream_key), basefwx.modes.CTR(iv))
    enc = cipher.encryptor()
    return enc.update(chunk) + enc.finalize()


def _an7_flip_start(perm_key: bytes, chunk_index: int, stride: int) -> int:
    if stride <= 0:
        return 0
    label = b'flip:' + basefwx.struct.pack('<Q', chunk_index)
    digest = basefwx._an7_hmac_sha256(perm_key, label)
    value = basefwx.struct.unpack_from('<Q', digest, 0)[0]
    return int(value % stride)


def _an7_apply_sparse_flip(chunk: bytearray, start: int, stride: int) -> None:
    if not chunk or stride <= 0:
        return
    for idx in range(start, len(chunk), stride):
        chunk[idx] ^= 255


def _an7_build_permutation(perm_key: bytes, superblock_index: int, count: int) -> 'list[int]':
    order = list(range(count))
    if count <= 1:
        return order
    label = b'perm:' + basefwx.struct.pack('<Q', superblock_index)
    digest = basefwx._an7_hmac_sha256(perm_key, label)
    rng_state = basefwx.struct.unpack_from('<Q', digest, 0)[0]
    for idx in range(count - 1, 0, -1):
        rng_state, rnd = basefwx._splitmix64(rng_state)
        j = rnd % (idx + 1)
        order[idx], order[j] = (order[j], order[idx])
    return order


def _an7_derive_keys(password: bytes, salt: bytes) -> 'dict[str, bytes]':
    if not password:
        raise ValueError('Password is required for AN7')
    if len(salt) != basefwx.AN7_SALT_LEN:
        raise ValueError('Invalid AN7 salt length')
    if basefwx.hash_secret_raw is None:
        raise RuntimeError('AN7 requires Argon2 support in this build')
    root_key, _ = basefwx._derive_user_key_argon2id(password, salt, length=64, time_cost=basefwx.AN7_ARGON2_TIME_COST, memory_cost=basefwx.AN7_ARGON2_MEMORY_COST, parallelism=basefwx.AN7_ARGON2_PARALLELISM)
    return {'stream': basefwx._hkdf_sha256(root_key, info=b'an7-stream', length=32), 'perm': basefwx._hkdf_sha256(root_key, info=b'an7-perm', length=32), 'meta': basefwx._hkdf_sha256(root_key, info=b'an7-meta', length=32), 'tail': basefwx._hkdf_sha256(root_key, info=b'an7-tail', length=32)}


def _an7_serialize_trailer(info: 'dict[str, basefwx.typing.Any]') -> bytes:
    stream_nonce = info['stream_nonce']
    if len(stream_nonce) != basefwx.AN7_TRAILER_NONCE_LEN:
        raise ValueError('AN7 trailer has invalid stream nonce length')
    basename_bytes = info['original_basename'].encode('utf-8')
    extension_bytes = info['original_extension'].encode('utf-8')
    created_bytes = info['created_utc'].encode('utf-8')
    if len(basename_bytes) > 65535 or len(extension_bytes) > 65535 or len(created_bytes) > 64:
        raise ValueError('AN7 trailer metadata is too large')
    payload = bytearray()
    payload += basefwx.AN7_TRAILER_VERSION
    payload += basefwx.struct.pack('<I', int(info['chunk_size']))
    payload += basefwx.struct.pack('<H', int(info['superblock_chunks']))
    payload += basefwx.struct.pack('<H', int(info['flip_stride']))
    payload += basefwx.struct.pack('<Q', int(info['original_size']))
    payload += basefwx.struct.pack('<H', len(created_bytes))
    payload += created_bytes
    payload += stream_nonce
    payload += info['sha256_original']
    payload += basefwx.struct.pack('<H', len(basename_bytes))
    payload += basename_bytes
    payload += basefwx.struct.pack('<H', len(extension_bytes))
    payload += extension_bytes
    return bytes(payload)


def _an7_parse_trailer(data: bytes) -> 'dict[str, basefwx.typing.Any]':
    min_len = len(basefwx.AN7_TRAILER_VERSION) + 4 + 2 + 2 + 8 + 2 + basefwx.AN7_TRAILER_NONCE_LEN + basefwx.AN7_SHA256_LEN + 2 + 2
    if len(data) < min_len:
        raise ValueError('AN7 trailer is too short')
    if not data.startswith(basefwx.AN7_TRAILER_VERSION):
        raise ValueError('AN7 trailer version mismatch')
    offset = len(basefwx.AN7_TRAILER_VERSION)

    def read_u16() -> int:
        nonlocal offset
        if offset + 2 > len(data):
            raise ValueError('AN7 trailer is truncated (u16)')
        value = basefwx.struct.unpack_from('<H', data, offset)[0]
        offset += 2
        return value

    def read_u32() -> int:
        nonlocal offset
        if offset + 4 > len(data):
            raise ValueError('AN7 trailer is truncated (u32)')
        value = basefwx.struct.unpack_from('<I', data, offset)[0]
        offset += 4
        return value

    def read_u64() -> int:
        nonlocal offset
        if offset + 8 > len(data):
            raise ValueError('AN7 trailer is truncated (u64)')
        value = basefwx.struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        return value
    chunk_size = read_u32()
    superblock_chunks = read_u16()
    flip_stride = read_u16()
    original_size = read_u64()
    created_len = read_u16()
    if created_len > 64 or offset + created_len > len(data):
        raise ValueError('AN7 trailer created timestamp is invalid')
    created_utc = data[offset:offset + created_len].decode('utf-8', errors='strict')
    offset += created_len
    if offset + basefwx.AN7_TRAILER_NONCE_LEN + basefwx.AN7_SHA256_LEN > len(data):
        raise ValueError('AN7 trailer payload is truncated')
    stream_nonce = data[offset:offset + basefwx.AN7_TRAILER_NONCE_LEN]
    offset += basefwx.AN7_TRAILER_NONCE_LEN
    sha256_original = data[offset:offset + basefwx.AN7_SHA256_LEN]
    offset += basefwx.AN7_SHA256_LEN
    basename_len = read_u16()
    if offset + basename_len > len(data):
        raise ValueError('AN7 trailer basename is truncated')
    original_basename = data[offset:offset + basename_len].decode('utf-8', errors='strict')
    offset += basename_len
    ext_len = read_u16()
    if offset + ext_len > len(data):
        raise ValueError('AN7 trailer extension is truncated')
    original_extension = data[offset:offset + ext_len].decode('utf-8', errors='strict')
    offset += ext_len
    if offset != len(data):
        raise ValueError('AN7 trailer has trailing bytes')
    return {'format_version': basefwx.AN7_TRAILER_VERSION.decode('ascii'), 'chunk_size': chunk_size, 'superblock_chunks': superblock_chunks, 'flip_stride': flip_stride, 'original_size': original_size, 'created_utc': created_utc, 'stream_nonce': stream_nonce, 'sha256_original': sha256_original, 'original_basename': original_basename, 'original_extension': original_extension}


def _an7_parse_footer_and_derive(footer: bytes, password: bytes) -> 'dict[str, basefwx.typing.Any]':
    if len(footer) != basefwx.AN7_FOOTER_SIZE:
        raise ValueError('AN7 footer length mismatch')
    salt = footer[:basefwx.AN7_SALT_LEN]
    tail_nonce = footer[basefwx.AN7_SALT_LEN:basefwx.AN7_SALT_LEN + basefwx.AN7_TAIL_NONCE_LEN]
    tail_blob = footer[basefwx.AN7_SALT_LEN + basefwx.AN7_TAIL_NONCE_LEN:]
    keys = basefwx._an7_derive_keys(password, salt)
    tail_plain = basefwx.AESGCM(keys['tail']).decrypt(tail_nonce, tail_blob, None)
    if len(tail_plain) != basefwx.AN7_TAIL_PLAIN_LEN:
        raise ValueError('AN7 footer tail length mismatch')
    trailer_len, payload_len, trailer_crc32 = basefwx.struct.unpack('<QQI', tail_plain)
    return {'keys': keys, 'footer': {'salt': salt, 'tail_nonce': tail_nonce, 'trailer_len': int(trailer_len), 'payload_len': int(payload_len), 'trailer_crc32': int(trailer_crc32)}}


def _an7_is_ascii_alnum(ch: str) -> bool:
    return '0' <= ch <= '9' or 'a' <= ch <= 'z' or 'A' <= ch <= 'Z'


def _an7_sanitize_basename(value: str) -> str:
    chars = []
    for ch in value:
        if ch == '/' or ch == '\\' or ord(ch) < 32:
            chars.append('_')
        else:
            chars.append(ch)
    out = ''.join(chars)
    return out if out else 'data'


def _an7_sanitize_extension(value: str) -> str:
    if not value:
        return ''
    ext = value if value.startswith('.') else '.' + value
    chars = []
    for ch in ext:
        if ch == '.':
            chars.append(ch)
        elif basefwx._an7_is_ascii_alnum(ch) or ch in '_-':
            chars.append(ch)
        else:
            chars.append('_')
    return ''.join(chars)


def _an7_resolve_output_path(input_path: 'basefwx.pathlib.Path', out: 'basefwx.typing.Optional[basefwx.typing.Union[str, basefwx.pathlib.Path]]') -> 'basefwx.pathlib.Path':
    if out is not None:
        desired = basefwx._normalize_path(out)
        if desired.exists() and desired.is_dir():
            desired = desired / f'data{basefwx._an7_random_digits10()}'
    else:
        desired = input_path.parent / f'data{basefwx._an7_random_digits10()}'
    desired = basefwx._an7_ensure_collision_suffix(desired)
    desired.parent.mkdir(parents=True, exist_ok=True)
    return desired


def _an7_resolve_restored_name(trailer: 'dict[str, basefwx.typing.Any]') -> str:
    base = basefwx._an7_sanitize_basename(trailer.get('original_basename', ''))
    ext = basefwx._an7_sanitize_extension(trailer.get('original_extension', ''))
    name = f'{base}{ext}'
    return name if name else 'dean7.out'


def _an7_resolve_dean_output_path(input_path: 'basefwx.pathlib.Path', trailer: 'dict[str, basefwx.typing.Any]', out: 'basefwx.typing.Optional[basefwx.typing.Union[str, basefwx.pathlib.Path]]') -> 'basefwx.pathlib.Path':
    restored_name = basefwx._an7_resolve_restored_name(trailer)
    if out is not None:
        desired = basefwx._normalize_path(out)
        if desired.exists() and desired.is_dir():
            desired = desired / restored_name
    else:
        desired = input_path.parent / restored_name
    desired = basefwx._an7_ensure_collision_suffix(desired)
    desired.parent.mkdir(parents=True, exist_ok=True)
    return desired
