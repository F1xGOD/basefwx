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


def _serialize_plugin_tag(plugin_id: bytes, position: int, config: bytes) -> bytes:
    if len(plugin_id) != basefwx.FWXAES_PLUGIN_ID_LEN:
        raise ValueError('plugin id must be 16 bytes')
    cfg = bytes(config or b'')
    if len(cfg) > basefwx.FWXAES_PLUGIN_MAX_CONFIG_LEN:
        raise ValueError('plugin config exceeds maximum')
    return (
        plugin_id
        + bytes([position])
        + basefwx.struct.pack('>H', len(cfg))
        + cfg
    )


def _parse_plugin_tag(blob_bytes: bytes, offset: int):
    fixed = basefwx.FWXAES_PLUGIN_TAG_FIXED_LEN
    if len(blob_bytes) < offset + fixed:
        raise ValueError('fwxAES plugin tag truncated')
    plugin_id = blob_bytes[offset:offset + basefwx.FWXAES_PLUGIN_ID_LEN]
    position = blob_bytes[offset + basefwx.FWXAES_PLUGIN_ID_LEN]
    cfg_len = basefwx.struct.unpack(
        '>H',
        blob_bytes[offset + basefwx.FWXAES_PLUGIN_ID_LEN + 1:offset + fixed],
    )[0]
    if cfg_len > basefwx.FWXAES_PLUGIN_MAX_CONFIG_LEN:
        raise ValueError('plugin config length exceeds maximum')
    end = offset + fixed + cfg_len
    if len(blob_bytes) < end:
        raise ValueError('fwxAES plugin tag truncated')
    config = blob_bytes[offset + fixed:end]
    return plugin_id, position, config, end - offset


def _load_plugin_from_tag(plugin_id: bytes, config: bytes):
    from .plugin import factory_for

    entry = factory_for(plugin_id)
    if entry is not None:
        return entry.factory(config), None
    raise ValueError('fwxAES plugin not available for blob tag')


def _assemble_raw_blob(algo, kdf, salt_len_field, iv_len, field0, ct_len, plugin_tag, header_payload, iv, ct):
    header = bytearray()
    header += basefwx.FWXAES_MAGIC
    header += bytes([algo, kdf, salt_len_field, iv_len])
    header += basefwx.struct.pack('>I', field0)
    header += basefwx.struct.pack('>I', ct_len)
    return bytes(header) + plugin_tag + header_payload + iv + ct


def fwxAES_encrypt_raw(plaintext: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, plugin=None, plugin_position=None, plugin_config: bytes=b'') -> bytes:
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError('fwxAES_encrypt_raw expects bytes')
    password = basefwx._resolve_password(password, use_master=use_master)
    pw = basefwx._coerce_password_bytes(password)
    use_plugin = plugin is not None and plugin_position is not None
    work_plaintext = bytes(plaintext)
    plugin_tag = b''
    if use_plugin:
        from .plugin import Position

        pos_flag = int(plugin_position)
        if (getattr(plugin, 'SUPPORTED_POSITIONS', 0) & pos_flag) == 0:
            raise ValueError('plugin does not support requested position')
        plugin_id = plugin.plugin_id() if hasattr(plugin, 'plugin_id') else plugin.PLUGIN_ID
        plugin_tag = _serialize_plugin_tag(plugin_id, pos_flag, plugin_config)
        if pos_flag == Position.PRE_AEAD:
            work_plaintext = plugin.forward(work_plaintext)
    algo = basefwx.FWXAES_ALGO_PLUGIN if use_plugin else basefwx.FWXAES_ALGO
    use_wrap = False
    key_header = b''
    mask_key = b''
    if use_master:
        try:
            mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(password, use_master, mask_info=basefwx.FWXAES_MASK_INFO, require_password=False, aad=basefwx.FWXAES_AAD)
            use_wrap = use_master_effective or not pw
            if use_wrap:
                key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
        except Exception:
            if not pw:
                raise
            use_wrap = False
    iv = basefwx.os.urandom(basefwx.FWXAES_IV_LEN)
    if use_wrap:
        header_len = len(key_header)
        if header_len > 4294967295:
            raise ValueError('fwxAES key header too large')
        key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
    else:
        salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
        iters = basefwx._fwxaes_iterations(pw)
        key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
    aesgcm = basefwx.AESGCM(key)
    ct = aesgcm.encrypt(iv, work_plaintext, basefwx.FWXAES_AAD)
    if use_plugin:
        from .plugin import Position

        if int(plugin_position) == Position.POST_AEAD:
            ct = plugin.forward(ct)
    if use_wrap:
        return _assemble_raw_blob(
            algo,
            basefwx.FWXAES_KDF_WRAP,
            0,
            basefwx.FWXAES_IV_LEN,
            header_len,
            len(ct),
            plugin_tag,
            key_header,
            iv,
            ct,
        )
    return _assemble_raw_blob(
        algo,
        basefwx.FWXAES_KDF_PBKDF2,
        basefwx.FWXAES_SALT_LEN,
        basefwx.FWXAES_IV_LEN,
        iters,
        len(ct),
        plugin_tag,
        salt,
        iv,
        ct,
    )


def fwxAES_decrypt_raw(blob: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, plugin=None) -> bytes:
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError('fwxAES_decrypt_raw expects bytes')
    password = basefwx._resolve_password(password, use_master=use_master)
    blob_bytes = bytes(blob)
    header_len = 4 + 1 + 1 + 1 + 1 + 4 + 4
    if len(blob_bytes) < header_len:
        raise ValueError('fwxAES blob too short')
    if blob_bytes[:4] != basefwx.FWXAES_MAGIC:
        raise ValueError('fwxAES bad magic')
    algo, kdf, salt_len, iv_len = (blob_bytes[4], blob_bytes[5], blob_bytes[6], blob_bytes[7])
    if algo not in (basefwx.FWXAES_ALGO, basefwx.FWXAES_ALGO_PLUGIN) or kdf not in (basefwx.FWXAES_KDF_PBKDF2, basefwx.FWXAES_KDF_WRAP):
        raise ValueError('fwxAES unsupported algo/kdf')
    iters = basefwx.struct.unpack('>I', blob_bytes[8:12])[0]
    ct_len = basefwx.struct.unpack('>I', blob_bytes[12:16])[0]
    off = 16
    plugin_obj = plugin
    plugin_position = 0
    if algo == basefwx.FWXAES_ALGO_PLUGIN:
        plugin_id, plugin_position, plugin_config, tag_len = _parse_plugin_tag(blob_bytes, off)
        off += tag_len
        if plugin_obj is None:
            plugin_obj, _ = _load_plugin_from_tag(plugin_id, plugin_config)
        elif hasattr(plugin_obj, 'plugin_id'):
            if plugin_obj.plugin_id() != plugin_id:
                raise ValueError('loaded plugin id does not match blob tag')
        elif getattr(plugin_obj, 'PLUGIN_ID', b'') != plugin_id:
            raise ValueError('loaded plugin id does not match blob tag')

    def _finish_plaintext(plain: bytes) -> bytes:
        if algo != basefwx.FWXAES_ALGO_PLUGIN:
            return plain
        from .plugin import Position

        if plugin_position == Position.PRE_AEAD:
            return plugin_obj.inverse(plain)
        return plain

    if kdf == basefwx.FWXAES_KDF_WRAP:
        header_len = iters
        if len(blob_bytes) < off + header_len + iv_len + ct_len:
            raise ValueError('fwxAES blob truncated')
        header = blob_bytes[off:off + header_len]
        off += header_len
        iv = blob_bytes[off:off + iv_len]
        off += iv_len
        ct = blob_bytes[off:off + ct_len]
        if algo == basefwx.FWXAES_ALGO_PLUGIN:
            from .plugin import Position

            if plugin_position == Position.POST_AEAD:
                ct = plugin_obj.inverse(ct)
        user_blob, master_blob = basefwx._unpack_length_prefixed(header, 2)
        mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, use_master, mask_info=basefwx.FWXAES_MASK_INFO, aad=basefwx.FWXAES_AAD)
        key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
        aesgcm = basefwx.AESGCM(key)
        return _finish_plaintext(aesgcm.decrypt(iv, ct, basefwx.FWXAES_AAD))
    if len(blob_bytes) < off + salt_len + iv_len + ct_len:
        raise ValueError('fwxAES blob truncated')
    salt = blob_bytes[off:off + salt_len]
    off += salt_len
    iv = blob_bytes[off:off + iv_len]
    off += iv_len
    ct = blob_bytes[off:off + ct_len]
    if algo == basefwx.FWXAES_ALGO_PLUGIN:
        from .plugin import Position

        if plugin_position == Position.POST_AEAD:
            ct = plugin_obj.inverse(ct)
    pw = basefwx._coerce_password_bytes(password)
    if not pw:
        raise ValueError('fwxAES password required for PBKDF2 payload')
    key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
    aesgcm = basefwx.AESGCM(key)
    return _finish_plaintext(aesgcm.decrypt(iv, ct, basefwx.FWXAES_AAD))


def fwxAES_encrypt_stream(source, dest, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    password = basefwx._resolve_password(password, use_master=use_master)
    pw = basefwx._coerce_password_bytes(password)
    chunk = basefwx.STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))

    def _encrypt_to(handle) -> int:
        use_wrap = False
        key_header = b''
        mask_key = b''
        if use_master:
            try:
                mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(password, use_master, mask_info=basefwx.FWXAES_MASK_INFO, require_password=False, aad=basefwx.FWXAES_AAD)
                use_wrap = use_master_effective or not pw
                if use_wrap:
                    key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
            except Exception:
                if not pw:
                    raise
                use_wrap = False
        iv = basefwx.os.urandom(basefwx.FWXAES_IV_LEN)
        header = bytearray()
        header += basefwx.FWXAES_MAGIC
        ct_len = 0
        if use_wrap:
            header_len = len(key_header)
            if header_len > 4294967295:
                raise ValueError('fwxAES key header too large')
            key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
            header += bytes([basefwx.FWXAES_ALGO, basefwx.FWXAES_KDF_WRAP, 0, basefwx.FWXAES_IV_LEN])
            header += basefwx.struct.pack('>I', header_len)
            header += basefwx.struct.pack('>I', 0)
            handle.write(header)
            handle.write(key_header)
            handle.write(iv)
        else:
            if not pw and (not use_master):
                raise ValueError('Password required when master key usage is disabled')
            salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
            iters = basefwx._fwxaes_iterations(pw)
            key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
            header += bytes([basefwx.FWXAES_ALGO, basefwx.FWXAES_KDF_PBKDF2, basefwx.FWXAES_SALT_LEN, basefwx.FWXAES_IV_LEN])
            header += basefwx.struct.pack('>I', iters)
            header += basefwx.struct.pack('>I', 0)
            handle.write(header)
            handle.write(salt)
            handle.write(iv)
        encryptor = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(basefwx.FWXAES_AAD)
        while True:
            buf = source.read(chunk)
            if not buf:
                break
            ct = encryptor.update(buf)
            if ct:
                handle.write(ct)
                ct_len += len(ct)
        tail = encryptor.finalize()
        if tail:
            handle.write(tail)
            ct_len += len(tail)
        handle.write(encryptor.tag)
        ct_len += len(encryptor.tag)
        handle.flush()
        handle.seek(12)
        handle.write(basefwx.struct.pack('>I', ct_len))
        handle.seek(0, basefwx.os.SEEK_END)
        return ct_len
    if basefwx._is_seekable(dest):
        return _encrypt_to(dest)
    tmp = basefwx.tempfile.NamedTemporaryFile('w+b', delete=False)
    try:
        ct_len = _encrypt_to(tmp)
        tmp.seek(0)
        basefwx.shutil.copyfileobj(tmp, dest)
        return ct_len
    finally:
        tmp.close()
        try:
            basefwx.os.remove(tmp.name)
        except FileNotFoundError:
            pass


def fwxAES_decrypt_stream(source, dest, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    password = basefwx._resolve_password(password, use_master=use_master)
    chunk = basefwx.STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))

    def _decrypt_from(handle) -> int:
        header = handle.read(16)
        if len(header) < 16:
            raise ValueError('fwxAES blob too short')
        if header[:4] != basefwx.FWXAES_MAGIC:
            raise ValueError('fwxAES bad magic')
        algo, kdf, salt_len, iv_len = (header[4], header[5], header[6], header[7])
        if algo != basefwx.FWXAES_ALGO or kdf not in (basefwx.FWXAES_KDF_PBKDF2, basefwx.FWXAES_KDF_WRAP):
            raise ValueError('fwxAES unsupported algo/kdf')
        iters = basefwx.struct.unpack('>I', header[8:12])[0]
        ct_len = basefwx.struct.unpack('>I', header[12:16])[0]
        if ct_len < basefwx.AEAD_TAG_LEN:
            raise ValueError('fwxAES ciphertext too short')
        if kdf == basefwx.FWXAES_KDF_WRAP:
            header_len = iters
            key_header = handle.read(header_len)
            if len(key_header) != header_len:
                raise ValueError('fwxAES blob truncated')
            iv = handle.read(iv_len)
            if len(iv) != iv_len:
                raise ValueError('fwxAES blob truncated')
            user_blob, master_blob = basefwx._unpack_length_prefixed(key_header, 2)
            mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, use_master, mask_info=basefwx.FWXAES_MASK_INFO, aad=basefwx.FWXAES_AAD)
            key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
        else:
            salt = handle.read(salt_len)
            if len(salt) != salt_len:
                raise ValueError('fwxAES blob truncated')
            iv = handle.read(iv_len)
            if len(iv) != iv_len:
                raise ValueError('fwxAES blob truncated')
            pw = basefwx._coerce_password_bytes(password)
            if not pw:
                raise ValueError('fwxAES password required for PBKDF2 payload')
            key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        ct_start = handle.tell()
        tag_pos = ct_start + ct_len - basefwx.AEAD_TAG_LEN
        handle.seek(tag_pos)
        tag = handle.read(basefwx.AEAD_TAG_LEN)
        if len(tag) != basefwx.AEAD_TAG_LEN:
            raise ValueError('fwxAES blob truncated')
        decryptor = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.GCM(iv, tag)).decryptor()
        decryptor.authenticate_additional_data(basefwx.FWXAES_AAD)
        handle.seek(ct_start)
        remaining = ct_len - basefwx.AEAD_TAG_LEN
        written = 0
        while remaining > 0:
            buf = handle.read(min(chunk, remaining))
            if not buf:
                raise ValueError('fwxAES blob truncated')
            remaining -= len(buf)
            plain = decryptor.update(buf)
            if plain:
                dest.write(plain)
                written += len(plain)
        try:
            tail = decryptor.finalize()
        except Exception as exc:
            raise ValueError('AES-GCM auth failed') from exc
        if tail:
            dest.write(tail)
            written += len(tail)
        return written
    if basefwx._is_seekable(source):
        return _decrypt_from(source)
    tmp = basefwx.tempfile.NamedTemporaryFile('w+b', delete=False)
    try:
        basefwx.shutil.copyfileobj(source, tmp)
        tmp.flush()
        tmp.seek(0)
        return _decrypt_from(tmp)
    finally:
        tmp.close()
        try:
            basefwx.os.remove(tmp.name)
        except FileNotFoundError:
            pass


def _live_nonce(prefix: bytes, sequence: int) -> bytes:
    if len(prefix) != basefwx.LIVE_NONCE_PREFIX_LEN:
        raise ValueError('Invalid live nonce prefix')
    if sequence < 0 or sequence >= 1 << 64:
        raise ValueError('Live stream sequence overflow')
    return prefix + sequence.to_bytes(8, 'big')


def _live_aad(frame_type: int, sequence: int, plain_len: int) -> bytes:
    if plain_len < 0:
        raise ValueError('Invalid live frame length')
    return basefwx.struct.pack('>4sBBQI', basefwx.LIVE_FRAME_MAGIC, basefwx.LIVE_FRAME_VERSION, frame_type & 255, sequence & (1 << 64) - 1, plain_len & 4294967295)


def _live_pack_frame(frame_type: int, sequence: int, body: bytes) -> bytes:
    if len(body) > 4294967295:
        raise ValueError('Live frame body too large')
    header = basefwx.LIVE_FRAME_HEADER_STRUCT.pack(basefwx.LIVE_FRAME_MAGIC, basefwx.LIVE_FRAME_VERSION, frame_type & 255, sequence & (1 << 64) - 1, len(body))
    return header + body


class LiveEncryptor:
    """Packetized live AEAD encryptor for arbitrary byte streams."""

    def __init__(self, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True) -> None:
        self._password = basefwx._resolve_password(password, use_master=use_master)
        self._use_master = bool(use_master)
        self._started = False
        self._finalized = False
        self._sequence = 1
        self._key = b''
        self._nonce_prefix = b''
        self._aead = None

    def _init_session(self) -> bytes:
        pw = basefwx._coerce_password_bytes(self._password)
        key_mode = basefwx.LIVE_KEYMODE_PBKDF2
        key_header = b''
        salt = b''
        iters = 0
        mask_key = b''
        use_wrap = False
        if self._use_master:
            try:
                mask_key, user_blob, master_blob, use_master_effective = basefwx._prepare_mask_key(self._password, self._use_master, mask_info=basefwx.FWXAES_MASK_INFO, require_password=False, aad=basefwx.FWXAES_AAD)
                use_wrap = use_master_effective or not pw
                if use_wrap:
                    key_header = basefwx._pack_length_prefixed(user_blob, master_blob)
            except Exception:
                if not pw:
                    raise
                use_wrap = False
        if use_wrap:
            key_mode = basefwx.LIVE_KEYMODE_WRAP
            self._key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
        else:
            if not pw:
                raise ValueError('Password required when live stream master key wrapping is disabled')
            salt = basefwx.os.urandom(basefwx.FWXAES_SALT_LEN)
            iters = basefwx._fwxaes_iterations(pw)
            self._key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        self._aead = basefwx.AESGCM(self._key)
        self._nonce_prefix = basefwx.os.urandom(basefwx.LIVE_NONCE_PREFIX_LEN)
        body = basefwx.LIVE_HEADER_STRUCT.pack(key_mode, len(salt), len(self._nonce_prefix), 0, len(key_header), iters) + key_header + salt + self._nonce_prefix
        return basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_HEADER, 0, body)

    def start(self) -> bytes:
        if self._started:
            raise ValueError('LiveEncryptor already started')
        if self._finalized:
            raise ValueError('LiveEncryptor already finalized')
        frame = self._init_session()
        self._started = True
        return frame

    def update(self, chunk: bytes) -> bytes:
        if not self._started:
            raise ValueError('LiveEncryptor.start() must be called before update()')
        if self._finalized:
            raise ValueError('LiveEncryptor already finalized')
        payload = memoryview(chunk)
        payload_len = payload.nbytes
        if payload_len == 0:
            return b''
        nonce = basefwx._live_nonce(self._nonce_prefix, self._sequence)
        aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_DATA, self._sequence, payload_len)
        aead = self._aead if self._aead is not None else basefwx.AESGCM(self._key)
        self._aead = aead
        ct = aead.encrypt(nonce, payload, aad)
        body = basefwx.struct.pack('>I', payload_len) + ct
        frame = basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_DATA, self._sequence, body)
        self._sequence += 1
        return frame

    def finalize(self) -> bytes:
        if not self._started:
            raise ValueError('LiveEncryptor.start() must be called before finalize()')
        if self._finalized:
            raise ValueError('LiveEncryptor already finalized')
        nonce = basefwx._live_nonce(self._nonce_prefix, self._sequence)
        aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_FIN, self._sequence, 0)
        aead = self._aead if self._aead is not None else basefwx.AESGCM(self._key)
        self._aead = aead
        fin_blob = aead.encrypt(nonce, b'', aad)
        frame = basefwx._live_pack_frame(basefwx.LIVE_FRAME_TYPE_FIN, self._sequence, fin_blob)
        self._sequence += 1
        self._finalized = True
        return frame


class LiveDecryptor:
    """Incremental parser/decryptor for packetized live AEAD frames."""

    def __init__(self, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True) -> None:
        self._password = basefwx._resolve_password(password, use_master=use_master)
        self._use_master = bool(use_master)
        self._buffer = bytearray()
        self._buffer_offset = 0
        self._started = False
        self._finished = False
        self._expected_sequence = 0
        self._key = b''
        self._nonce_prefix = b''
        self._aead = None

    def _parse_header(self, data: bytearray, body_off: int, body_len: int) -> None:
        fixed_len = basefwx.LIVE_HEADER_STRUCT.size
        if body_len < fixed_len:
            raise ValueError('Truncated live stream header')
        key_mode, salt_len, nonce_len, _reserved, key_header_len, iters = basefwx.LIVE_HEADER_STRUCT.unpack_from(data, body_off)
        offset = body_off + fixed_len
        need = fixed_len + key_header_len + salt_len + nonce_len
        if body_len != need:
            raise ValueError('Invalid live stream header length')
        key_header = bytes(data[offset:offset + key_header_len])
        offset += key_header_len
        salt = bytes(data[offset:offset + salt_len])
        offset += salt_len
        nonce_prefix = bytes(data[offset:offset + nonce_len])
        if len(nonce_prefix) != basefwx.LIVE_NONCE_PREFIX_LEN:
            raise ValueError('Invalid live stream nonce prefix')
        if key_mode == basefwx.LIVE_KEYMODE_WRAP:
            if not key_header:
                raise ValueError('Missing live key header')
            user_blob, master_blob = basefwx._unpack_length_prefixed(key_header, 2)
            mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, self._password, self._use_master, mask_info=basefwx.FWXAES_MASK_INFO, aad=basefwx.FWXAES_AAD)
            key = basefwx._hkdf_sha256(mask_key, info=basefwx.FWXAES_KEY_INFO, length=basefwx.FWXAES_KEY_LEN)
        elif key_mode == basefwx.LIVE_KEYMODE_PBKDF2:
            pw = basefwx._coerce_password_bytes(self._password)
            if not pw:
                raise ValueError('Password required for PBKDF2 live stream')
            if not salt:
                raise ValueError('Missing live stream PBKDF2 salt')
            if iters <= 0:
                raise ValueError('Invalid live stream PBKDF2 iterations')
            key = basefwx._kdf_pbkdf2_raw(pw, salt, iters)
        else:
            raise ValueError('Unsupported live key mode')
        self._key = key
        self._aead = basefwx.AESGCM(key)
        self._nonce_prefix = nonce_prefix
        self._started = True
        self._expected_sequence = 1

    def _decrypt_data_frame(self, sequence: int, data: bytearray, body_off: int, body_len: int) -> bytes:
        if body_len < 4 + basefwx.AEAD_TAG_LEN:
            raise ValueError('Truncated live data frame')
        plain_len = basefwx.struct.unpack_from('>I', data, body_off)[0]
        ct_off = body_off + 4
        ct_len = body_len - 4
        if plain_len != ct_len - basefwx.AEAD_TAG_LEN:
            raise ValueError('Live frame length mismatch')
        nonce = basefwx._live_nonce(self._nonce_prefix, sequence)
        aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_DATA, sequence, plain_len)
        try:
            aead = self._aead if self._aead is not None else basefwx.AESGCM(self._key)
            self._aead = aead
            plain = aead.decrypt(nonce, memoryview(data)[ct_off:ct_off + ct_len], aad)
        except Exception as exc:
            raise ValueError('Live frame authentication failed') from exc
        if len(plain) != plain_len:
            raise ValueError('Live frame length mismatch')
        return plain

    def _decrypt_fin_frame(self, sequence: int, data: bytearray, body_off: int, body_len: int) -> None:
        if body_len < basefwx.AEAD_TAG_LEN:
            raise ValueError('Truncated live FIN frame')
        nonce = basefwx._live_nonce(self._nonce_prefix, sequence)
        aad = basefwx._live_aad(basefwx.LIVE_FRAME_TYPE_FIN, sequence, 0)
        try:
            aead = self._aead if self._aead is not None else basefwx.AESGCM(self._key)
            self._aead = aead
            plain = aead.decrypt(nonce, memoryview(data)[body_off:body_off + body_len], aad)
        except Exception as exc:
            raise ValueError('Live FIN authentication failed') from exc
        if plain:
            raise ValueError('Live FIN frame carries unexpected payload')
        self._finished = True

    def update(self, data: bytes) -> 'list[bytes]':
        if self._finished and data:
            raise ValueError('Live stream already finalized')
        if data:
            self._buffer.extend(data)
        outputs: 'list[bytes]' = []
        header_len = basefwx.LIVE_FRAME_HEADER_STRUCT.size
        buf = self._buffer
        buf_len = len(buf)
        offset = self._buffer_offset
        while buf_len - offset >= header_len:
            magic, version, frame_type, sequence, body_len = basefwx.LIVE_FRAME_HEADER_STRUCT.unpack_from(buf, offset)
            if magic != basefwx.LIVE_FRAME_MAGIC:
                raise ValueError('Invalid live frame magic')
            if version != basefwx.LIVE_FRAME_VERSION:
                raise ValueError('Unsupported live frame version')
            if body_len > basefwx.KFM_MAX_PAYLOAD:
                raise ValueError('Live frame too large')
            frame_len = header_len + body_len
            if buf_len - offset < frame_len:
                break
            body_off = offset + header_len
            if not self._started:
                if frame_type != basefwx.LIVE_FRAME_TYPE_HEADER or sequence != 0:
                    raise ValueError('Live stream must start with header frame')
                self._parse_header(buf, body_off, body_len)
            else:
                if sequence != self._expected_sequence:
                    raise ValueError('Live frame sequence mismatch')
                if frame_type == basefwx.LIVE_FRAME_TYPE_DATA:
                    plain = self._decrypt_data_frame(sequence, buf, body_off, body_len)
                    if plain:
                        outputs.append(plain)
                elif frame_type == basefwx.LIVE_FRAME_TYPE_FIN:
                    self._decrypt_fin_frame(sequence, buf, body_off, body_len)
                else:
                    raise ValueError('Unexpected live frame type')
                self._expected_sequence += 1
            offset += frame_len
        self._buffer_offset = offset
        if self._buffer_offset:
            if self._buffer_offset == buf_len:
                self._buffer.clear()
                self._buffer_offset = 0
            elif self._buffer_offset >= 1 << 20 or self._buffer_offset * 2 >= buf_len:
                del self._buffer[:self._buffer_offset]
                self._buffer_offset = 0
        return outputs

    def finalize(self) -> None:
        if not self._started:
            raise ValueError('Missing live stream header frame')
        if not self._finished:
            raise ValueError('Live stream ended without FIN frame')
        if len(self._buffer) > self._buffer_offset:
            raise ValueError('Trailing bytes after live stream FIN')


def fwxAES_live_encrypt_chunks(chunks: 'basefwx.typing.Iterable[bytes]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True) -> 'list[bytes]':
    encryptor = basefwx.LiveEncryptor(password, use_master=use_master)
    out: 'list[bytes]' = [encryptor.start()]
    for chunk in chunks:
        frame = encryptor.update(bytes(chunk))
        if frame:
            out.append(frame)
    out.append(encryptor.finalize())
    return out


def fwxAES_live_decrypt_chunks(chunks: 'basefwx.typing.Iterable[bytes]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True) -> 'list[bytes]':
    decryptor = basefwx.LiveDecryptor(password, use_master=use_master)
    out: 'list[bytes]' = []
    for chunk in chunks:
        out.extend(decryptor.update(bytes(chunk)))
    decryptor.finalize()
    return out


def fwxAES_live_encrypt_stream(source, dest, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    encryptor = basefwx.LiveEncryptor(password, use_master=use_master)
    total = 0
    first = encryptor.start()
    dest.write(first)
    total += len(first)
    chunk = basefwx.LIVE_STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))
    readinto = getattr(source, 'readinto', None)
    if callable(readinto):
        buf = bytearray(chunk)
        view = memoryview(buf)
        while True:
            size = readinto(view)
            if not size:
                break
            frame = encryptor.update(view[:size])
            if frame:
                dest.write(frame)
                total += len(frame)
    else:
        while True:
            buf = source.read(chunk)
            if not buf:
                break
            frame = encryptor.update(buf)
            if frame:
                dest.write(frame)
                total += len(frame)
    final = encryptor.finalize()
    dest.write(final)
    total += len(final)
    try:
        dest.flush()
    except Exception:
        pass
    return total


def fwxAES_live_decrypt_stream(source, dest, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    decryptor = basefwx.LiveDecryptor(password, use_master=use_master)
    chunk = basefwx.LIVE_STREAM_CHUNK_SIZE if chunk_size is None else max(1, int(chunk_size))
    written = 0
    readinto = getattr(source, 'readinto', None)
    if callable(readinto):
        buf = bytearray(chunk)
        view = memoryview(buf)
        while True:
            size = readinto(view)
            if not size:
                break
            for plain in decryptor.update(view[:size]):
                dest.write(plain)
                written += len(plain)
    else:
        while True:
            buf = source.read(chunk)
            if not buf:
                break
            for plain in decryptor.update(buf):
                dest.write(plain)
                written += len(plain)
    decryptor.finalize()
    try:
        dest.flush()
    except Exception:
        pass
    return written


def fwxAES_live_encrypt_ffmpeg(source_cmd: 'basefwx.typing.Sequence[str]', encrypted_dest, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    if not source_cmd:
        raise ValueError('source_cmd must not be empty')
    cmd = [str(part) for part in source_cmd]
    hw_plan = basefwx.MediaCipher._build_hw_execution_plan('fwxAES_live_encrypt_ffmpeg', stream_type='live', prefer_cpu_decode=True)
    basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
    dest_handle = None
    close_dest = False
    if basefwx._is_pathlike_target(encrypted_dest):
        dest_handle = open(basefwx.pathlib.Path(encrypted_dest), 'wb')
        close_dest = True
    elif hasattr(encrypted_dest, 'write'):
        dest_handle = encrypted_dest
    else:
        raise TypeError('encrypted_dest must be a writable stream or filesystem path')
    proc = basefwx.subprocess.Popen(cmd, stdin=basefwx.subprocess.DEVNULL, stdout=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE)
    stderr_parts: 'list[bytes]' = []
    stderr_thread = None
    if proc.stderr is not None:

        def _drain_stderr() -> None:
            try:
                data = proc.stderr.read()
                if data:
                    stderr_parts.append(data)
            except Exception:
                pass
        stderr_thread = basefwx.threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()
    try:
        if proc.stdout is None:
            raise RuntimeError('source_cmd did not expose stdout')
        written = basefwx.fwxAES_live_encrypt_stream(proc.stdout, dest_handle, password, use_master=use_master, chunk_size=chunk_size)
        proc.stdout.close()
        rc = proc.wait()
        if stderr_thread is not None:
            stderr_thread.join(timeout=1.0)
        if rc != 0:
            msg = b''.join(stderr_parts).decode('utf-8', errors='replace').strip()
            raise RuntimeError(msg or f'source command failed (exit {rc})')
        return written
    except Exception:
        with basefwx.contextlib.suppress(Exception):
            proc.kill()
        with basefwx.contextlib.suppress(Exception):
            proc.wait(timeout=1.0)
        raise
    finally:
        if proc.stdout is not None:
            with basefwx.contextlib.suppress(Exception):
                proc.stdout.close()
        if proc.stderr is not None:
            with basefwx.contextlib.suppress(Exception):
                proc.stderr.close()
        if close_dest and dest_handle is not None:
            with basefwx.contextlib.suppress(Exception):
                dest_handle.close()


def fwxAES_live_decrypt_ffmpeg(encrypted_source, sink_cmd: 'basefwx.typing.Sequence[str]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, chunk_size: int | None=None) -> int:
    if not sink_cmd:
        raise ValueError('sink_cmd must not be empty')
    cmd = [str(part) for part in sink_cmd]
    hw_plan = basefwx.MediaCipher._build_hw_execution_plan('fwxAES_live_decrypt_ffmpeg', stream_type='live', prefer_cpu_decode=True)
    basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
    source_handle = None
    close_source = False
    if basefwx._is_pathlike_target(encrypted_source):
        source_handle = open(basefwx.pathlib.Path(encrypted_source), 'rb')
        close_source = True
    elif hasattr(encrypted_source, 'read'):
        source_handle = encrypted_source
    else:
        raise TypeError('encrypted_source must be a readable stream or filesystem path')
    proc = basefwx.subprocess.Popen(cmd, stdin=basefwx.subprocess.PIPE, stdout=basefwx.subprocess.DEVNULL, stderr=basefwx.subprocess.PIPE)
    stderr_parts: 'list[bytes]' = []
    stderr_thread = None
    if proc.stderr is not None:

        def _drain_stderr() -> None:
            try:
                data = proc.stderr.read()
                if data:
                    stderr_parts.append(data)
            except Exception:
                pass
        stderr_thread = basefwx.threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()
    try:
        if proc.stdin is None:
            raise RuntimeError('sink_cmd did not expose stdin')
        written = basefwx.fwxAES_live_decrypt_stream(source_handle, proc.stdin, password, use_master=use_master, chunk_size=chunk_size)
        proc.stdin.close()
        rc = proc.wait()
        if stderr_thread is not None:
            stderr_thread.join(timeout=1.0)
        if rc != 0:
            msg = b''.join(stderr_parts).decode('utf-8', errors='replace').strip()
            raise RuntimeError(msg or f'sink command failed (exit {rc})')
        return written
    except Exception:
        with basefwx.contextlib.suppress(Exception):
            proc.kill()
        with basefwx.contextlib.suppress(Exception):
            proc.wait(timeout=1.0)
        raise
    finally:
        if proc.stdin is not None:
            with basefwx.contextlib.suppress(Exception):
                proc.stdin.close()
        if proc.stderr is not None:
            with basefwx.contextlib.suppress(Exception):
                proc.stderr.close()
        if close_source and source_handle is not None:
            with basefwx.contextlib.suppress(Exception):
                source_handle.close()


def fwxAES_file(file: 'basefwx.typing.Union[str, basefwx.pathlib.Path]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, use_master: bool=True, output: 'basefwx.typing.Optional[str]'=None, heavy: bool=False, strip_metadata: bool=False, normalize: bool=False, normalize_threshold: 'basefwx.typing.Optional[int]'=None, cover_phrase: str='low taper fade', compress: bool=False, ignore_media: bool=False, keep_meta: bool=False, archive_original: bool=False, keep_input: bool=False) -> str:
    password = basefwx._resolve_password(password, use_master=use_master)
    path = basefwx._normalize_path(file)
    display_path = path
    threshold = basefwx.NORMALIZE_THRESHOLD if normalize_threshold is None else int(normalize_threshold)
    local_reporter = None
    created_reporter = False
    if not basefwx._SILENT_MODE:
        local_reporter = basefwx._ProgressReporter(1)
        created_reporter = True
    if heavy:
        if strip_metadata:
            raise ValueError('fwxAES heavy mode does not support strip-metadata')
        if normalize:
            raise ValueError('fwxAES heavy mode does not support normalize wrapping')
        if normalize_threshold is not None:
            raise ValueError('fwxAES heavy mode does not support normalize thresholds')
        if cover_phrase != 'low taper fade':
            raise ValueError('fwxAES heavy mode does not support cover phrases')
        if keep_meta:
            raise ValueError('fwxAES heavy mode does not support media metadata options')
        if archive_original:
            raise ValueError('fwxAES heavy mode does not support media archive options')

    def _set_bytes_hw_plan() -> None:
        if not local_reporter:
            return
        plan = basefwx.MediaCipher._build_hw_execution_plan('fwxAES_file-heavy' if heavy else 'fwxAES_file', stream_type='bytes', allow_pixel_gpu=False, prefer_cpu_decode=True)
        basefwx.MediaCipher._log_hw_execution_plan(plan)
        local_reporter.set_hw_execution_plan(plan)
    try:
        if heavy:
            _set_bytes_hw_plan()
            pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master, None)
            encode_use_master = use_master and master_available
            decode_use_master = use_master
            password = basefwx._resolve_password(password, use_master=encode_use_master)
            out_path_override = basefwx._normalize_path(output) if output else None
            if path.suffix.lower() == '.fwx':
                target, _ = basefwx._aes_heavy_decode_path(path, password, local_reporter, 0, False, decode_use_master)
                if out_path_override and out_path_override != target:
                    if out_path_override.exists() and out_path_override.is_dir():
                        target_out = out_path_override / target.name
                    else:
                        target_out = out_path_override
                        target_out.parent.mkdir(parents=True, exist_ok=True)
                    basefwx.shutil.move(str(target), str(target_out))
                    target = target_out
                return str(target)
            pack_ctx = basefwx._pack_input_to_archive(path, compress, local_reporter, 0)
            pack_flag = pack_ctx[1] if pack_ctx else ''
            pack_temp = pack_ctx[2] if pack_ctx else None
            source_path = pack_ctx[0] if pack_ctx else path
            out_path = out_path_override if out_path_override else path.with_suffix('.fwx')
            try:
                target, _ = basefwx._aes_heavy_encode_path(source_path, password, local_reporter, 0, False, encode_use_master, pubkey_bytes, pack_flag=pack_flag, output_path=out_path, display_path=display_path, keep_input=keep_input)
                if pack_ctx:
                    basefwx._remove_input(path, keep_input, output_path=target)
                return str(target)
            finally:
                if pack_temp is not None:
                    pack_temp.cleanup()
        if path.suffix.lower() == '.fwx':
            _set_bytes_hw_plan()
            if local_reporter:
                local_reporter.update(0, 0.05, 'read', display_path)
            data = path.read_bytes()
            if data.startswith(basefwx.FWXAES_MAGIC):
                blob = data
            else:
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise ValueError('Input is not a valid FWX1 blob or UTF-8 normalized text') from exc
                blob = basefwx.normalize_unwrap(text)
            if local_reporter:
                local_reporter.update(0, 0.35, 'decrypt', display_path)
            plain = basefwx.fwxAES_decrypt_raw(blob, password, use_master=use_master)
            packed = basefwx._unwrap_pack_header(plain)
            if packed:
                pack_flag, archive_bytes = packed
                dest_path = basefwx._normalize_path(output) if output else path.parent
                dest_dir = dest_path if dest_path.exists() and dest_path.is_dir() else dest_path.parent
                temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-pack-dec-')
                try:
                    suffix = basefwx.PACK_SUFFIX_XZ if pack_flag == basefwx.PACK_TAR_XZ else basefwx.PACK_SUFFIX_GZ
                    archive_path = basefwx.pathlib.Path(temp_dir.name) / f'{path.stem}{suffix}'
                    archive_path.write_bytes(archive_bytes)
                    if local_reporter:
                        local_reporter.update(0, 0.7, 'unpack', display_path)
                    extracted = basefwx._unpack_archive(archive_path, pack_flag, target_dir=dest_dir)
                    if local_reporter:
                        local_reporter.update(0, 1.0, 'done', display_path)
                    return str(extracted)
                finally:
                    temp_dir.cleanup()
            out_path = basefwx._normalize_path(output) if output else path.with_suffix('')
            if local_reporter:
                local_reporter.update(0, 0.8, 'write', display_path)
            with open(out_path, 'wb') as handle:
                handle.write(plain)
            if local_reporter:
                local_reporter.update(0, 1.0, 'done', display_path)
            return str(out_path)
        if not ignore_media:
            try:
                media_ext = path.suffix.lower()
                if media_ext in basefwx.MediaCipher.IMAGE_EXTS | basefwx.MediaCipher.VIDEO_EXTS | basefwx.MediaCipher.AUDIO_EXTS:
                    return basefwx.MediaCipher.encrypt_media(str(path), password, output=output, keep_meta=keep_meta, archive_original=archive_original, keep_input=keep_input, reporter=local_reporter, file_index=0, display_path=display_path)
            except Exception:
                pass
        _set_bytes_hw_plan()
        if local_reporter:
            local_reporter.update(0, 0.05, 'read', display_path)
        pack_ctx = basefwx._pack_input_to_archive(path, compress, None, 0)
        if pack_ctx:
            archive_path, pack_flag, pack_temp = pack_ctx
            try:
                if local_reporter:
                    local_reporter.update(0, 0.25, 'pack', display_path)
                payload = basefwx._wrap_pack_header(archive_path.read_bytes(), pack_flag)
            finally:
                pack_temp.cleanup()
        else:
            payload = path.read_bytes()
        if local_reporter:
            local_reporter.update(0, 0.55, 'encrypt', display_path)
        blob = basefwx.fwxAES_encrypt_raw(payload, password, use_master=use_master)
        out_path = basefwx._normalize_path(output) if output else path.with_suffix('.fwx')
        if local_reporter:
            local_reporter.update(0, 0.8, 'write', display_path)
        if normalize and len(payload) <= threshold:
            text = basefwx.normalize_wrap(blob, cover_phrase)
            out_path.write_text(text, encoding='utf-8', newline='\n')
        else:
            out_path.write_bytes(blob)
        basefwx._remove_input(path, keep_input, out_path)
        if local_reporter:
            local_reporter.update(0, 1.0, 'done', display_path)
        return str(out_path)
    finally:
        if created_reporter and local_reporter:
            local_reporter.reset_terminal_state()
