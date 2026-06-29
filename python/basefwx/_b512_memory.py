# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

from ._b512_common import basefwx
from ._b512_obfuscation import (
    _estimate_aead_blob_size,
    _pack_length_prefixed,
    _unpack_length_prefixed,
)

def pb512encode(t, p, use_master: bool=True):
    """
        Password-based reversible encoding with URL-safe base64.
        
        Output is URL-safe (no + or /) when BASEFWX_OBFUSCATE_CODECS=0.
        With obfuscation enabled (default), output may contain special characters
        but provides additional security through character substitution.
        
        Confidentiality comes from AEAD layers, not this routine.
        """
    p = basefwx._resolve_password(p, use_master=use_master)
    mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(p, use_master, mask_info=b'basefwx.pb512.mask.v1', require_password=True, aad=b'pb512')
    plain_bytes = t.encode('utf-8')
    masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.pb512.stream.v1')
    payload = bytearray(1 + 4 + len(masked))
    payload[0] = 2
    payload[1:5] = len(plain_bytes).to_bytes(4, 'big')
    payload[5:] = masked
    blob = basefwx._pack_length_prefixed(user_blob, master_blob, bytes(payload))
    result = basefwx.base64.urlsafe_b64encode(blob).decode('utf-8')
    result = basefwx._maybe_obfuscate_codecs(result)
    basefwx._del('mask_key')
    basefwx._del('plain_bytes')
    basefwx._del('masked')
    return result

def pb512decode(digs, key, use_master: bool=True):
    key = basefwx._resolve_password(key, use_master=use_master)
    if not key and (not use_master):
        raise ValueError('Password required when PQ master key wrapping is disabled')
    try:
        digs = basefwx._maybe_deobfuscate_codecs(digs)
        raw = basefwx.base64.urlsafe_b64decode(digs)
    except Exception as exc:
        try:
            raw = basefwx.base64.b64decode(digs)
        except Exception:
            if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
                print('⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError('Invalid pb512 payload encoding') from exc
    try:
        user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
    except ValueError:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._pb512decode_legacy(digs, key, use_master)
        raise
    mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, key, use_master, mask_info=b'basefwx.pb512.mask.v1', aad=b'pb512')
    if not payload or payload[0] != 2:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._pb512decode_legacy(digs, key, use_master)
        raise ValueError('Unsupported pb512 payload format')
    if len(payload) < 5:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._pb512decode_legacy(digs, key, use_master)
        raise ValueError('Malformed pb512 payload')
    expected_len = int.from_bytes(payload[1:5], 'big')
    masked = payload[5:]
    if expected_len != len(masked):
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._pb512decode_legacy(digs, key, use_master)
        raise ValueError('pb512 payload length mismatch')
    clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.pb512.stream.v1')
    result = clear.decode('utf-8')
    basefwx._del('mask_key')
    basefwx._del('clear')
    basefwx._del('masked')
    return result

def _pb512decode_legacy(digs, key, use_master: bool=True) -> str:
    if not key and (not use_master):
        raise ValueError('Password required when PQ master key wrapping is disabled')
    try:
        ln = int(digs[:6])
        val = int(digs[6:])
    except ValueError as exc:
        raise ValueError('Malformed legacy pb512 payload') from exc
    raw = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    if len(raw) < ln:
        raw = b'\x00' * (ln - len(raw)) + raw

    def rc(buf, offset):
        length = int.from_bytes(buf[offset:offset + 4], 'big')
        offset += 4
        part = buf[offset:offset + length]
        offset += length
        return (part, offset)
    offset = 0
    ecu, offset = rc(raw, offset)
    ecm, offset = rc(raw, offset)
    cb, offset = rc(raw, offset)
    master_blob_present = len(ecm) > 0
    if master_blob_present and (not use_master):
        raise ValueError('Master key required to decode this payload')

    def mdcode(s):
        parts = []
        for b in bytearray(s.encode('ascii')):
            x = str(int(bin(b)[2:], 2))
            parts.append(str(len(x)))
            parts.append(x)
        return ''.join(parts)

    def decrypt_chunks_from_string(e, n):
        c = len(n)
        z = []
        kx = int(n)
        x = 10 ** c
        l = int(e[-10:])
        e2 = e[:-10]
        for i in range(0, len(e2), c):
            d = int(e2[i:i + c])
            f = (d - kx) % x
            z.append(str(f).zfill(c))
        return ''.join(z)[:l]

    def mcode(s):
        chars = []
        h = 0
        L = 0
        o = 0
        arr = list(s)
        for x in arr:
            h += 1
            if x != '':
                if h == 1:
                    L = int(x)
                    chars.append(chr(int(s[h:h + L])))
                    o = h
                elif L + o + 1 == h:
                    L = int(x)
                    chars.append(chr(int(s[h:h + L])))
                    o = h
        return ''.join(chars)
    if master_blob_present:
        private_key = basefwx._load_master_pq_private()
        kem_shared = basefwx.ml_kem_768.decrypt(private_key, ecm)
        code = basefwx._kem_shared_to_digits(kem_shared, 16)
    else:
        min_len = basefwx.USER_KDF_SALT_SIZE + 16
        if len(ecu) < min_len:
            raise ValueError('Corrupted user key blob: missing salt or IV')
        salt = ecu[:basefwx.USER_KDF_SALT_SIZE]
        iv = ecu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
        cf = ecu[basefwx.USER_KDF_SALT_SIZE + 16:]
        uk, _ = basefwx._derive_user_key(key, salt=salt, kdf='pbkdf2')
        decryptor = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
        padded = decryptor.update(cf) + decryptor.finalize()
        unpadder = basefwx.padding.PKCS7(128).unpadder()
        decoded = basefwx.base64.b64decode(unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
        code = decoded
    result = mcode(decrypt_chunks_from_string(cb.decode('utf-8'), mdcode(code)))
    return result

def b512encode(string, user_key, use_master: bool=True):
    user_key = basefwx._resolve_password(user_key, use_master=use_master)
    if not user_key and (not use_master):
        raise ValueError('Password required when PQ master key wrapping is disabled')
    mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(user_key, use_master, mask_info=b'basefwx.b512.mask.v1', require_password=False, aad=b'b512')
    plain_bytes = string.encode('utf-8')
    masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.b512.stream.v1')
    payload = bytearray(1 + 4 + len(masked))
    payload[0] = 2
    payload[1:5] = len(plain_bytes).to_bytes(4, 'big')
    payload[5:] = masked
    blob = basefwx._pack_length_prefixed(user_blob, master_blob, bytes(payload))
    result = basefwx.base64.b64encode(blob).decode('utf-8')
    result = basefwx._maybe_obfuscate_codecs(result)
    basefwx._del('mask_key')
    basefwx._del('plain_bytes')
    basefwx._del('masked')
    return result

def b512decode(enc, key='', use_master: bool=True):
    key = basefwx._resolve_password(key, use_master=use_master)
    if not key and (not use_master):
        raise ValueError('Password required when PQ master key wrapping is disabled')
    try:
        enc = basefwx._maybe_deobfuscate_codecs(enc)
        raw = basefwx.base64.b64decode(enc)
    except Exception as exc:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._b512decode_legacy(enc, key, use_master)
        raise ValueError('Invalid b512 payload encoding') from exc
    try:
        user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
    except ValueError:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._b512decode_legacy(enc, key, use_master)
        raise
    mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, key, use_master, mask_info=b'basefwx.b512.mask.v1', aad=b'b512')
    if not payload or payload[0] != 2:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._b512decode_legacy(enc, key, use_master)
        raise ValueError('Unsupported b512 payload format')
    if len(payload) < 5:
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._b512decode_legacy(enc, key, use_master)
        raise ValueError('Malformed b512 payload')
    expected_len = int.from_bytes(payload[1:5], 'big')
    masked = payload[5:]
    if expected_len != len(masked):
        if basefwx.os.getenv('BASEFWX_ALLOW_LEGACY_CODECS') == '1':
            print('⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).')
            return basefwx._b512decode_legacy(enc, key, use_master)
        raise ValueError('b512 payload length mismatch')
    clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.b512.stream.v1')
    result = clear.decode('utf-8')
    basefwx._del('mask_key')
    basefwx._del('clear')
    basefwx._del('masked')
    return result

def _b512decode_legacy(enc, key='', use_master: bool=True) -> str:
    if not key and (not use_master):
        raise ValueError('Password required when PQ master key wrapping is disabled')

    def rc(buf, offset):
        length = int.from_bytes(buf[offset:offset + 4], 'big')
        offset += 4
        part = buf[offset:offset + length]
        offset += length
        return (part, offset)
    raw = basefwx.base64.b64decode(enc)
    offset = 0
    epu, offset = rc(raw, offset)
    epm, offset = rc(raw, offset)
    ec, offset = rc(raw, offset)
    master_blob_present = len(epm) > 0
    if not use_master and master_blob_present:
        raise ValueError('Master key required to decode this payload')

    def mdcode(s):
        parts = []
        for b in bytearray(s.encode('ascii')):
            x = str(int(bin(b)[2:], 2))
            parts.append(str(len(x)))
            parts.append(x)
        return ''.join(parts)

    def decrypt_chunks_from_string(e, n):
        c = len(n)
        kx = int(n)
        x = 10 ** c
        l = int(e[-10:])
        e2 = e[:-10]
        z = []
        for i in range(0, len(e2), c):
            d = int(e2[i:i + c])
            f = (d - kx) % x
            z.append(str(f).zfill(c))
        return ''.join(z)[:l]

    def mcode(s):
        chars = []
        h = 0
        L = 0
        o = 0
        arr = list(s)
        for xx in arr:
            h += 1
            if xx != '':
                if h == 1:
                    L = int(xx)
                    chars.append(chr(int(s[h:h + L])))
                    o = h
                elif L + o + 1 == h:
                    L = int(xx)
                    chars.append(chr(int(s[h:h + L])))
                    o = h
        return ''.join(chars)
    if master_blob_present:
        private_key = basefwx._load_master_pq_private()
        kem_shared = basefwx.ml_kem_768.decrypt(private_key, epm)
        ep_str = basefwx._kem_shared_to_digits(kem_shared, 16)
        ep = ep_str.encode('utf-8')
    else:
        min_len = basefwx.USER_KDF_SALT_SIZE + 16
        if len(epu) < min_len:
            raise ValueError('Corrupted user key blob: missing salt or IV')
        salt = epu[:basefwx.USER_KDF_SALT_SIZE]
        iv = epu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
        cf = epu[basefwx.USER_KDF_SALT_SIZE + 16:]
        uk, _ = basefwx._derive_user_key(key, salt=salt, kdf='pbkdf2')
        dec = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
        out = dec.update(cf) + dec.finalize()
        up = basefwx.padding.PKCS7(128).unpadder()
        ep = basefwx.base64.b64decode(up.update(out) + up.finalize())

    def b512decode_chunk(txt, code):
        st = txt.replace('4G5tRA', '=')
        x = basefwx.fwx256unbin(st)
        if x and x[0] == '0':
            x = '-' + x[1:]
        return mcode(decrypt_chunks_from_string(x, mdcode(code)))
    return b512decode_chunk(ec.decode('utf-8'), ep.decode('utf-8'))

def b512file_encode_bytes(data: bytes, ext: str, code: str, strip_metadata: bool=False, use_master: bool=True, *, enable_aead: 'basefwx.typing.Optional[bool]'=None) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError('b512file_encode_bytes expects bytes')
    approx_b64_len = (len(data) + 2) // 3 * 4
    if approx_b64_len > basefwx.HKDF_MAX_LEN:
        raise ValueError('b512file_encode_bytes payload too large; use file-based streaming APIs')
    pubkey_bytes, master_available = basefwx._resolve_master_usage(use_master and (not strip_metadata), None)
    use_master_effective = (use_master and (not strip_metadata)) and master_available
    password = basefwx._resolve_password(code, use_master=use_master_effective)
    b64_payload = basefwx.base64.b64encode(bytes(data)).decode('utf-8')
    ext_token = basefwx.b512encode(ext or '', password, use_master=use_master_effective)
    data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
    kdf_used = (basefwx.USER_KDF or 'argon2id').lower()
    use_aead = basefwx.ENABLE_B512_AEAD if enable_aead is None else bool(enable_aead)
    metadata_blob = basefwx._build_metadata('FWX512R', strip_metadata, use_master_effective, aead='AESGCM' if use_aead else 'NONE', kdf=kdf_used)
    body = f'{ext_token}{basefwx.FWX_DELIM}{data_token}'
    payload = f'{metadata_blob}{basefwx.META_DELIM}{body}' if metadata_blob else body
    payload_bytes = payload.encode('utf-8')
    if not use_aead:
        return payload_bytes
    mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(password, use_master_effective, mask_info=basefwx.B512_FILE_MASK_INFO, require_password=not use_master_effective, aad=b'b512file')
    aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
    ct_blob = basefwx._aead_encrypt(aead_key, payload_bytes, basefwx.B512_AEAD_INFO)
    return basefwx._pack_length_prefixed(user_blob, master_blob, ct_blob)

def b512file_decode_bytes(blob: bytes, code: str, strip_metadata: bool=False, use_master: bool=True) -> 'basefwx.typing.Tuple[bytes, str]':
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError('b512file_decode_bytes expects bytes')
    use_master_effective = use_master and (not strip_metadata)
    password = basefwx._resolve_password(code, use_master=use_master_effective)
    raw_bytes = bytes(blob)
    binary_mode = False
    user_blob: bytes = b''
    master_blob: bytes = b''
    ct_blob: bytes = b''
    if basefwx.ENABLE_B512_AEAD:
        try:
            user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(raw_bytes, 3)
            binary_mode = True
        except ValueError:
            binary_mode = False
    if binary_mode:
        mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, use_master_effective, mask_info=basefwx.B512_FILE_MASK_INFO, aad=b'b512file')
        aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
        payload_bytes = basefwx._aead_decrypt(aead_key, ct_blob, basefwx.B512_AEAD_INFO)
        content = payload_bytes.decode('utf-8')
    else:
        content = raw_bytes.decode('utf-8')
    metadata_blob, content_core = basefwx._split_metadata(content)
    meta = basefwx._decode_metadata(metadata_blob)
    master_hint = meta.get('ENC-MASTER') if meta else None
    if master_hint == 'no':
        use_master_effective = False
    header, payload = basefwx._split_with_delims(content_core, (basefwx.FWX_DELIM, basefwx.LEGACY_FWX_DELIM), 'FWX container')
    ext = basefwx.b512decode(header, password, use_master=use_master_effective)
    data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)
    decoded = basefwx.base64.b64decode(data_b64)
    return (decoded, ext)

def pb512file_encode_bytes(data: bytes, ext: str, code: str, strip_metadata: bool=False, use_master: bool=True) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError('pb512file_encode_bytes expects bytes')
    approx_b64_len = (len(data) + 2) // 3 * 4
    if approx_b64_len > basefwx.HKDF_MAX_LEN:
        raise ValueError('pb512file_encode_bytes payload too large; use file-based streaming APIs')
    use_master_effective = use_master and (not strip_metadata)
    password = basefwx._resolve_password(code, use_master=use_master_effective)
    b64_payload = basefwx.base64.b64encode(bytes(data)).decode('utf-8')
    ext_token = basefwx.pb512encode(ext or '', password, use_master=use_master_effective)
    data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)
    kdf_used = (basefwx.USER_KDF or 'argon2id').lower()
    heavy_iters = basefwx.HEAVY_PBKDF2_ITERATIONS
    heavy_argon_time = basefwx.HEAVY_ARGON2_TIME_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_mem = basefwx.HEAVY_ARGON2_MEMORY_COST if basefwx.hash_secret_raw is not None else None
    heavy_argon_par = basefwx.HEAVY_ARGON2_PARALLELISM if basefwx.hash_secret_raw is not None else None
    fast_obf = not strip_metadata and basefwx._use_fast_obfuscation(len(data))
    obf_mode = 'fast' if fast_obf else 'yes'
    metadata_blob = basefwx._build_metadata('AES-HEAVY', strip_metadata, use_master_effective, kdf=kdf_used, obfuscation=obf_mode, kdf_iters=heavy_iters, argon2_time_cost=heavy_argon_time, argon2_memory_cost=heavy_argon_mem, argon2_parallelism=heavy_argon_par)
    body = f'{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}'
    plaintext = f'{metadata_blob}{basefwx.META_DELIM}{body}' if metadata_blob else body
    ciphertext = basefwx.encryptAES(plaintext, password, use_master=use_master_effective, metadata_blob=metadata_blob, kdf=kdf_used, obfuscate=True, kdf_iterations=heavy_iters, argon2_time_cost=heavy_argon_time, argon2_memory_cost=heavy_argon_mem, argon2_parallelism=heavy_argon_par, fast_obfuscation=fast_obf)
    return ciphertext

def pb512file_decode_bytes(blob: bytes, code: str, strip_metadata: bool=False, use_master: bool=True) -> 'basefwx.typing.Tuple[bytes, str]':
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError('pb512file_decode_bytes expects bytes')
    use_master_effective = use_master and (not strip_metadata)
    password = basefwx._resolve_password(code, use_master=use_master_effective)
    plaintext = basefwx.decryptAES(bytes(blob), password, use_master=use_master_effective)
    metadata_blob, payload = basefwx._split_metadata(plaintext)
    meta = basefwx._decode_metadata(metadata_blob)
    if meta.get('ENC-MASTER') == 'no':
        use_master_effective = False
    ext_token, data_token = basefwx._split_with_delims(payload, (basefwx.FWX_HEAVY_DELIM, basefwx.LEGACY_FWX_HEAVY_DELIM), 'FWX heavy')
    ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
    data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)
    decoded = basefwx.base64.b64decode(data_b64)
    return (decoded, ext)
