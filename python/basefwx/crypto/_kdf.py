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

def _coerce_password_bytes(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> bytes:
    if isinstance(password, str):
        return password.encode('utf-8')
    if isinstance(password, (bytes, bytearray, memoryview)):
        return bytes(password)
    raise TypeError(f'Unsupported password type: {type(password)!r}')


def _harden_kdf_params(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, iterations: int, argon2_time_cost: int, argon2_memory_cost: int, argon2_parallelism: int) -> 'tuple[int, int, int, int]':
    pw = basefwx._coerce_password_bytes(password)
    if not pw:
        return (iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism)
    if basefwx._TEST_KDF_ITERS is not None:
        return (iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism)
    if len(pw) < basefwx.SHORT_PASSWORD_MIN:
        iterations = max(iterations, basefwx.SHORT_PBKDF2_ITERATIONS)
        argon2_time_cost = max(argon2_time_cost, basefwx.SHORT_ARGON2_TIME_COST)
        argon2_memory_cost = max(argon2_memory_cost, basefwx.SHORT_ARGON2_MEMORY_COST)
        argon2_parallelism = max(argon2_parallelism, basefwx.SHORT_ARGON2_PARALLELISM)
    return (iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism)


def _fwxaes_iterations(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> int:
    iters = basefwx.FWXAES_PBKDF2_ITERS
    if basefwx._TEST_KDF_ITERS is not None:
        return iters
    pw = basefwx._coerce_password_bytes(password)
    if pw and len(pw) < basefwx.SHORT_PASSWORD_MIN:
        iters = max(iters, basefwx.SHORT_PBKDF2_ITERATIONS)
    return iters


def _kdf_pbkdf2_raw(password: bytes, salt: bytes, iters: int) -> bytes:
    _require_peer_pbkdf2_within_limits(iters)
    return basefwx.hashlib.pbkdf2_hmac('sha256', password, salt, iters, dklen=basefwx.FWXAES_KEY_LEN)


def _derive_user_key_argon2id(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', salt: 'basefwx.typing.Optional[bytes]'=None, *, length: int=32, time_cost: 'int | None'=None, memory_cost: 'int | None'=None, parallelism: 'int | None'=None) -> 'basefwx.typing.Tuple[bytes, bytes]':
    if salt is None:
        salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
    if len(salt) < basefwx.USER_KDF_SALT_SIZE:
        raise ValueError('User key salt must be at least 16 bytes')
    if basefwx.hash_secret_raw is None:
        raise RuntimeError('Argon2 backend unavailable')
    time_cost = time_cost if time_cost is not None else basefwx.ARGON2_TIME_COST
    memory_cost = memory_cost if memory_cost is not None else basefwx.ARGON2_MEMORY_COST
    parallelism = parallelism if parallelism is not None else basefwx.ARGON2_PARALLELISM
    password_bytes = basefwx._coerce_password_bytes(password)
    required_memory_mb = memory_cost * 1024 // 1024
    try:
        key = basefwx.hash_secret_raw(password_bytes, salt, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=length, type=basefwx.Argon2Type.ID)
    except MemoryError:
        raise RuntimeError(f'Insufficient memory for Argon2id key derivation. Required: ~{required_memory_mb} MiB, Consider using PBKDF2 instead (set BASEFWX_USER_KDF=pbkdf2)')
    except Exception as e:
        if 'memory' in str(e).lower():
            raise RuntimeError(f'Memory allocation failed for Argon2id (requires ~{required_memory_mb} MiB). Use BASEFWX_USER_KDF=pbkdf2 as a fallback.') from e
        raise
    return (key, salt)


def _derive_user_key_pbkdf2(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', salt: bytes, *, iterations: int | None=None, length: int=32) -> 'basefwx.typing.Tuple[bytes, bytes]':
    if len(salt) < basefwx.USER_KDF_SALT_SIZE:
        raise ValueError('User key salt must be at least 16 bytes')
    iterations = iterations or basefwx.USER_KDF_ITERATIONS
    _require_peer_pbkdf2_within_limits(iterations)
    password_bytes = basefwx._coerce_password_bytes(password)
    return (basefwx.hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations, dklen=length), salt)


def _require_peer_argon2_within_limits(
    argon2_time_cost: 'basefwx.typing.Optional[int]',
    argon2_memory_cost: 'basefwx.typing.Optional[int]',
    argon2_parallelism: 'basefwx.typing.Optional[int]',
) -> None:
    if argon2_time_cost is not None:
        if argon2_time_cost <= 0:
            raise ValueError('Peer ENC-ARGON2-TC must be positive')
        if argon2_time_cost > basefwx.ARGON2_TIME_COST_MAX:
            raise ValueError('Peer ENC-ARGON2-TC exceeds maximum')
    if argon2_memory_cost is not None:
        if argon2_memory_cost <= 0:
            raise ValueError('Peer ENC-ARGON2-MEM must be positive')
        if argon2_memory_cost > basefwx.ARGON2_MEMORY_COST_MAX:
            raise ValueError('Peer ENC-ARGON2-MEM exceeds maximum')
    if argon2_parallelism is not None:
        if argon2_parallelism <= 0:
            raise ValueError('Peer ENC-ARGON2-PAR must be positive')
        if argon2_parallelism > basefwx.ARGON2_PARALLELISM_MAX:
            raise ValueError('Peer ENC-ARGON2-PAR exceeds maximum')


def _require_peer_pbkdf2_within_limits(iterations: int) -> None:
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise ValueError('Peer PBKDF2 iteration count must be an integer')
    if iterations <= 0:
        raise ValueError('Peer PBKDF2 iteration count must be positive')
    if iterations > basefwx.PEER_PBKDF2_ITERATIONS_MAX:
        raise ValueError('Peer PBKDF2 iteration count exceeds maximum')


def _parse_peer_pbkdf2_iterations(value: 'basefwx.typing.Any', default: int) -> int:
    parsed = _parse_peer_decimal(
        value, 'ENC-KDF-ITER', basefwx.PEER_PBKDF2_ITERATIONS_MAX,
        default=default,
    )
    _require_peer_pbkdf2_within_limits(parsed)
    return parsed


def _parse_peer_decimal(
    value: 'basefwx.typing.Any',
    field: str,
    maximum: int,
    *,
    default: 'basefwx.typing.Optional[int]' = None,
) -> 'basefwx.typing.Optional[int]':
    """Parse unauthenticated decimal metadata without large-int conversion."""
    if value is None or value == '':
        return default
    if not isinstance(value, str) or not value:
        raise ValueError(
            f'Peer {field} must be an unsigned decimal integer'
        )
    maximum_text = str(maximum)
    if len(value) > len(maximum_text):
        raise ValueError(f'Peer {field} exceeds maximum')
    if any(char < '0' or char > '9' for char in value):
        raise ValueError(
            f'Peer {field} must be an unsigned decimal integer'
        )
    if len(value) > 1 and value[0] == '0':
        raise ValueError(
            f'Peer {field} must not contain leading zeros'
        )
    if (
        len(value) == len(maximum_text)
        and value > maximum_text
    ):
        raise ValueError(f'Peer {field} exceeds maximum')
    return int(value)


def _require_strong_password_for_encryption(
    password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]',
    context: str = 'Encryption',
) -> None:
    pw = _coerce_password_bytes(password) if password is not None else b''
    if not pw:
        return
    if basefwx._TEST_KDF_ITERS is not None:
        return
    if basefwx._env_enabled('BASEFWX_ALLOW_WEAK_PASSWORD'):
        return
    min_len = basefwx.MINIMUM_PASSWORD_LENGTH
    raw_min = basefwx.os.getenv('BASEFWX_MIN_PASSWORD_LEN')
    if raw_min and raw_min.strip():
        try:
            configured = int(raw_min.strip())
            if configured >= 0:
                min_len = configured
        except ValueError:
            pass
    if min_len == 0 or len(pw) >= min_len:
        return
    label = context or 'Encryption'
    raise ValueError(
        f'{label} requires a password of at least {min_len} UTF-8 bytes '
        f'(set BASEFWX_ALLOW_WEAK_PASSWORD=1 to override)'
    )


def _resolve_kdf_label(kdf: 'basefwx.typing.Optional[str]', *, peer: bool=False) -> str:
    if peer:
        if kdf not in {'pbkdf2', 'argon2', 'argon2id'}:
            raise ValueError(f'Unsupported peer KDF label: {kdf}')
        return 'argon2id' if kdf == 'argon2' else kdf
    requested = kdf
    if requested is None or not str(requested).strip() or str(requested).lower() == 'auto':
        requested = basefwx.USER_KDF
    if requested is None or not str(requested).strip() or str(requested).lower() == 'auto':
        requested = basefwx.USER_KDF_DEFAULT
    normalized = str(requested).lower()
    if normalized not in {'pbkdf2', 'argon2', 'argon2id'}:
        raise ValueError(f'Unsupported KDF label: {normalized}')
    return 'argon2id' if normalized == 'argon2' else normalized


def _derive_user_key(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', salt: bytes | None=None, *, iterations: int | None=None, kdf: 'basefwx.typing.Optional[str]'=None, argon2_time_cost: 'basefwx.typing.Optional[int]'=None, argon2_memory_cost: 'basefwx.typing.Optional[int]'=None, argon2_parallelism: 'basefwx.typing.Optional[int]'=None) -> 'basefwx.typing.Tuple[bytes, bytes]':
    if salt is None:
        salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
    iterations = iterations or basefwx.USER_KDF_ITERATIONS
    argon2_time_cost = argon2_time_cost if argon2_time_cost is not None else basefwx.ARGON2_TIME_COST
    argon2_memory_cost = argon2_memory_cost if argon2_memory_cost is not None else basefwx.ARGON2_MEMORY_COST
    argon2_parallelism = argon2_parallelism if argon2_parallelism is not None else basefwx.ARGON2_PARALLELISM
    _require_peer_argon2_within_limits(argon2_time_cost, argon2_memory_cost, argon2_parallelism)
    iterations, argon2_time_cost, argon2_memory_cost, argon2_parallelism = basefwx._harden_kdf_params(password, iterations=iterations, argon2_time_cost=argon2_time_cost, argon2_memory_cost=argon2_memory_cost, argon2_parallelism=argon2_parallelism)
    requested_kdf = _resolve_kdf_label(kdf)
    if requested_kdf in {'argon2', 'argon2id'}:
        if basefwx.hash_secret_raw is None:
            raise RuntimeError(
                'Argon2 KDF requested but argon2 backend is unavailable'
            )
        return basefwx._derive_user_key_argon2id(
            password,
            salt,
            time_cost=argon2_time_cost,
            memory_cost=argon2_memory_cost,
            parallelism=argon2_parallelism,
        )
    return basefwx._derive_user_key_pbkdf2(password, salt, iterations=iterations)


def _derive_key_material(secret: 'basefwx.typing.Union[str, bytes, bytearray]', context: 'basefwx.typing.Union[str, bytes, bytearray]', *, length: int=32, iterations: int=200000) -> bytes:
    """
        Derive deterministic key material from a password-like secret using PBKDF2.
        The context parameter namespaces derivations for separate use-cases.
        """
    if isinstance(secret, str):
        secret_bytes = secret.encode('utf-8')
    else:
        secret_bytes = bytes(secret)
    if isinstance(context, str):
        context_bytes = context.encode('utf-8')
    else:
        context_bytes = bytes(context)
    iterations, _, _, _ = basefwx._harden_kdf_params(secret_bytes, iterations=iterations, argon2_time_cost=basefwx.SHORT_ARGON2_TIME_COST, argon2_memory_cost=basefwx.SHORT_ARGON2_MEMORY_COST, argon2_parallelism=basefwx.SHORT_ARGON2_PARALLELISM)
    return basefwx.hashlib.pbkdf2_hmac('sha256', secret_bytes, context_bytes, iterations, dklen=length)


def derive_key_from_text(text, salt, key_length_bytes=32):
    """Derives an AES key from text using PBKDF2."""
    salt_bytes = salt.encode() if isinstance(salt, str) else bytes(salt)
    key, _ = basefwx._derive_user_key_pbkdf2(text, salt_bytes, iterations=100000, length=key_length_bytes)
    return key


def encryptAES(plaintext: str, user_key: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool=False, *, metadata_blob: 'basefwx.typing.Optional[str]'=None, master_public_key: 'basefwx.typing.Optional[bytes]'=None, master_selection=None, kdf: 'basefwx.typing.Optional[str]'=None, progress_callback: 'basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]'=None, obfuscate: bool=True, fast_obfuscation: bool=False, kdf_iterations: 'basefwx.typing.Optional[int]'=None, argon2_time_cost: 'basefwx.typing.Optional[int]'=None, argon2_memory_cost: 'basefwx.typing.Optional[int]'=None, argon2_parallelism: 'basefwx.typing.Optional[int]'=None) -> bytes:
    kdf_used = basefwx._resolve_kdf_label(kdf)
    user_key = basefwx._resolve_password(user_key, use_master=use_master)
    basefwx._require_strong_password_for_encryption(user_key, 'Encryption')
    if not user_key and (not use_master):
        raise ValueError('Cannot encrypt without user password or master key')
    metadata_blob = metadata_blob if metadata_blob is not None else basefwx._split_metadata(plaintext)[0]
    metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
    if len(metadata_bytes) > basefwx.METADATA_MAX:
        raise ValueError('Payload metadata exceeds 1 MiB cap')
    meta_info = basefwx._decode_metadata(metadata_blob) if metadata_blob else {}
    key_separation = meta_info.get('ENC-KSEP')
    if key_separation not in (None, '', 'v1'):
        raise ValueError('Unsupported payload key-separation version')
    use_derived_keys = key_separation == 'v1'
    aad = metadata_bytes if metadata_bytes else b''
    minimum_fixed_size = (
        3 * 4
        + 4
        + len(metadata_bytes)
        + basefwx.AEAD_NONCE_LEN
        + basefwx.AEAD_TAG_LEN
    )
    if len(plaintext) > basefwx.LENGTH_PREFIXED_MAX - minimum_fixed_size:
        raise ValueError('Length-prefixed blob exceeds 64 MiB total cap')
    payload_bytes = plaintext.encode('utf-8')
    minimum_blob_size = minimum_fixed_size + len(payload_bytes)
    if minimum_blob_size > basefwx.LENGTH_PREFIXED_MAX:
        raise ValueError('Length-prefixed blob exceeds 64 MiB total cap')
    selection = master_selection or basefwx._select_master_key(
        use_master, master_public_key
    )
    pq_public = selection.pq_public
    ec_public = selection.ec_public
    use_master_effective = use_master and selection.used_master
    if not user_key and not use_master_effective:
        raise ValueError(
            'Password required when no usable master key is available'
        )
    if use_master_effective:
        if pq_public is not None:
            kem_ciphertext, kem_shared = basefwx._kem_encrypt(pq_public)
            master_payload = kem_ciphertext
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        else:
            ec_blob, ec_shared = basefwx._ec_kem_enc(ec_public)
            master_payload = ec_blob
            ephemeral_key = basefwx._kem_derive_key(ec_shared)
    else:
        master_payload = b''
        ephemeral_key = basefwx.os.urandom(32)
    if user_key:
        user_derived_key, user_salt = basefwx._derive_user_key(user_key, salt=None, iterations=kdf_iterations or basefwx.USER_KDF_ITERATIONS, kdf=kdf_used, argon2_time_cost=argon2_time_cost, argon2_memory_cost=argon2_memory_cost, argon2_parallelism=argon2_parallelism)
        wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
        ephemeral_enc_user = user_salt + wrapped_ephemeral
    else:
        ephemeral_enc_user = b''
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
        else ephemeral_key
    )
    if obfuscate and basefwx.ENABLE_OBFUSCATION:
        payload_bytes = basefwx._obfuscate_bytes(
            payload_bytes, payload_obf_key, fast=fast_obfuscation
        )
    nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
    encryptor = basefwx.Cipher(
        basefwx.algorithms.AES(payload_aead_key),
        basefwx.modes.GCM(nonce),
    ).encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    chunk_size = 1 << 20
    total = len(payload_bytes)
    processed = 0
    cipher_chunks: 'basefwx.typing.List[bytes]' = []
    for offset in range(0, total, chunk_size):
        chunk = payload_bytes[offset:offset + chunk_size]
        cipher_chunks.append(encryptor.update(chunk))
        processed += len(chunk)
        if progress_callback:
            progress_callback(processed, total)
    cipher_chunks.append(encryptor.finalize())
    tag = encryptor.tag
    ciphertext = nonce + b''.join(cipher_chunks) + tag
    payload = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + ciphertext
    blob = basefwx._pack_length_prefixed(
        ephemeral_enc_user, master_payload, payload
    )
    basefwx._del('ephemeral_key')
    basefwx._del('payload_aead_key')
    basefwx._del('payload_obf_key')
    basefwx._del('user_derived_key')
    basefwx._del('kem_shared')
    basefwx._del('payload_bytes')
    return blob


def decryptAES(encrypted_blob: bytes, key: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]'='', use_master: bool=False, *, master_public_key: 'basefwx.typing.Optional[bytes]'=None, allow_legacy: 'basefwx.typing.Optional[bool]'=None, progress_callback: 'basefwx.typing.Optional[basefwx.typing.Callable[[int, int], None]]'=None) -> str:
    key = basefwx._resolve_password(key, use_master=use_master)
    if len(encrypted_blob) > basefwx.LENGTH_PREFIXED_MAX:
        raise ValueError('Length-prefixed blob exceeds 64 MiB total cap')

    def read_chunk(in_bytes, offset):
        if offset < 0 or offset + 4 > len(in_bytes):
            raise ValueError('Malformed length-prefixed blob: missing length')
        length = int.from_bytes(in_bytes[offset:offset + 4], 'big')
        offset += 4
        if length > basefwx.LENGTH_PREFIXED_MAX:
            raise ValueError('Length-prefixed part exceeds 64 MiB cap')
        if length > len(in_bytes) - offset:
            raise ValueError('Malformed length-prefixed blob: truncated chunk')
        chunk = in_bytes[offset:offset + length]
        offset += length
        return (chunk, offset)

    def legacy_decrypt(user_blob: bytes, master_blob: bytes, payload_blob: bytes) -> str:
        master_present = len(master_blob) > 0
        user_present = len(user_blob) > 0
        if master_present:
            if not use_master:
                raise ValueError('Master key required to decrypt this payload (legacy)')
            if basefwx._is_ec_master_blob(master_blob):
                kem_shared = basefwx._ec_kem_dec(master_blob)
            else:
                private_key = basefwx._load_master_pq_private()
                kem_shared = basefwx._kem_decrypt(private_key, master_blob)
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        elif user_present:
            if not key:
                raise ValueError('User password required to decrypt this payload (legacy)')
            min_len = basefwx.USER_KDF_SALT_SIZE + 16
            if len(user_blob) < min_len:
                raise ValueError('Corrupted user key blob: missing salt or IV (legacy)')
            user_salt = user_blob[:basefwx.USER_KDF_SALT_SIZE]
            iv_user = user_blob[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
            enc_user_key = user_blob[basefwx.USER_KDF_SALT_SIZE + 16:]
            user_derived_key, _ = basefwx._derive_user_key(key, salt=user_salt, iterations=basefwx.USER_KDF_ITERATIONS, kdf='pbkdf2')
            cipher_user = basefwx.Cipher(basefwx.algorithms.AES(user_derived_key), basefwx.modes.CBC(iv_user))
            decryptor_user = cipher_user.decryptor()
            padded_b64 = decryptor_user.update(enc_user_key) + decryptor_user.finalize()
            unpadder = basefwx.padding.PKCS7(128).unpadder()
            ephemeral_key_b64 = unpadder.update(padded_b64) + unpadder.finalize()
            ephemeral_key = basefwx.base64.b64decode(ephemeral_key_b64)
        else:
            raise ValueError('Ciphertext missing key transport data (legacy)')
        if len(payload_blob) < 16:
            raise ValueError('Legacy ciphertext missing IV')
        iv_data = payload_blob[:16]
        real_ciphertext = payload_blob[16:]
        cipher_data = basefwx.Cipher(basefwx.algorithms.AES(ephemeral_key), basefwx.modes.CBC(iv_data))
        decryptor_data = cipher_data.decryptor()
        padded_plaintext = decryptor_data.update(real_ciphertext) + decryptor_data.finalize()
        unpadder2 = basefwx.padding.PKCS7(128).unpadder()
        plaintext = unpadder2.update(padded_plaintext) + unpadder2.finalize()
        print('⚠️  Falling back to legacy CBC decryption (ALLOW_CBC_DECRYPT=1).')
        plaintext_str = plaintext.decode('utf-8')
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        return plaintext_str
    legacy_allowed = allow_legacy if allow_legacy is not None else basefwx.os.getenv('ALLOW_CBC_DECRYPT') == '1'

    def _confirm_legacy_fallback(reason: str) -> None:
        prompt = f'⚠️  {reason}.\nFalling back to legacy CBC decryption which is unauthenticated and weaker.\nType YES to accept the security risk and continue: '
        response = input(prompt)
        if response.strip() != 'YES':
            raise ValueError('Legacy CBC fallback aborted by user')
    offset = 0
    ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
    ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
    payload_blob, offset = read_chunk(encrypted_blob, offset)
    if offset != len(encrypted_blob):
        raise ValueError('Malformed length-prefixed blob: trailing data')
    master_blob_present = len(ephemeral_enc_master) > 0
    user_blob_present = len(ephemeral_enc_user) > 0
    if len(payload_blob) < 4:
        if legacy_allowed:
            _confirm_legacy_fallback('Ciphertext payload truncated; AEAD decode unavailable')
            return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
        raise ValueError('Ciphertext payload truncated')
    metadata_len = int.from_bytes(payload_blob[:4], 'big')
    if metadata_len > basefwx.METADATA_MAX:
        raise ValueError('Ciphertext metadata length exceeds 1 MiB cap')
    metadata_end = 4 + metadata_len
    if metadata_end > len(payload_blob):
        if legacy_allowed:
            _confirm_legacy_fallback('Malformed payload metadata; AEAD decode unavailable')
            return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
        raise ValueError('Malformed payload metadata header')
    metadata_bytes = payload_blob[4:metadata_end]
    try:
        metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ''
    except UnicodeDecodeError:
        metadata_blob = ''
    aad = metadata_bytes if metadata_bytes else b''
    meta_info = basefwx._decode_metadata(metadata_blob) if metadata_blob else {}
    key_separation = meta_info.get('ENC-KSEP')
    if key_separation not in (None, '', 'v1'):
        raise ValueError('Unsupported payload key-separation version')
    use_derived_keys = key_separation == 'v1'
    obf_hint = basefwx._require_payload_obfuscation_mode(
        meta_info.get('ENC-OBF')
    )
    should_deobfuscate = obf_hint != 'no'
    fast_obf = should_deobfuscate and obf_hint == 'fast'

    wire_kdf_hint = meta_info.get('ENC-KDF')
    kdf_hint = (
        basefwx._resolve_kdf_label(wire_kdf_hint, peer=True)
        if wire_kdf_hint
        else basefwx._resolve_kdf_label(None)
    )
    kdf_iter_hint = basefwx._parse_peer_pbkdf2_iterations(
        meta_info.get('ENC-KDF-ITER'), basefwx.USER_KDF_ITERATIONS
    )
    argon2_time_hint = basefwx._parse_peer_decimal(
        meta_info.get('ENC-ARGON2-TC'), 'ENC-ARGON2-TC',
        basefwx.ARGON2_TIME_COST_MAX,
    )
    argon2_mem_hint = basefwx._parse_peer_decimal(
        meta_info.get('ENC-ARGON2-MEM'), 'ENC-ARGON2-MEM',
        basefwx.ARGON2_MEMORY_COST_MAX,
    )
    argon2_par_hint = basefwx._parse_peer_decimal(
        meta_info.get('ENC-ARGON2-PAR'), 'ENC-ARGON2-PAR',
        basefwx.ARGON2_PARALLELISM_MAX,
    )
    ciphertext = payload_blob[metadata_end:]

    def _unwrap_with_user() -> bytes:
        if not key:
            raise ValueError('User password required to decrypt this payload')
        min_len = basefwx.USER_KDF_SALT_SIZE + 13
        if len(ephemeral_enc_user) < min_len:
            raise ValueError('Corrupted user key blob: missing salt or AEAD data')
        user_salt = ephemeral_enc_user[:basefwx.USER_KDF_SALT_SIZE]
        wrapped_ephemeral = ephemeral_enc_user[basefwx.USER_KDF_SALT_SIZE:]
        user_derived_key, _ = basefwx._derive_user_key(key, salt=user_salt, iterations=kdf_iter_hint or basefwx.USER_KDF_ITERATIONS, kdf=kdf_hint, argon2_time_cost=argon2_time_hint, argon2_memory_cost=argon2_mem_hint, argon2_parallelism=argon2_par_hint)
        return basefwx._aead_decrypt(user_derived_key, wrapped_ephemeral, aad)

    def _unwrap_user_with_legacy_policy() -> bytes:
        try:
            return _unwrap_with_user()
        except basefwx.InvalidTag as exc:
            if legacy_allowed:
                _confirm_legacy_fallback('User-branch AEAD authentication failed; attempting legacy CBC decrypt')
                raise _LegacyUserFallback(
                    legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
                )
            raise ValueError('User branch authentication failed; incorrect password or tampering') from exc

    class _LegacyUserFallback(Exception):
        def __init__(self, plaintext: str):
            super().__init__('legacy user fallback completed')
            self.plaintext = plaintext

    try:
        if master_blob_present and use_master:
            try:
                if basefwx._is_ec_master_blob(ephemeral_enc_master):
                    if basefwx._env_enabled('BASEFWX_PQ_STRICT') or basefwx._env_enabled(
                        'BASEFWX_PQ_ONLY'
                    ):
                        raise ValueError('EC master blobs are disabled in PQ strict mode')
                    kem_shared = basefwx._ec_kem_dec(ephemeral_enc_master)
                else:
                    private_key = basefwx._load_master_pq_private()
                    kem_shared = basefwx._kem_decrypt(private_key, ephemeral_enc_master)
                ephemeral_key = basefwx._kem_derive_key(kem_shared)
            except Exception:
                if user_blob_present and key:
                    ephemeral_key = _unwrap_user_with_legacy_policy()
                else:
                    raise
        elif master_blob_present and not use_master:
            if user_blob_present and key:
                ephemeral_key = _unwrap_user_with_legacy_policy()
            else:
                raise ValueError('Master key required to decrypt this payload')
        elif user_blob_present:
            ephemeral_key = _unwrap_user_with_legacy_policy()
        else:
            if legacy_allowed:
                _confirm_legacy_fallback('Ciphertext missing key transport data; AEAD decode unavailable')
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError('Ciphertext missing key transport data')
    except _LegacyUserFallback as fallback:
        return fallback.plaintext
    try:
        if len(ciphertext) < basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN:
            raise ValueError('Ciphertext truncated')
        nonce = ciphertext[:basefwx.AEAD_NONCE_LEN]
        tag = ciphertext[-basefwx.AEAD_TAG_LEN:]
        cipher_body = ciphertext[basefwx.AEAD_NONCE_LEN:-basefwx.AEAD_TAG_LEN]
        aead_key = (
            basefwx._hkdf_sha256(
                ephemeral_key,
                info=basefwx.FWXAES_PAYLOAD_AEAD_INFO,
                length=32,
            )
            if use_derived_keys
            else ephemeral_key
        )
        decryptor_ctx = basefwx.Cipher(basefwx.algorithms.AES(aead_key), basefwx.modes.GCM(nonce, tag)).decryptor()
        if aad:
            decryptor_ctx.authenticate_additional_data(aad)
        chunk_size = 1 << 20
        total_ct = len(cipher_body)
        processed = 0
        plaintext_parts: 'basefwx.typing.List[bytes]' = []
        for offset_chunk in range(0, total_ct, chunk_size):
            chunk = cipher_body[offset_chunk:offset_chunk + chunk_size]
            plaintext_parts.append(decryptor_ctx.update(chunk))
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total_ct)
        plaintext_parts.append(decryptor_ctx.finalize())
        payload_bytes = b''.join(plaintext_parts)
    except basefwx.InvalidTag as exc:
        if legacy_allowed:
            print('⚠️  AEAD authentication failed; attempting legacy CBC decrypt.')
            return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
        raise ValueError('AEAD authentication failed; ciphertext or metadata tampered') from exc
    if should_deobfuscate:
        obf_key = (
            basefwx._hkdf_sha256(
                ephemeral_key,
                info=basefwx.FWXAES_PAYLOAD_OBF_INFO,
                length=32,
            )
            if use_derived_keys
            else ephemeral_key
        )
        payload_bytes = basefwx._deobfuscate_bytes(payload_bytes, obf_key, fast=fast_obf)
    plaintext = payload_bytes.decode('utf-8')
    header_blob, _ = basefwx._split_metadata(plaintext)
    if metadata_blob and header_blob and (header_blob != metadata_blob):
        raise ValueError('Metadata integrity mismatch detected')
    basefwx._del('payload_bytes')
    basefwx._del('ephemeral_key')
    basefwx._del('user_derived_key')
    basefwx._del('kem_shared')
    return plaintext
