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

def _decode_pubkey_bytes(raw: bytes) -> bytes:
    """Best-effort decoding pipeline supporting raw/zlib/base64 inputs."""
    if not raw:
        return raw
    candidates = []
    for candidate in (raw, raw.strip()):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    decoded_variants = []
    for candidate in candidates:
        try:
            decoded = basefwx.base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        if decoded not in candidates and decoded not in decoded_variants:
            decoded_variants.append(decoded)
    candidates.extend(decoded_variants)
    for candidate in candidates:
        try:
            return basefwx.zlib.decompress(candidate)
        except Exception:
            continue
    return candidates[-1] if candidates else raw


def _set_master_pubkey_override(cls, data: 'basefwx.typing.Optional[bytes]') -> None:
    cls._MASTER_PUBKEY_OVERRIDE = data


def _resolve_master_pubkey_path(cli_arg: 'basefwx.typing.Optional[str]') -> 'basefwx.typing.Optional[bytes]':
    path_spec = cli_arg or basefwx.os.getenv('BASEFWX_MASTER_PQ_PUB')
    if not path_spec:
        return None
    candidate = basefwx.pathlib.Path(path_spec).expanduser()
    if not candidate.exists():
        raise FileNotFoundError(f'Master PQ public key not found at {candidate}')
    return basefwx._decode_pubkey_bytes(candidate.read_bytes())


def _load_master_pq_public() -> 'basefwx.typing.Optional[bytes]':
    if basefwx._MASTER_PUBKEY_OVERRIDE:
        return basefwx._MASTER_PUBKEY_OVERRIDE
    env_path = basefwx.os.getenv('BASEFWX_MASTER_PQ_PUB')
    if env_path:
        return basefwx._resolve_master_pubkey_path(env_path)
    return None


def _load_master_pq_private() -> bytes:
    candidates = (basefwx.pathlib.Path('~/master_pq.sk').expanduser(),)
    for path in candidates:
        if path.exists():
            data = path.read_bytes()
            try:
                text = data.decode('utf-8').strip()
                return basefwx.zlib.decompress(basefwx.base64.b64decode(text))
            except Exception:
                try:
                    return basefwx.zlib.decompress(data)
                except Exception:
                    return data
    raise FileNotFoundError('No master_pq.sk private key found')


def _load_master_ec_public() -> 'basefwx.typing.Optional[basefwx.ec.EllipticCurvePublicKey]':
    env_pub = basefwx.os.getenv(basefwx.MASTER_EC_PUBLIC_ENV)
    env_priv = basefwx.os.getenv(basefwx.MASTER_EC_PRIVATE_ENV)
    if env_pub:
        pub_path = basefwx.pathlib.Path(env_pub).expanduser()
        if pub_path.exists():
            return basefwx._decode_ec_public_key(pub_path.read_bytes())
        return None
    pub_path = basefwx._default_master_ec_public_path()
    priv_path = basefwx._default_master_ec_private_path()
    if pub_path.exists():
        return basefwx._decode_ec_public_key(pub_path.read_bytes())
    if priv_path.exists():
        private_key = basefwx._decode_ec_private_key(priv_path.read_bytes())
        public_key = private_key.public_key()
        if not pub_path.exists():
            try:
                pub_path.write_bytes(public_key.public_bytes(encoding=basefwx.serialization.Encoding.PEM, format=basefwx.serialization.PublicFormat.SubjectPublicKeyInfo))
                basefwx.os.chmod(pub_path, 420)
            except Exception:
                pass
        return public_key
    return None


def _load_master_ec_private() -> 'basefwx.ec.EllipticCurvePrivateKey':
    candidates = []
    env_priv = basefwx.os.getenv(basefwx.MASTER_EC_PRIVATE_ENV)
    if env_priv:
        candidates.append(basefwx.pathlib.Path(env_priv).expanduser())
    candidates.append(basefwx._default_master_ec_private_path())
    for path in candidates:
        if path.exists():
            return basefwx._decode_ec_private_key(path.read_bytes())
    raise FileNotFoundError('No master EC private key found')


def _write_ec_keypair(public_path: 'basefwx.pathlib.Path', private_path: 'basefwx.pathlib.Path') -> 'tuple[basefwx.ec.EllipticCurvePublicKey, basefwx.ec.EllipticCurvePrivateKey]':
    private_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(encoding=basefwx.serialization.Encoding.PEM, format=basefwx.serialization.PrivateFormat.PKCS8, encryption_algorithm=basefwx.serialization.NoEncryption())
    public_bytes = public_key.public_bytes(encoding=basefwx.serialization.Encoding.PEM, format=basefwx.serialization.PublicFormat.SubjectPublicKeyInfo)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    try:
        basefwx.os.chmod(private_path, 384)
    except Exception:
        pass
    try:
        basefwx.os.chmod(public_path, 420)
    except Exception:
        pass
    return (public_key, private_key)


def _ec_kem_enc(public_key: 'basefwx.ec.EllipticCurvePublicKey') -> 'tuple[bytes, bytes]':
    if public_key is None:
        raise ValueError('EC public key required for master wrap')
    ephemeral_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
    shared = ephemeral_key.exchange(basefwx.ec.ECDH(), public_key)
    epk_bytes = ephemeral_key.public_key().public_bytes(encoding=basefwx.serialization.Encoding.X962, format=basefwx.serialization.PublicFormat.UncompressedPoint)
    if len(epk_bytes) > 65535:
        raise ValueError('EC public key encoding too large')
    header = basefwx.MASTER_EC_MAGIC + len(epk_bytes).to_bytes(2, 'big')
    return (header + epk_bytes, shared)


def _ec_kem_dec(master_blob: bytes) -> bytes:
    if not master_blob.startswith(basefwx.MASTER_EC_MAGIC):
        raise ValueError('Invalid EC master blob')
    if len(master_blob) < 5:
        raise ValueError('Malformed EC master blob')
    length = int.from_bytes(master_blob[3:5], 'big')
    start = 5
    end = start + length
    if len(master_blob) < end:
        raise ValueError('Truncated EC master blob')
    epk_bytes = master_blob[start:end]
    public_key = basefwx.ec.EllipticCurvePublicKey.from_encoded_point(basefwx.ec.SECP521R1(), epk_bytes)
    private_key = basefwx._load_master_ec_private()
    return private_key.exchange(basefwx.ec.ECDH(), public_key)


def _resolve_master_usage(use_master: bool, master_pubkey: 'basefwx.typing.Optional[bytes]') -> 'tuple[basefwx.typing.Optional[bytes], bool]':
    if not use_master:
        return (None, False)
    if master_pubkey is not None:
        return (master_pubkey, True)
    pq_pub = basefwx._load_master_pq_public()
    if pq_pub is not None:
        return (pq_pub, True)
    try:
        ec_pub = basefwx._load_master_ec_public()
    except Exception:
        ec_pub = None
    return (None, ec_pub is not None)


def _kem_derive_key(shared: bytes, length: int=32) -> bytes:
    return basefwx._hkdf_sha256(shared, length=length)


def _prepare_mask_key(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool, *, mask_info: bytes, require_password: bool, aad: 'basefwx.typing.Optional[bytes]'=None) -> 'basefwx.typing.Tuple[bytes, bytes, bytes, bool]':
    if require_password and (not password):
        raise ValueError('Password required for this mode')
    pubkey = basefwx._load_master_pq_public() if use_master else None
    ec_pub = None
    if use_master and pubkey is None:
        try:
            ec_pub = basefwx._load_master_ec_public()
        except Exception:
            ec_pub = None
    use_master_effective = use_master and (pubkey is not None or ec_pub is not None)
    if not password and (not use_master_effective):
        raise ValueError('Password required when PQ master key wrapping is disabled')
    if use_master_effective:
        if pubkey is not None:
            kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(pubkey)
            master_blob = kem_ct
            mask_key = basefwx._hkdf_sha256(kem_shared, info=mask_info)
        else:
            ec_blob, ec_shared = basefwx._ec_kem_enc(ec_pub)
            master_blob = ec_blob
            mask_key = basefwx._hkdf_sha256(ec_shared, info=mask_info)
    else:
        master_blob = b''
        mask_key = basefwx.os.urandom(32)
    user_blob = b''
    if password:
        kdf_label = (basefwx.USER_KDF or 'argon2id').lower()
        user_derived_key, salt = basefwx._derive_user_key(password, salt=None, iterations=basefwx.USER_KDF_ITERATIONS, kdf=kdf_label)
        wrapped = basefwx._aead_encrypt(user_derived_key, mask_key, aad)
        kdf_bytes = kdf_label.encode('utf-8')
        if len(kdf_bytes) > 255:
            raise ValueError('KDF label too long')
        user_blob = bytes([len(kdf_bytes)]) + kdf_bytes + salt + wrapped
    return (mask_key, user_blob, master_blob, use_master_effective)


def _recover_mask_key_from_blob(user_blob: bytes, master_blob: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool, *, mask_info: bytes, aad: 'basefwx.typing.Optional[bytes]'=None) -> bytes:
    master_present = len(master_blob) > 0
    user_present = len(user_blob) > 0

    def _user_path() -> bytes:
        if not user_present:
            raise ValueError('Ciphertext missing key transport data')
        if not password:
            raise ValueError('Password required to decode this payload')
        if len(user_blob) < 1:
            raise ValueError('Corrupted user key blob: missing KDF metadata')
        kdf_len = user_blob[0]
        header_len = 1 + kdf_len + basefwx.USER_KDF_SALT_SIZE
        if len(user_blob) < header_len:
            raise ValueError('Corrupted user key blob: truncated data')
        kdf_label = user_blob[1:1 + kdf_len].decode('utf-8') if kdf_len else basefwx.USER_KDF or 'argon2id'
        salt = user_blob[1 + kdf_len:header_len]
        wrapped = user_blob[header_len:]
        user_derived_key, _ = basefwx._derive_user_key(password, salt=salt, iterations=basefwx.USER_KDF_ITERATIONS, kdf=kdf_label)
        return basefwx._aead_decrypt(user_derived_key, wrapped, aad)
    if master_present and use_master:
        try:
            if master_blob.startswith(basefwx.MASTER_EC_MAGIC):
                shared = basefwx._ec_kem_dec(master_blob)
                return basefwx._hkdf_sha256(shared, info=mask_info)
            private_key = basefwx._load_master_pq_private()
            shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
            return basefwx._hkdf_sha256(shared, info=mask_info)
        except FileNotFoundError:
            if user_present and password:
                return _user_path()
            raise
    if master_present and (not use_master):
        if user_present and password:
            return _user_path()
        raise ValueError('Master key required to decode this payload')
    return _user_path()


def _kem_shared_to_digits(shared: bytes, digits: int=16) -> str:
    output = []
    seed = shared
    while len(output) < digits:
        digest = basefwx.hashlib.sha3_512(seed).digest()
        for byte in digest:
            output.append(str(byte % 10))
            if len(output) == digits:
                break
        seed = digest
    return ''.join(output)


def _pq_wrap_secret(secret: bytes) -> 'basefwx.typing.Tuple[bytes, bytes, bytes]':
    public_key = basefwx._load_master_pq_public()
    if public_key is None:
        raise ValueError('Master public key unavailable for PQ wrap')
    kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(public_key)
    aes_key = basefwx._kem_derive_key(kem_shared)
    aesgcm = basefwx.AESGCM(aes_key)
    nonce = basefwx.os.urandom(12)
    wrapped = nonce + aesgcm.encrypt(nonce, secret, None)
    return (kem_ct, wrapped, kem_shared)


def _pq_unwrap_secret(ciphertext: bytes, wrapped: bytes) -> bytes:
    secret, _ = basefwx._pq_unwrap_secret_with_shared(ciphertext, wrapped)
    return secret


def _pq_unwrap_secret_with_shared(ciphertext: bytes, wrapped: bytes) -> 'basefwx.typing.Tuple[bytes, bytes]':
    private_key = basefwx._load_master_pq_private()
    kem_shared = basefwx.ml_kem_768.decrypt(private_key, ciphertext)
    aes_key = basefwx._kem_derive_key(kem_shared)
    aesgcm = basefwx.AESGCM(aes_key)
    nonce, ct = (wrapped[:12], wrapped[12:])
    secret = aesgcm.decrypt(nonce, ct, None)
    return (secret, kem_shared)

def _default_master_ec_public_path() -> 'basefwx.pathlib.Path':
    return basefwx.pathlib.Path('~/master_ec_public.pem').expanduser()


def _default_master_ec_private_path() -> 'basefwx.pathlib.Path':
    return basefwx.pathlib.Path('~/master_ec_private.pem').expanduser()


def _decode_ec_public_key(raw: bytes) -> 'basefwx.ec.EllipticCurvePublicKey':
    if not raw:
        raise ValueError('Empty EC public key data')
    loaders = (lambda data: basefwx.serialization.load_pem_public_key(data), lambda data: basefwx.serialization.load_pem_private_key(data, password=None).public_key(), lambda data: basefwx.serialization.load_der_public_key(data), lambda data: basefwx.serialization.load_der_private_key(data, password=None).public_key())
    for loader in loaders:
        try:
            key = loader(raw)
        except Exception:
            continue
        if isinstance(key, basefwx.ec.EllipticCurvePublicKey):
            return key
    raise ValueError('Unsupported EC public key format')


def _decode_ec_private_key(raw: bytes) -> 'basefwx.ec.EllipticCurvePrivateKey':
    if not raw:
        raise ValueError('Empty EC private key data')
    loaders = (lambda data: basefwx.serialization.load_pem_private_key(data, password=None), lambda data: basefwx.serialization.load_der_private_key(data, password=None))
    for loader in loaders:
        try:
            key = loader(raw)
        except Exception:
            continue
        if isinstance(key, basefwx.ec.EllipticCurvePrivateKey):
            return key
    raise ValueError('Unsupported EC private key format')
