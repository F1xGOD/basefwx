# BASEFWX ENCRYPTION ENGINE ->

class basefwx:
    import base64
    import sys
    import secrets
    import pathlib
    import typing
    import json
    import struct
    from PIL import Image
    from io import BytesIO
    import numpy as np
    import os
    import zlib
    import hashlib
    import string
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pqcrypto.kem import ml_kem_768
    from datetime import datetime, timezone
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hmac

    MAX_INPUT_BYTES = 15 * 1024 * 1024  # 15 MiB ceiling for source files
    PROGRESS_BAR_WIDTH = 30
    FWX_DELIM = "A8igTOmG"
    FWX_HEAVY_DELIM = "673827837628292873"
    META_DELIM = "::FWX-META::"
    ENGINE_VERSION = "3.2.0"
    MASTER_PQ_ALG = "ml-kem-768"
    MASTER_PQ_PUBLIC = b"eJwBoARf+9Kzz6BzXHi8fntsVzKBAxCzV6VTNfbCvfAqh+jMdEfccE7UR4Nnbl+roH3ML55Adeabfs6kZ3CgSZijRTWJDbaUXj+LX391QXOnTa7rNEg1qTaxSa1DKmFZwY+kCRlyjP8BWUY0P9c2NLHDiHlBObDRjUyWrbb1YdiJXfITJz3bvBlnRLTQIRSpH042LZy1CwpQT+C0ISO5tc9qkDocWZ3Jx8+Avd0KcY2TP8rcCY4kY/7JR4xWiRV6e1wnz3BnQxdivx4jPusMo8VnlInHhYlSJvEIHDgqo5WjScSIKkT0UNXknxWgb5mpoB/poD4gtyCWA57iGarFM6k3oZZnRjMilMAwvQ8bGCRxnDLsnJPCEpTkDP2Ek7LDSGv6KaG3ManmIaAoZH4mpxAmePaRkTSKYuE7vMeVqeyxl394QUZrfi/YirIhfom6SYIChFzlAgHAZCPMx+9FVzmVxicnvlKRPCWITkFRnkVraxZ8x9S4OR9HzT4G0BEsj/sKOY5VeAi6c82ricH6HnaJB+eEvhjiTssSoxnBX9vUbftnLjFqTMPctY1DgmTabWz1U23rffPSqo0zeDxIlR0FD1foxs9gc9JSR/MChL2ZzFLAUqq7QBPWxHsrjN8VO86FyG64VncSQvtwEPR5kRQgEgoBkqsHHnOVBov3le/mB9oBbPDzCTw7rPchTzNWVvwDOS/bfkmQIlOKKENZLvMInF6ktaLGiAzhy0eob5g7dMFwLCnDU/iQjQqZbyIMVCqMuBlgTFHhPWgKErNwcnIMPEoYg+mstgJIq272I7VCX9usoSjWXZX6SViIpg8FrS2RFCzmXPEpbCQHcg9arbxCD+cZIWfxVmxFx1y4Od2Eb/FkZTt6Maq4zMNalRfBjX/0C0C1aetQWiJ8HCvkZufLlYwAwovRJE+7wkXDgQLMe6dwzzo6ydEJM32kJBuzhjxjMGd4BY8JGKzKVBeJhsMLaViBGw5SEiXWgZhUbECktcJDrfc6r8PBgcQwV1TpU3pTcNNHFt1YoAMCpO9XdO7cDfnbaqRbBUY0hr3sI3P0x962F7rkR45xEGzFZp9XfmsRmG5qHfSTk4EGyS0cdFoDZ51Rvw/4e738wo4QRJGkDBGagROXzbwnmpSpV+cxXvK0Su5FIaGhJQHJqTQTv94Gy710eE43GffqEuT6D4X6mRclSBNGTepgGq6laanzJSp3UcVwFZwCNjdbCB+ycdkqR77muhUgnxHAcZvRf4oXx0pnkGx2Px/gvvAaZGLmqv16jFFZj3pocKlIrVBiSduoYy/CBkehUQDoeykgZs73zhGklAi1NBTBkXjgasYySO2UuS8bSINJfKLqUHOsfbB6sEOLilCaPfCcRtqafMqYJwdXW+KwgpmXqbV0I+nyqAVMIpRmwMYjpBxEkV5CMRgHyEnMr2cBXuv8RcjZfLmMbCATfNcJdEuQUXDjfE4nr94DHERSk8y3IkE7paIUbGV4jgGnFtEYUiZ6ADewLTFDDTmFpRA7jCjytuukSqmmdchYYLIgQnRmTRk3AZbnMbwxkgwy86skVNZZYldaxFdWvulRMd1FgnQn5Q=="
    IMAGECIPHER_SCRAMBLE_CONTEXT = b'basefwx.imagecipher.scramble.v1'
    IMAGECIPHER_OFFSET_CONTEXT = b'basefwx.imagecipher.offset.v1'
    IMAGECIPHER_AEAD_INFO = b'basefwx.image.v1'
    ENABLE_B512_AEAD = os.getenv("BASEFWX_B512_AEAD", "1") == "1"
    B512_AEAD_INFO = b'basefwx.b512file.v1'
    B512_FILE_MASK_INFO = b'basefwx.b512file.mask.v1'
    ENABLE_OBFUSCATION = os.getenv("BASEFWX_OBFUSCATE", "1") == "1"
    OBF_INFO_MASK = b'basefwx.obf.mask.v1'
    OBF_INFO_PERM = b'basefwx.obf.perm.v1'
    OFB_FAST_MIN = 64 * 1024
    PERM_FAST_MIN = 4 * 1024
    USER_KDF_SALT_SIZE = 16
    USER_KDF_ITERATIONS = 200_000
    USER_KDF = os.getenv("BASEFWX_USER_KDF", "argon2id").lower()
    _MASTER_PUBKEY_OVERRIDE: typing.ClassVar[typing.Optional[bytes]] = None

    class _ProgressReporter:
        """Lightweight textual progress reporter with two WinRAR-style bars."""

        def __init__(self, total_files: int, stream=None):
            self.total_files = max(total_files, 1)
            self.stream = stream or basefwx.sys.stdout
            self._printed = False

        @staticmethod
        def _render_bar(fraction: float, width: int | None = None) -> str:
            width = width or basefwx.PROGRESS_BAR_WIDTH
            fraction = max(0.0, min(1.0, fraction))
            filled = int(round(fraction * width))
            filled = min(filled, width)
            bar = '#' * filled + '.' * (width - filled)
            return f"[{bar}] {fraction * 100:6.2f}%"

        def _write(self, line1: str, line2: str) -> None:
            if self._printed:
                self.stream.write('\033[2F')  # move up two lines
            self.stream.write('\033[2K' + line1 + '\n')
            self.stream.write('\033[2K' + line2 + '\n')
            self.stream.flush()
            self._printed = True

        def update(self, file_index: int, fraction: float, phase: str, path: "basefwx.pathlib.Path") -> None:
            overall_fraction = (file_index + max(0.0, min(1.0, fraction))) / self.total_files
            overall = self._render_bar(overall_fraction)
            current = self._render_bar(fraction)
            label = path.name if path else ""
            line1 = f"Overall {overall} ({file_index}/{self.total_files} files complete)"
            line2 = f"File    {current} phase: {phase}{' [' + label + ']' if label else ''}"
            self._write(line1, line2)

        def finalize_file(self, file_index: int, path: "basefwx.pathlib.Path") -> None:
            overall_fraction = (file_index + 1) / self.total_files
            overall = self._render_bar(overall_fraction)
            label = path.name if path else ""
            current = self._render_bar(1.0)
            line1 = f"Overall {overall} ({file_index + 1}/{self.total_files} files complete)"
            line2 = f"File    {current} phase: done{' [' + label + ']' if label else ''}"
            self._write(line1, line2)

    @staticmethod
    def _human_readable_size(num_bytes: int) -> str:
        units = ["B", "KiB", "MiB", "GiB"]
        value = float(num_bytes)
        for unit in units:
            if value < 1024.0 or unit == units[-1]:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} TiB"

    @staticmethod
    def _del(varname: str) -> None:
        try:
            frame = basefwx.sys._getframe(1)
        except Exception:
            return
        try:
            if varname in frame.f_locals:
                frame.f_locals[varname] = None
        except Exception:
            pass

    @staticmethod
    def _hkdf(info: bytes, key: bytes, length: int = 32) -> bytes:
        hk = basefwx.HKDF(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hk.derive(key)

    @staticmethod
    def _splitmix64(state: int) -> "basefwx.typing.Tuple[int, int]":
        z = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        x = z
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9 & ((1 << 64) - 1)
        x = (x ^ (x >> 27)) * 0x94D049BB133111EB & ((1 << 64) - 1)
        x = x ^ (x >> 31)
        return z, x & ((1 << 64) - 1)

    @staticmethod
    def _permute_inplace(data: bytearray, seed: int) -> None:
        n = len(data)
        if n >= basefwx.PERM_FAST_MIN:
            rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed & ((1 << 64) - 1)))
            perm = rng.permutation(n)
            arr = basefwx.np.frombuffer(memoryview(data), dtype=basefwx.np.uint8)
            out = arr.take(perm)
            arr[:] = out
            return
        st = seed & ((1 << 64) - 1)
        for i in range(n - 1, 0, -1):
            st, rnd = basefwx._splitmix64(st)
            j = rnd % (i + 1)
            if j != i:
                data[i], data[j] = data[j], data[i]

    @staticmethod
    def _unpermute_inplace(data: bytearray, seed: int) -> None:
        n = len(data)
        if n >= basefwx.PERM_FAST_MIN:
            rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed & ((1 << 64) - 1)))
            perm = rng.permutation(n)
            inv = basefwx.np.empty_like(perm)
            inv[perm] = basefwx.np.arange(n, dtype=perm.dtype)
            arr = basefwx.np.frombuffer(memoryview(data), dtype=basefwx.np.uint8)
            out = arr.take(inv)
            arr[:] = out
            return
        swaps = []
        st = seed & ((1 << 64) - 1)
        for i in range(n - 1, 0, -1):
            st, rnd = basefwx._splitmix64(st)
            j = rnd % (i + 1)
            swaps.append((i, j))
        for i, j in reversed(swaps):
            if j != i:
                data[i], data[j] = data[j], data[i]

    @staticmethod
    def _xor_keystream_inplace(buf: bytearray, key: bytes, info: bytes = OBF_INFO_MASK) -> None:
        if not buf:
            return
        n = len(buf)
        block_key = basefwx._hkdf(info, key, 32)
        ctr = 0
        total_len_bytes = n.to_bytes(8, 'big')
        if n >= basefwx.OFB_FAST_MIN:
            mv = memoryview(buf)
            arr = basefwx.np.frombuffer(mv, dtype=basefwx.np.uint8)
            offset = 0
            while offset < n:
                h = basefwx.hmac.HMAC(block_key, basefwx.hashes.SHA256())
                meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
                h.update(meta)
                block = h.finalize()
                take = min(len(block), n - offset)
                block_arr = basefwx.np.frombuffer(block, dtype=basefwx.np.uint8)
                basefwx.np.bitwise_xor(
                    arr[offset:offset + take],
                    block_arr[:take],
                    out=arr[offset:offset + take]
                )
                offset += take
                ctr += 1
            return
        off = 0
        while off < n:
            h = basefwx.hmac.HMAC(block_key, basefwx.hashes.SHA256())
            meta = info + total_len_bytes + ctr.to_bytes(8, 'big')
            h.update(meta)
            block = h.finalize()
            take = min(len(block), n - off)
            for i in range(take):
                buf[off + i] ^= block[i]
            off += take
            ctr += 1

    @staticmethod
    def _obfuscate_bytes(data: bytes, ephemeral_key: bytes) -> bytes:
        if not data:
            return data
        perm_seed_bytes = basefwx._hkdf(
            basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
            ephemeral_key,
            16
        )
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        out = bytearray(data)
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        out.reverse()
        basefwx._permute_inplace(out, perm_seed)
        basefwx._del('perm_seed')
        return bytes(out)

    @staticmethod
    def _deobfuscate_bytes(data: bytes, ephemeral_key: bytes) -> bytes:
        if not data:
            return data
        perm_seed_bytes = basefwx._hkdf(
            basefwx.OBF_INFO_PERM + len(data).to_bytes(8, 'big'),
            ephemeral_key,
            16
        )
        perm_seed = int.from_bytes(perm_seed_bytes, 'big')
        out = bytearray(data)
        basefwx._unpermute_inplace(out, perm_seed)
        out.reverse()
        basefwx._xor_keystream_inplace(out, ephemeral_key, basefwx.OBF_INFO_MASK)
        basefwx._del('perm_seed')
        return bytes(out)

    @staticmethod
    def _build_metadata(
        method: str,
        strip: bool,
        use_master: bool,
        *,
        aead: str = "AESGCM",
        kdf: "basefwx.typing.Optional[str]" = None
    ) -> str:
        if strip:
            return ""
        timestamp = basefwx.datetime.now(basefwx.timezone.utc).isoformat().replace("+00:00", "Z")
        version = getattr(basefwx, "__version__", basefwx.ENGINE_VERSION)
        kdf_label = (kdf or basefwx.USER_KDF or "argon2id").lower()
        info = {
            "ENC-TIME": timestamp,
            "ENC-VERSION": version,
            "ENC-METHOD": method,
            "ENC-MASTER": "yes" if use_master else "no",
            "ENC-KEM": basefwx.MASTER_PQ_ALG if use_master else "none",
            "ENC-AEAD": aead,
            "ENC-KDF": kdf_label
        }
        data = basefwx.json.dumps(info, separators=(',', ':')).encode('utf-8')
        return basefwx.base64.b64encode(data).decode('utf-8')

    @staticmethod
    def _decode_metadata(blob: str) -> "basefwx.typing.Dict[str, basefwx.typing.Any]":
        if not blob:
            return {}
        try:
            raw = basefwx.base64.b64decode(blob.encode('utf-8'))
            return basefwx.json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    @staticmethod
    def _split_metadata(payload: str) -> "basefwx.typing.Tuple[str, str]":
        if basefwx.META_DELIM in payload:
            return payload.split(basefwx.META_DELIM, 1)
        return "", payload

    @staticmethod
    def _apply_strip_attributes(path: "basefwx.pathlib.Path") -> None:
        try:
            basefwx.os.utime(path, (0, 0))
        except Exception:
            pass

    @staticmethod
    def _warn_on_metadata(meta: "basefwx.typing.Dict[str, basefwx.typing.Any]", expected_method: str) -> None:
        if not meta:
            return
        recorded_method = meta.get("ENC-METHOD")
        recorded_version = meta.get("ENC-VERSION")
        hints = []
        if recorded_method and recorded_method != expected_method:
            hints.append(recorded_method)
        if recorded_version and recorded_version != basefwx.ENGINE_VERSION:
            hints.append(recorded_version)
        if hints:
            print("Did you mean to use:\n" + " or ".join(hints))

    @staticmethod
    def _decode_pubkey_bytes(raw: bytes) -> bytes:
        """Best-effort decoding pipeline supporting raw/zlib/base64 inputs."""
        if not raw:
            return raw
        candidates = []
        for candidate in (raw, raw.strip()):
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        # Try base64 decode on each candidate; append successful variants
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

    @classmethod
    def _set_master_pubkey_override(cls, data: "basefwx.typing.Optional[bytes]") -> None:
        cls._MASTER_PUBKEY_OVERRIDE = data

    @staticmethod
    def _resolve_master_pubkey_path(cli_arg: "basefwx.typing.Optional[str]") -> "basefwx.typing.Optional[bytes]":
        path_spec = cli_arg or basefwx.os.getenv("BASEFWX_MASTER_PQ_PUB")
        if not path_spec:
            return None
        candidate = basefwx.pathlib.Path(path_spec).expanduser()
        if not candidate.exists():
            raise FileNotFoundError(f"Master PQ public key not found at {candidate}")
        return basefwx._decode_pubkey_bytes(candidate.read_bytes())

    @staticmethod
    def _load_master_pq_public() -> "basefwx.typing.Optional[bytes]":
        if basefwx._MASTER_PUBKEY_OVERRIDE:
            return basefwx._MASTER_PUBKEY_OVERRIDE
        env_path = basefwx.os.getenv("BASEFWX_MASTER_PQ_PUB")
        if env_path:
            return basefwx._resolve_master_pubkey_path(env_path)
        if basefwx.os.getenv("ALLOW_BAKED_PUB") == "1":
            return basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTER_PQ_PUBLIC))
        return None

    @staticmethod
    def _load_master_pq_private() -> bytes:
        candidates = (
            basefwx.pathlib.Path('~/master_pq.sk').expanduser(),
            basefwx.pathlib.Path(r'W:\master_pq.sk')
        )
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

    @staticmethod
    def _kem_derive_key(shared: bytes, length: int = 32) -> bytes:
        return basefwx._hkdf_sha256(shared, length=length)

    @staticmethod
    def _hkdf_sha256(
        key_material: bytes,
        *,
        length: int = 32,
        info: bytes = b'basefwx.kem.v1'
    ) -> bytes:
        hk = basefwx.HKDF(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hk.derive(key_material)

    @staticmethod
    def _aead_encrypt(key: bytes, plaintext: bytes, aad: "basefwx.typing.Optional[bytes]") -> bytes:
        nonce = basefwx.os.urandom(12)
        ct = basefwx.AESGCM(key).encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    @staticmethod
    def _aead_decrypt(key: bytes, blob: bytes, aad: "basefwx.typing.Optional[bytes]") -> bytes:
        if len(blob) < 13:
            raise ValueError("Malformed AEAD blob: too short")
        nonce, ct = blob[:12], blob[12:]
        return basefwx.AESGCM(key).decrypt(nonce, ct, aad or None)

    @staticmethod
    def _pack_length_prefixed(*parts: bytes) -> bytes:
        total = 4 * len(parts) + sum(len(p) for p in parts)
        out = bytearray(total)
        mv = memoryview(out)
        offset = 0
        for part in parts:
            mv[offset:offset + 4] = len(part).to_bytes(4, 'big')
            offset += 4
            mv[offset:offset + len(part)] = part
            offset += len(part)
        return bytes(out)

    @staticmethod
    def _unpack_length_prefixed(data: bytes, count: int) -> "basefwx.typing.Tuple[bytes, ...]":
        mv = memoryview(data)
        total_len = len(mv)
        offset = 0
        parts: "basefwx.typing.List[bytes]" = []
        for _ in range(count):
            if offset + 4 > total_len:
                raise ValueError("Malformed length-prefixed blob (missing length)")
            length = basefwx.struct.unpack_from('>I', mv, offset)[0]
            offset += 4
            if offset + length > total_len:
                raise ValueError("Malformed length-prefixed blob (truncated part)")
            parts.append(bytes(mv[offset:offset + length]))
            offset += length
        if offset != total_len:
            raise ValueError("Malformed length-prefixed blob (extra bytes)")
        return tuple(parts)

    @staticmethod
    def _mask_payload(mask_key: bytes, payload: bytes, *, info: bytes) -> bytes:
        if not payload:
            return b""
        stream = basefwx._hkdf_sha256(mask_key, length=len(payload), info=info)
        return bytes(a ^ b for a, b in zip(payload, stream))

    @staticmethod
    def _prepare_mask_key(
        password: str,
        use_master: bool,
        *,
        mask_info: bytes,
        require_password: bool,
        aad: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[bytes, bytes, bytes, bool]":
        if require_password and not password:
            raise ValueError("Password required for this mode")
        pubkey = basefwx._load_master_pq_public() if use_master else None
        use_master_effective = use_master and pubkey is not None
        if not password and not use_master_effective:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        if use_master_effective:
            kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(pubkey)
            master_blob = kem_ct
            mask_key = basefwx._hkdf_sha256(kem_shared, info=mask_info)
        else:
            master_blob = b""
            mask_key = basefwx.os.urandom(32)
        user_blob = b""
        if password:
            kdf_label = (basefwx.USER_KDF or "argon2id").lower()
            user_derived_key, salt = basefwx._derive_user_key(
                password,
                salt=None,
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_label
            )
            wrapped = basefwx._aead_encrypt(user_derived_key, mask_key, aad)
            kdf_bytes = kdf_label.encode('utf-8')
            if len(kdf_bytes) > 255:
                raise ValueError("KDF label too long")
            user_blob = bytes([len(kdf_bytes)]) + kdf_bytes + salt + wrapped
        return mask_key, user_blob, master_blob, use_master_effective

    @staticmethod
    def _recover_mask_key_from_blob(
        user_blob: bytes,
        master_blob: bytes,
        password: str,
        use_master: bool,
        *,
        mask_info: bytes,
        aad: "basefwx.typing.Optional[bytes]" = None
    ) -> bytes:
        master_present = len(master_blob) > 0
        user_present = len(user_blob) > 0
        if master_present:
            if not use_master:
                raise ValueError("Master key required to decode this payload")
            private_key = basefwx._load_master_pq_private()
            shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
            return basefwx._hkdf_sha256(shared, info=mask_info)
        if not user_present:
            raise ValueError("Ciphertext missing key transport data")
        if not password:
            raise ValueError("Password required to decode this payload")
        if len(user_blob) < 1:
            raise ValueError("Corrupted user key blob: missing KDF metadata")
        kdf_len = user_blob[0]
        header_len = 1 + kdf_len + basefwx.USER_KDF_SALT_SIZE
        if len(user_blob) < header_len:
            raise ValueError("Corrupted user key blob: truncated data")
        kdf_label = user_blob[1:1 + kdf_len].decode('utf-8') if kdf_len else (basefwx.USER_KDF or "argon2id")
        salt = user_blob[1 + kdf_len:header_len]
        wrapped = user_blob[header_len:]
        user_derived_key, _ = basefwx._derive_user_key(
            password,
            salt=salt,
            iterations=basefwx.USER_KDF_ITERATIONS,
            kdf=kdf_label
        )
        return basefwx._aead_decrypt(user_derived_key, wrapped, aad)

    @staticmethod
    def _kem_shared_to_digits(shared: bytes, digits: int = 16) -> str:
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

    @staticmethod
    def _derive_key_material(
        secret: "basefwx.typing.Union[str, bytes, bytearray]",
        context: "basefwx.typing.Union[str, bytes, bytearray]",
        *,
        length: int = 32,
        iterations: int = 200_000
    ) -> bytes:
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
        return basefwx.hashlib.pbkdf2_hmac(
            'sha256',
            secret_bytes,
            context_bytes,
            iterations,
            dklen=length
        )

    @staticmethod
    def _pq_wrap_secret(secret: bytes) -> "basefwx.typing.Tuple[bytes, bytes, bytes]":
        public_key = basefwx._load_master_pq_public()
        if public_key is None:
            raise ValueError("Master public key unavailable for PQ wrap")
        kem_ct, kem_shared = basefwx.ml_kem_768.encrypt(public_key)
        aes_key = basefwx._kem_derive_key(kem_shared)
        aesgcm = basefwx.AESGCM(aes_key)
        nonce = basefwx.os.urandom(12)
        wrapped = nonce + aesgcm.encrypt(nonce, secret, None)
        return kem_ct, wrapped, kem_shared

    @staticmethod
    def _pq_unwrap_secret(ciphertext: bytes, wrapped: bytes) -> bytes:
        secret, _ = basefwx._pq_unwrap_secret_with_shared(ciphertext, wrapped)
        return secret

    @staticmethod
    def _pq_unwrap_secret_with_shared(ciphertext: bytes, wrapped: bytes) -> "basefwx.typing.Tuple[bytes, bytes]":
        private_key = basefwx._load_master_pq_private()
        kem_shared = basefwx.ml_kem_768.decrypt(private_key, ciphertext)
        aes_key = basefwx._kem_derive_key(kem_shared)
        aesgcm = basefwx.AESGCM(aes_key)
        nonce, ct = wrapped[:12], wrapped[12:]
        secret = aesgcm.decrypt(nonce, ct, None)
        return secret, kem_shared

    @staticmethod
    def _normalize_path(path_like: "basefwx.typing.Union[str, basefwx.pathlib.Path]") -> "basefwx.pathlib.Path":
        if isinstance(path_like, basefwx.pathlib.Path):
            path = path_like
        else:
            path = basefwx.pathlib.Path(str(path_like))
        path = path.expanduser()
        try:
            return path.resolve(strict=False)
        except Exception:
            return path

    @staticmethod
    def _ensure_existing_file(path: "basefwx.pathlib.Path") -> None:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Input file not found: {path}")

    @staticmethod
    def _ensure_size_limit(path: "basefwx.pathlib.Path", max_bytes: int = None) -> None:
        limit = max_bytes or basefwx.MAX_INPUT_BYTES
        size = path.stat().st_size
        if size > limit:
            human_size = basefwx._human_readable_size(size)
            human_limit = basefwx._human_readable_size(limit)
            raise ValueError(
                f"{path.name} is {human_size}, exceeding the {human_limit} limit for this mode"
            )

    @staticmethod
    def _resolve_password(password: str, use_master: bool = True) -> str:
        if password == "":
            if not use_master:
                raise ValueError("Password required when master key usage is disabled")
            return ""

        if isinstance(password, str) and password.startswith("yubikey:"):
            label = password.split(":", 1)[1] or "default"
            try:
                from .yubikey_pq import YubiKeyPQKeyStore, YubiKeyUnavailableError
            except ImportError as exc:
                raise ValueError(
                    "YubiKey support is optional. Install python-fido2 inside your "
                    "environment to use 'yubikey:<label>' password specifications."
                ) from exc
            try:
                vault = YubiKeyPQKeyStore()
                return vault.derive_passphrase(label.strip() or "default")
            except YubiKeyUnavailableError as exc:
                raise ValueError(str(exc)) from exc

        if basefwx.os.path.isfile(password):
            with open(password, "r", encoding="utf-8") as handle:
                password = handle.read()
        return password

    @staticmethod
    def _coerce_file_list(files) -> "basefwx.typing.List[basefwx.pathlib.Path]":
        if isinstance(files, (str, basefwx.pathlib.Path)):
            candidates = [files]
        else:
            candidates = list(files)
        if not candidates:
            raise ValueError("No files provided")
        normalized = []
        for item in candidates:
            normalized.append(basefwx._normalize_path(item))
        return normalized

    def __init__(self):
        self.sys.set_int_max_str_digits(2000000000)
        pass

    @staticmethod
    def generate_random_string(length):
        """Generates a random string of the specified length."""

        alphabet = basefwx.string.ascii_letters + basefwx.string.digits
        return ''.join(basefwx.secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def derive_key_from_text(text, salt, key_length_bytes=32):

        """Derives an AES key from text using PBKDF2."""

        salt_bytes = salt.encode() if isinstance(salt, str) else bytes(salt)
        key, _ = basefwx._derive_user_key_pbkdf2(
            text,
            salt_bytes,
            iterations=100_000,
            length=key_length_bytes
        )
        return key

    @staticmethod
    def _derive_user_key_argon2id(
        password: str,
        salt: "basefwx.typing.Optional[bytes]" = None,
        *,
        length: int = 32
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if salt is None:
            salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        key = basefwx.hash_secret_raw(
            password.encode("utf-8"),
            salt,
            time_cost=3,
            memory_cost=2 ** 15,
            parallelism=4,
            hash_len=length,
            type=basefwx.Argon2Type.ID
        )
        return key, salt

    @staticmethod
    def _derive_user_key_pbkdf2(
        password: str,
        salt: bytes,
        *,
        iterations: int = USER_KDF_ITERATIONS,
        length: int = 32
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if len(salt) < basefwx.USER_KDF_SALT_SIZE:
            raise ValueError("User key salt must be at least 16 bytes")
        kdf = basefwx.PBKDF2HMAC(
            algorithm=basefwx.hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations
        )
        return kdf.derive(password.encode("utf-8")), salt

    @staticmethod
    def _derive_user_key(
        password: str,
        salt: bytes | None = None,
        *,
        iterations: int = USER_KDF_ITERATIONS,
        kdf: "basefwx.typing.Optional[str]" = None
    ) -> "basefwx.typing.Tuple[bytes, bytes]":
        if salt is None:
            salt = basefwx.os.urandom(basefwx.USER_KDF_SALT_SIZE)
        kdf_name = (kdf or basefwx.USER_KDF or "argon2id").lower()
        if kdf_name == "pbkdf2":
            return basefwx._derive_user_key_pbkdf2(password, salt, iterations=iterations)
        return basefwx._derive_user_key_argon2id(password, salt)

    @staticmethod
    def encryptAES(
        plaintext: str,
        user_key: str,
        use_master: bool = True,
        *,
        metadata_blob: "basefwx.typing.Optional[str]" = None,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        kdf: "basefwx.typing.Optional[str]" = None
    ) -> bytes:
        if not user_key and not use_master:
            raise ValueError("Cannot encrypt without user password or master key")
        basefwx.sys.set_int_max_str_digits(2000000000)
        metadata_blob = metadata_blob if metadata_blob is not None else basefwx._split_metadata(plaintext)[0]
        metadata_bytes = metadata_blob.encode('utf-8') if metadata_blob else b''
        aad = metadata_bytes if metadata_bytes else b''
        pq_public = master_public_key if master_public_key is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and pq_public is not None
        if use_master_effective:
            kem_ciphertext, kem_shared = basefwx.ml_kem_768.encrypt(pq_public)
            master_payload = kem_ciphertext
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        else:
            master_payload = b""
            ephemeral_key = basefwx.os.urandom(32)
        if user_key:
            kdf_used = (kdf or basefwx.USER_KDF or "argon2id").lower()
            user_derived_key, user_salt = basefwx._derive_user_key(
                user_key,
                salt=None,
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_used
            )
            wrapped_ephemeral = basefwx._aead_encrypt(user_derived_key, ephemeral_key, aad)
            ephemeral_enc_user = user_salt + wrapped_ephemeral
        else:
            ephemeral_enc_user = b""
        payload_bytes = plaintext.encode('utf-8')
        if basefwx.ENABLE_OBFUSCATION:
            payload_bytes = basefwx._obfuscate_bytes(payload_bytes, ephemeral_key)
        ciphertext = basefwx._aead_encrypt(
            ephemeral_key,
            payload_bytes,
            aad
        )
        payload = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + ciphertext

        def int_to_4(i):
            return i.to_bytes(4, byteorder='big', signed=False)

        blob = b''
        blob += int_to_4(len(ephemeral_enc_user)) + ephemeral_enc_user
        blob += int_to_4(len(master_payload)) + master_payload
        blob += int_to_4(len(payload)) + payload
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        basefwx._del('payload_bytes')
        return blob

    @staticmethod
    def decryptAES(
        encrypted_blob: bytes,
        key: str = "",
        use_master: bool = True,
        *,
        master_public_key: "basefwx.typing.Optional[bytes]" = None,
        allow_legacy: "basefwx.typing.Optional[bool]" = None
    ) -> str:
        basefwx.sys.set_int_max_str_digits(2000000000)

        def read_chunk(in_bytes, offset):
            length = int.from_bytes(in_bytes[offset:offset + 4], 'big')
            offset += 4
            chunk = in_bytes[offset:offset + length]
            offset += length
            return chunk, offset

        def legacy_decrypt(user_blob: bytes, master_blob: bytes, payload_blob: bytes) -> str:
            master_present = len(master_blob) > 0
            user_present = len(user_blob) > 0
            if master_present:
                if not use_master:
                    raise ValueError("Master key required to decrypt this payload (legacy)")
                private_key = basefwx._load_master_pq_private()
                kem_shared = basefwx.ml_kem_768.decrypt(private_key, master_blob)
                ephemeral_key = basefwx._kem_derive_key(kem_shared)
            elif user_present:
                if not key:
                    raise ValueError("User password required to decrypt this payload (legacy)")
                min_len = basefwx.USER_KDF_SALT_SIZE + 16
                if len(user_blob) < min_len:
                    raise ValueError("Corrupted user key blob: missing salt or IV (legacy)")
                user_salt = user_blob[:basefwx.USER_KDF_SALT_SIZE]
                iv_user = user_blob[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
                enc_user_key = user_blob[basefwx.USER_KDF_SALT_SIZE + 16:]
                user_derived_key, _ = basefwx._derive_user_key(
                    key,
                    salt=user_salt,
                    iterations=basefwx.USER_KDF_ITERATIONS,
                    kdf="pbkdf2"
                )
                cipher_user = basefwx.Cipher(
                    basefwx.algorithms.AES(user_derived_key),
                    basefwx.modes.CBC(iv_user)
                )
                decryptor_user = cipher_user.decryptor()
                padded_b64 = decryptor_user.update(enc_user_key) + decryptor_user.finalize()
                unpadder = basefwx.padding.PKCS7(128).unpadder()
                ephemeral_key_b64 = unpadder.update(padded_b64) + unpadder.finalize()
                ephemeral_key = basefwx.base64.b64decode(ephemeral_key_b64)
            else:
                raise ValueError("Ciphertext missing key transport data (legacy)")
            if len(payload_blob) < 16:
                raise ValueError("Legacy ciphertext missing IV")
            iv_data = payload_blob[:16]
            real_ciphertext = payload_blob[16:]
            cipher_data = basefwx.Cipher(
                basefwx.algorithms.AES(ephemeral_key),
                basefwx.modes.CBC(iv_data)
            )
            decryptor_data = cipher_data.decryptor()
            padded_plaintext = decryptor_data.update(real_ciphertext) + decryptor_data.finalize()
            unpadder2 = basefwx.padding.PKCS7(128).unpadder()
            plaintext = unpadder2.update(padded_plaintext) + unpadder2.finalize()
            print("⚠️  Falling back to legacy CBC decryption (ALLOW_CBC_DECRYPT=1).")
            plaintext_str = plaintext.decode('utf-8')
            basefwx._del('ephemeral_key')
            basefwx._del('user_derived_key')
            basefwx._del('kem_shared')
            return plaintext_str

        legacy_allowed = allow_legacy if allow_legacy is not None else basefwx.os.getenv("ALLOW_CBC_DECRYPT") == "1"
        offset = 0
        ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
        ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
        payload_blob, offset = read_chunk(encrypted_blob, offset)
        master_blob_present = len(ephemeral_enc_master) > 0
        user_blob_present = len(ephemeral_enc_user) > 0

        if len(payload_blob) < 4:
            if legacy_allowed:
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Ciphertext payload truncated")

        metadata_len = int.from_bytes(payload_blob[:4], 'big')
        metadata_end = 4 + metadata_len
        if metadata_end > len(payload_blob):
            if legacy_allowed:
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Malformed payload metadata header")
        metadata_bytes = payload_blob[4:metadata_end]
        try:
            metadata_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ""
        except UnicodeDecodeError:
            metadata_blob = ""
        aad = metadata_bytes if metadata_bytes else b''
        meta_info = basefwx._decode_metadata(metadata_blob) if metadata_blob else {}
        kdf_hint = (meta_info.get("ENC-KDF") or basefwx.USER_KDF or "argon2id").lower()
        ciphertext = payload_blob[metadata_end:]

        if master_blob_present:
            if not use_master:
                raise ValueError("Master key required to decrypt this payload")
            private_key = basefwx._load_master_pq_private()
            kem_shared = basefwx.ml_kem_768.decrypt(private_key, ephemeral_enc_master)
            ephemeral_key = basefwx._kem_derive_key(kem_shared)
        elif user_blob_present:
            if not key:
                raise ValueError("User password required to decrypt this payload")
            min_len = basefwx.USER_KDF_SALT_SIZE + 13  # salt + nonce + tag
            if len(ephemeral_enc_user) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or AEAD data")
            user_salt = ephemeral_enc_user[:basefwx.USER_KDF_SALT_SIZE]
            wrapped_ephemeral = ephemeral_enc_user[basefwx.USER_KDF_SALT_SIZE:]
            user_derived_key, _ = basefwx._derive_user_key(
                key,
                salt=user_salt,
                iterations=basefwx.USER_KDF_ITERATIONS,
                kdf=kdf_hint
            )
            try:
                ephemeral_key = basefwx._aead_decrypt(user_derived_key, wrapped_ephemeral, aad)
            except basefwx.InvalidTag as exc:
                if legacy_allowed:
                    print("⚠️  User-branch AEAD authentication failed; attempting legacy CBC decrypt.")
                    return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
                raise ValueError("User branch authentication failed; incorrect password or tampering") from exc
        else:
            if legacy_allowed:
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("Ciphertext missing key transport data")

        try:
            payload_bytes = basefwx._aead_decrypt(ephemeral_key, ciphertext, aad)
        except basefwx.InvalidTag as exc:
            if legacy_allowed:
                print("⚠️  AEAD authentication failed; attempting legacy CBC decrypt.")
                return legacy_decrypt(ephemeral_enc_user, ephemeral_enc_master, payload_blob)
            raise ValueError("AEAD authentication failed; ciphertext or metadata tampered") from exc
        if basefwx.ENABLE_OBFUSCATION:
            payload_bytes = basefwx._deobfuscate_bytes(payload_bytes, ephemeral_key)
        plaintext = payload_bytes.decode('utf-8')
        header_blob, _ = basefwx._split_metadata(plaintext)
        if metadata_blob and header_blob and header_blob != metadata_blob:
            raise ValueError("Metadata integrity mismatch detected")
        basefwx._del('payload_bytes')
        basefwx._del('ephemeral_key')
        basefwx._del('user_derived_key')
        basefwx._del('kem_shared')
        return plaintext
    # REVERSIBLE  - SECURITY: ❙
    @staticmethod
    def b64encode(string: str):

        return basefwx.base64.b64encode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64decode(string: str):

        return basefwx.base64.b64decode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def hash512(string: str):

        return basefwx.hashlib.sha256(string.encode('utf-8')).hexdigest()

    @staticmethod
    def uhash513(string: str):

        sti = string
        return basefwx.hashlib.sha256(basefwx.b512encode(basefwx.hashlib.sha512(
            basefwx.hashlib.sha1(
                basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                "utf-8")).hexdigest(), basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
            'utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(t, p, use_master: bool = True):
        """
        Reversible obfuscation helper; confidentiality comes from AEAD layers, not this routine.
        """
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            p,
            use_master,
            mask_info=b'basefwx.pb512.mask.v1',
            require_password=True,
            aad=b'pb512'
        )
        plain_bytes = t.encode('utf-8')
        masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.pb512.stream.v1')
        payload = b'\x02' + len(plain_bytes).to_bytes(4, 'big') + masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, payload)
        result = basefwx.base64.b64encode(blob).decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def pb512decode(digs, key, use_master: bool = True):
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            raw = basefwx.base64.b64decode(digs)
        except Exception as exc:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("Invalid pb512 payload encoding") from exc
        try:
            user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
        except ValueError:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise
        mask_key = basefwx._recover_mask_key_from_blob(
            user_blob,
            master_blob,
            key,
            use_master,
            mask_info=b'basefwx.pb512.mask.v1',
            aad=b'pb512'
        )
        if not payload or payload[0] != 0x02:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("Unsupported pb512 payload format")
        if len(payload) < 5:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("Malformed pb512 payload")
        expected_len = int.from_bytes(payload[1:5], 'big')
        masked = payload[5:]
        if expected_len != len(masked):
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy pb512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._pb512decode_legacy(digs, key, use_master)
            raise ValueError("pb512 payload length mismatch")
        clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.pb512.stream.v1')
        result = clear.decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('clear')
        basefwx._del('masked')
        return result

    @staticmethod
    def _pb512decode_legacy(digs, key, use_master: bool = True) -> str:
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            ln = int(digs[:6])
            val = int(digs[6:])
        except ValueError as exc:
            raise ValueError("Malformed legacy pb512 payload") from exc
        raw = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        if len(raw) < ln:
            raw = (b"\x00" * (ln - len(raw))) + raw

        def rc(buf, offset):
            length = int.from_bytes(buf[offset:offset + 4], 'big')
            offset += 4
            part = buf[offset:offset + length]
            offset += length
            return part, offset

        offset = 0
        ecu, offset = rc(raw, offset)
        ecm, offset = rc(raw, offset)
        cb, offset = rc(raw, offset)
        master_blob_present = len(ecm) > 0
        if master_blob_present and not use_master:
            raise ValueError("Master key required to decode this payload")

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

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
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for x in arr:
                h += 1
                if x != "":
                    if h == 1:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

        if master_blob_present:
            private_key = basefwx._load_master_pq_private()
            kem_shared = basefwx.ml_kem_768.decrypt(private_key, ecm)
            code = basefwx._kem_shared_to_digits(kem_shared, 16)
        else:
            min_len = basefwx.USER_KDF_SALT_SIZE + 16
            if len(ecu) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or IV")
            salt = ecu[:basefwx.USER_KDF_SALT_SIZE]
            iv = ecu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
            cf = ecu[basefwx.USER_KDF_SALT_SIZE + 16:]
            uk, _ = basefwx._derive_user_key(key, salt=salt, kdf="pbkdf2")
            decryptor = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            padded = decryptor.update(cf) + decryptor.finalize()
            unpadder = basefwx.padding.PKCS7(128).unpadder()
            decoded = basefwx.base64.b64decode(unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
            code = decoded
        result = mcode(decrypt_chunks_from_string(cb.decode('utf-8'), mdcode(code)))
        return result

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙

    @staticmethod
    def b512encode(string, user_key, use_master: bool = True):
        if not user_key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            user_key,
            use_master,
            mask_info=b'basefwx.b512.mask.v1',
            require_password=False,
            aad=b'b512'
        )
        plain_bytes = string.encode('utf-8')
        masked = basefwx._mask_payload(mask_key, plain_bytes, info=b'basefwx.b512.stream.v1')
        payload = b'\x02' + len(plain_bytes).to_bytes(4, 'big') + masked
        blob = basefwx._pack_length_prefixed(user_blob, master_blob, payload)
        result = basefwx.base64.b64encode(blob).decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('plain_bytes')
        basefwx._del('masked')
        return result

    @staticmethod
    def b512decode(enc, key="", use_master: bool = True):
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")
        try:
            raw = basefwx.base64.b64decode(enc)
        except Exception as exc:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Invalid b512 payload encoding") from exc
        try:
            user_blob, master_blob, payload = basefwx._unpack_length_prefixed(raw, 3)
        except ValueError:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise
        mask_key = basefwx._recover_mask_key_from_blob(
            user_blob,
            master_blob,
            key,
            use_master,
            mask_info=b'basefwx.b512.mask.v1',
            aad=b'b512'
        )
        if not payload or payload[0] != 0x02:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Unsupported b512 payload format")
        if len(payload) < 5:
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("Malformed b512 payload")
        expected_len = int.from_bytes(payload[1:5], 'big')
        masked = payload[5:]
        if expected_len != len(masked):
            if basefwx.os.getenv("BASEFWX_ALLOW_LEGACY_CODECS") == "1":
                print("⚠️  Falling back to legacy b512 decoder (BASEFWX_ALLOW_LEGACY_CODECS=1).")
                return basefwx._b512decode_legacy(enc, key, use_master)
            raise ValueError("b512 payload length mismatch")
        clear = basefwx._mask_payload(mask_key, masked, info=b'basefwx.b512.stream.v1')
        result = clear.decode('utf-8')
        basefwx._del('mask_key')
        basefwx._del('clear')
        basefwx._del('masked')
        return result

    @staticmethod
    def _b512decode_legacy(enc, key="", use_master: bool = True) -> str:
        if not key and not use_master:
            raise ValueError("Password required when PQ master key wrapping is disabled")

        def rc(buf, offset):
            length = int.from_bytes(buf[offset:offset + 4], 'big')
            offset += 4
            part = buf[offset:offset + length]
            offset += length
            return part, offset

        raw = basefwx.base64.b64decode(enc)
        offset = 0
        epu, offset = rc(raw, offset)
        epm, offset = rc(raw, offset)
        ec, offset = rc(raw, offset)

        master_blob_present = len(epm) > 0
        if not use_master and master_blob_present:
            raise ValueError("Master key required to decode this payload")

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

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
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for xx in arr:
                h += 1
                if xx != "":
                    if h == 1:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

        if master_blob_present:
            private_key = basefwx._load_master_pq_private()
            kem_shared = basefwx.ml_kem_768.decrypt(private_key, epm)
            ep_str = basefwx._kem_shared_to_digits(kem_shared, 16)
            ep = ep_str.encode('utf-8')
        else:
            min_len = basefwx.USER_KDF_SALT_SIZE + 16
            if len(epu) < min_len:
                raise ValueError("Corrupted user key blob: missing salt or IV")
            salt = epu[:basefwx.USER_KDF_SALT_SIZE]
            iv = epu[basefwx.USER_KDF_SALT_SIZE:basefwx.USER_KDF_SALT_SIZE + 16]
            cf = epu[basefwx.USER_KDF_SALT_SIZE + 16:]
            uk, _ = basefwx._derive_user_key(key, salt=salt, kdf="pbkdf2")
            dec = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            out = dec.update(cf) + dec.finalize()
            up = basefwx.padding.PKCS7(128).unpadder()
            ep = basefwx.base64.b64decode(up.update(out) + up.finalize())

        def b512decode_chunk(txt, code):
            st = txt.replace("4G5tRA", "=")
            x = basefwx.fwx256unbin(st)
            if x and x[0] == "0":
                x = "-" + x[1:]
            return mcode(decrypt_chunks_from_string(x, mdcode(code)))

        return b512decode_chunk(ec.decode('utf-8'), ep.decode('utf-8'))

    @staticmethod
    def _b512_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        data = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(data).decode('utf-8')
        ext_token = basefwx.b512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
        if reporter:
            reporter.update(file_index, 0.65, "b256", path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        use_aead = basefwx.ENABLE_B512_AEAD
        metadata_blob = basefwx._build_metadata(
            "FWX512R",
            strip_metadata,
            use_master_effective,
            aead="AESGCM" if use_aead else "NONE",
            kdf=kdf_used
        )
        body = f"{ext_token}{basefwx.FWX_DELIM}{data_token}"
        payload = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        payload_bytes = payload.encode('utf-8')

        mask_key = None
        aead_key = None
        ct_blob = None
        user_blob: bytes = b""
        master_blob: bytes = b""
        if use_aead:
            mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
                password,
                use_master_effective,
                mask_info=basefwx.B512_FILE_MASK_INFO,
                require_password=not use_master_effective,
                aad=b'b512file'
            )
            aead_key = basefwx._hkdf_sha256(mask_key, info=basefwx.B512_AEAD_INFO)
            ct_blob = basefwx._aead_encrypt(aead_key, payload_bytes, basefwx.B512_AEAD_INFO)
            output_bytes = basefwx._pack_length_prefixed(user_blob, master_blob, ct_blob)
            approx_size = len(output_bytes)
        else:
            output_bytes = payload_bytes
            approx_size = len(output_bytes)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(output_bytes)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
            reporter.update(
                file_index,
                0.9,
                f"write (~{basefwx._human_readable_size(approx_size)})",
                output_path
            )
            reporter.finalize_file(file_index, output_path)

        basefwx._del('mask_key')
        basefwx._del('aead_key')
        basefwx._del('ct_blob')
        basefwx._del('payload_bytes')
        basefwx._del('output_bytes')
        basefwx._del('user_blob')
        basefwx._del('master_blob')

        return output_path, approx_size

    @staticmethod
    def _b512_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.1, "read", path)

        raw_bytes = path.read_bytes()

        user_blob: bytes = b""
        master_blob: bytes = b""
        ct_blob: bytes = b""
        use_master_effective = use_master and not strip_metadata
        binary_mode = False
        try:
            user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(raw_bytes, 3)
            binary_mode = True
        except ValueError:
            binary_mode = False

        if binary_mode:
            mask_key = None
            aead_key = None
            payload_bytes = None
            try:
                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    password,
                    use_master_effective,
                    mask_info=basefwx.B512_FILE_MASK_INFO,
                    aad=b'b512file'
                )
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
        master_hint = meta.get("ENC-MASTER") if meta else None
        if master_hint == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "FWX512R")

        try:
            header, payload = content_core.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX container") from exc

        if reporter:
            reporter.update(file_index, 0.35, "b256", path)

        ext = basefwx.b512decode(header, password, use_master=use_master_effective)
        data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.65, "base64", path)

        decoded_bytes = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(decoded_bytes)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.update(file_index, 0.9, "write", target)
            reporter.finalize_file(file_index, target)

        output_len = len(decoded_bytes)
        basefwx._del('content')
        basefwx._del('decoded_bytes')

        return target, output_len

    @staticmethod
    def b512file_encode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
        try:
            pubkey_bytes = basefwx._load_master_pq_public() if use_master else None
            effective_use_master = use_master and not strip_metadata and pubkey_bytes is not None
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_encode_path(
                path,
                password,
                strip_metadata=strip_metadata,
                use_master=effective_use_master,
                master_pubkey=pubkey_bytes
            )
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to encode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def b512file(
            files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]",
            password: str,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ):
        paths = basefwx._coerce_file_list(files)
        encode_use_master = use_master and not strip_metadata and master_pubkey is not None
        decode_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=encode_use_master)
        except Exception as exc:
            print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        reporter = basefwx._ProgressReporter(len(paths))
        results = {}

        for idx, path in enumerate(paths):
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                reporter.update(idx, 0.0, "missing", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"
                continue

            try:
                if path.suffix.lower() == ".fwx":
                    basefwx._b512_decode_path(path, resolved_password, reporter, idx, len(paths), strip_metadata, decode_use_master)
                else:
                    basefwx._b512_encode_path(path, resolved_password, reporter, idx, len(paths), strip_metadata, encode_use_master, master_pubkey)
                results[str(path)] = "SUCCESS!"
            except Exception as exc:
                reporter.update(idx, 0.0, f"error: {exc}", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

    class sepImageCipher:
        _MARKER = b'--ENCRYPTED_PWD--'

        @staticmethod
        def _load_master_pubkey():
            return basefwx._load_master_pq_public()

        @staticmethod
        def _load_master_privkey():
            return basefwx._load_master_pq_private()

        @staticmethod
        def scramble_indices(size: int, key: bytes):
            seed_material = basefwx._derive_key_material(
                key,
                basefwx.IMAGECIPHER_SCRAMBLE_CONTEXT
            )
            seed = int.from_bytes(seed_material[:4], 'big')
            basefwx.np.random.seed(seed)
            idx = basefwx.np.arange(size)
            basefwx.np.random.shuffle(idx)
            return idx

        @staticmethod
        def rotate8(x: int, k: int) -> int:
            return ((x << k) & 0xFF) | (x >> (8 - k))

        @staticmethod
        def encrypt_image_inv(path: str, password: str, output: str = 'chaos_inv.png'):
            key_bytes = password.encode()
            img = basefwx.Image.open(path).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)

            # pixel shuffle & transform
            scrambled = flat[
                basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            ].copy()
            digest = basefwx._derive_key_material(
                key_bytes,
                basefwx.IMAGECIPHER_OFFSET_CONTEXT
            )
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            for i in range(flat.shape[0]):
                off = int(offsets[i])
                r, g, b = map(int, scrambled[i])
                # shift
                r = (r + off) & 0xFF
                g = (g + off // 2) & 0xFF
                b = (b + off // 3) & 0xFF
                # swap
                p = perms[off % 6]
                r, g, b = ([r, g, b][j] for j in p)
                # rotate
                k = (off % 7) + 1
                scrambled[i] = [
                    basefwx.ImageCipher.rotate8(r, k),
                    basefwx.ImageCipher.rotate8(g, k),
                    basefwx.ImageCipher.rotate8(b, k)
                ]

            img_enc = basefwx.Image.fromarray(scrambled.reshape(h, w, 3))
            img_enc.save(output)

            png_data = basefwx.pathlib.Path(output).read_bytes()
            derived_user_key = None
            kem_shared = None
            aead_key = None
            salt = b""
            if password:
                derived_user_key, salt = basefwx._derive_user_key(password, kdf=basefwx.USER_KDF)
            kem_ct, wrapped_pwd, kem_shared = basefwx._pq_wrap_secret(key_bytes)
            aead_source = derived_user_key if derived_user_key is not None else kem_shared
            aead_key = basefwx._hkdf_sha256(aead_source, info=basefwx.IMAGECIPHER_AEAD_INFO)
            cipher_blob = basefwx._aead_encrypt(aead_key, png_data, basefwx.IMAGECIPHER_AEAD_INFO)
            nonce, ct = cipher_blob[:12], cipher_blob[12:]
            with open(output, 'wb') as f:
                f.write(ct)
                f.write(basefwx.ImageCipher._MARKER)
                f.write(len(kem_ct).to_bytes(4, 'big'))
                f.write(kem_ct)
                f.write(len(wrapped_pwd).to_bytes(4, 'big'))
                f.write(wrapped_pwd)
                f.write(len(salt).to_bytes(4, 'big'))
                f.write(salt)
                f.write(nonce)
            basefwx._del('derived_user_key')
            basefwx._del('kem_shared')
            basefwx._del('aead_key')
            basefwx._del('png_data')
            basefwx._del('key_bytes')
            print(f'🔥 Encrypted image+pwd → {output}')

        @staticmethod
        def decrypt_image_inv(path: str, password: str = '', output: str = 'decrypted_inv.png'):
            data = basefwx.pathlib.Path(path).read_bytes()
            idx = data.rfind(basefwx.ImageCipher._MARKER)
            if idx < 0:
                raise ValueError('No embedded password marker')
            ciphertext = data[:idx]
            rest = data[idx + len(basefwx.ImageCipher._MARKER):]
            offset = 0
            kem_len = int.from_bytes(rest[offset:offset + 4], 'big')
            offset += 4
            kem_ct = rest[offset:offset + kem_len]
            offset += kem_len
            wrap_len = int.from_bytes(rest[offset:offset + 4], 'big')
            offset += 4
            wrapped_pwd = rest[offset:offset + wrap_len]
            offset += wrap_len
            legacy_footer = offset == len(rest)
            if legacy_footer:
                salt_len = 0
                salt = b""
                nonce = b""
            else:
                if offset + 4 > len(rest):
                    raise ValueError('Malformed image cipher footer: missing salt length')
                salt_len = int.from_bytes(rest[offset:offset + 4], 'big')
                offset += 4
                if offset + salt_len + 12 > len(rest):
                    raise ValueError('Malformed image cipher footer: truncated salt/nonce')
                salt = rest[offset:offset + salt_len]
                offset += salt_len
                nonce = rest[offset:offset + 12]
                if len(nonce) != 12:
                    raise ValueError('Malformed image cipher footer: missing nonce')

            derived_key = None
            kem_shared = None
            aead_key = None
            recovered_secret = None
            if password:
                password_text = password
                key_bytes = password.encode()
                if salt_len:
                    derived_key, _ = basefwx._derive_user_key(password_text, salt=salt, kdf=basefwx.USER_KDF)
                    aead_source = derived_key
                else:
                    aead_source = basefwx._derive_key_material(key_bytes, basefwx.IMAGECIPHER_AEAD_INFO)
            else:
                recovered_secret, kem_shared = basefwx._pq_unwrap_secret_with_shared(kem_ct, wrapped_pwd)
                try:
                    password_text = recovered_secret.decode('utf-8')
                except UnicodeDecodeError:
                    password_text = recovered_secret.decode('latin-1')
                key_bytes = password_text.encode('utf-8')
                print('🔓 Password recovered via master key')
                if salt_len:
                    derived_key, _ = basefwx._derive_user_key(password_text, salt=salt, kdf=basefwx.USER_KDF)
                    aead_source = derived_key
                else:
                    aead_source = kem_shared
            if legacy_footer:
                png_data = ciphertext
            else:
                aead_key = basefwx._hkdf_sha256(aead_source, info=basefwx.IMAGECIPHER_AEAD_INFO)
                png_data = basefwx._aead_decrypt(aead_key, nonce + ciphertext, basefwx.IMAGECIPHER_AEAD_INFO)

            img = basefwx.Image.open(basefwx.BytesIO(png_data)).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)
            digest = basefwx._derive_key_material(
                key_bytes,
                basefwx.IMAGECIPHER_OFFSET_CONTEXT
            )
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            temp = flat.copy()
            # invert rotate
            for i in range(flat.shape[0]):
                k = (int(offsets[i]) % 7) + 1
                r, g, b = temp[i]
                flat[i] = [
                    ((r >> k) | (r << (8 - k))) & 0xFF,
                    ((g >> k) | (g << (8 - k))) & 0xFF,
                    ((b >> k) | (b << (8 - k))) & 0xFF
                ]
            # invert swap
            temp = flat.copy()
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                p = perms[off % 6]
                inv = [p.index(j) for j in range(3)];
                vals = temp[i]
                flat[i] = [vals[inv[j]] for j in range(3)]
            # invert shift & unshuffle
            recovered = basefwx.np.zeros_like(flat)
            idx_map = basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            out_arr = basefwx.np.zeros_like(flat)
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                r, g, b = flat[i]
                recovered[i] = [
                    (r - off) & 0xFF,
                    (g - off // 2) & 0xFF,
                    (b - off // 3) & 0xFF
                ]
            for i, orig in enumerate(idx_map):
                out_arr[orig] = recovered[i]

            basefwx.Image.fromarray(out_arr.reshape(h, w, 3)).save(output)
            basefwx._del('derived_key')
            basefwx._del('recovered_secret')
            basefwx._del('kem_shared')
            basefwx._del('aead_key')
            basefwx._del('ciphertext')
            basefwx._del('png_data')
            basefwx._del('key_bytes')
            print(f'✅ Decrypted → {output}')

    class ImageCipher:
        _MARKER = b'--ENCRYPTED_PWD--'

        @staticmethod
        def _load_master_pubkey():
            return basefwx._load_master_pq_public()

        @staticmethod
        def _load_master_privkey():
            return basefwx._load_master_pq_private()

        @staticmethod
        def scramble_indices(size: int, key: bytes):
            seed_material = basefwx._derive_key_material(
                key,
                basefwx.IMAGECIPHER_SCRAMBLE_CONTEXT
            )
            seed = int.from_bytes(seed_material[:4], 'big')
            basefwx.np.random.seed(seed)
            idx = basefwx.np.arange(size)
            basefwx.np.random.shuffle(idx)
            return idx

        @staticmethod
        def rotate8(x: int, k: int) -> int:
            return ((x << k) & 0xFF) | (x >> (8 - k))

        @staticmethod
        def encrypt_image_inv(path: str, password: str, output: str = 'chaos_inv.png'):
            key_bytes = password.encode()
            img = basefwx.Image.open(path).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)

            # pixel shuffle & transform
            scrambled = flat[
                basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            ].copy()
            digest = basefwx._derive_key_material(
                key_bytes,
                basefwx.IMAGECIPHER_OFFSET_CONTEXT
            )
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            for i in range(flat.shape[0]):
                off = int(offsets[i])
                r, g, b = map(int, scrambled[i])
                # shift
                r = (r + off) & 0xFF
                g = (g + off // 2) & 0xFF
                b = (b + off // 3) & 0xFF
                # swap
                p = perms[off % 6]
                r, g, b = ([r, g, b][j] for j in p)
                # rotate
                k = (off % 7) + 1
                scrambled[i] = [
                    basefwx.ImageCipher.rotate8(r, k),
                    basefwx.ImageCipher.rotate8(g, k),
                    basefwx.ImageCipher.rotate8(b, k)
                ]

            img_enc = basefwx.Image.fromarray(scrambled.reshape(h, w, 3))
            img_enc.save(output)

            png_data = basefwx.pathlib.Path(output).read_bytes()
            derived_user_key = None
            salt = b""
            if password:
                derived_user_key, salt = basefwx._derive_user_key(password, kdf=basefwx.USER_KDF)
            kem_ct, wrapped_pwd, kem_shared = basefwx._pq_wrap_secret(key_bytes)
            aead_source = derived_user_key if derived_user_key is not None else kem_shared
            aead_key = basefwx._hkdf_sha256(aead_source, info=basefwx.IMAGECIPHER_AEAD_INFO)
            cipher_blob = basefwx._aead_encrypt(aead_key, png_data, basefwx.IMAGECIPHER_AEAD_INFO)
            nonce, ct = cipher_blob[:12], cipher_blob[12:]
            with open(output, 'wb') as f:
                f.write(ct)
                f.write(basefwx.ImageCipher._MARKER)
                f.write(len(kem_ct).to_bytes(4, 'big'))
                f.write(kem_ct)
                f.write(len(wrapped_pwd).to_bytes(4, 'big'))
                f.write(wrapped_pwd)
                f.write(len(salt).to_bytes(4, 'big'))
                f.write(salt)
                f.write(nonce)
            print(f'🔥 Encrypted image+pwd → {output}')

        @staticmethod
        def decrypt_image_inv(path: str, password: str = '', output: str = 'decrypted_inv.png'):
            data = basefwx.pathlib.Path(path).read_bytes()
            idx = data.rfind(basefwx.ImageCipher._MARKER)
            if idx < 0:
                raise ValueError('No embedded password marker')
            ciphertext = data[:idx]
            rest = data[idx + len(basefwx.ImageCipher._MARKER):]
            offset = 0
            kem_len = int.from_bytes(rest[offset:offset + 4], 'big')
            offset += 4
            kem_ct = rest[offset:offset + kem_len]
            offset += kem_len
            wrap_len = int.from_bytes(rest[offset:offset + 4], 'big')
            offset += 4
            wrapped_pwd = rest[offset:offset + wrap_len]
            offset += wrap_len
            legacy_footer = offset == len(rest)
            if legacy_footer:
                salt_len = 0
                salt = b""
                nonce = b""
            else:
                if offset + 4 > len(rest):
                    raise ValueError('Malformed image cipher footer: missing salt length')
                salt_len = int.from_bytes(rest[offset:offset + 4], 'big')
                offset += 4
                if offset + salt_len + 12 > len(rest):
                    raise ValueError('Malformed image cipher footer: truncated salt/nonce')
                salt = rest[offset:offset + salt_len]
                offset += salt_len
                nonce = rest[offset:offset + 12]
                if len(nonce) != 12:
                    raise ValueError('Malformed image cipher footer: missing nonce')

            if password:
                password_text = password
                key_bytes = password.encode()
                if salt_len:
                    derived_key, _ = basefwx._derive_user_key(password_text, salt=salt, kdf=basefwx.USER_KDF)
                    aead_source = derived_key
                else:
                    aead_source = basefwx._derive_key_material(key_bytes, basefwx.IMAGECIPHER_AEAD_INFO)
            else:
                recovered_secret, kem_shared = basefwx._pq_unwrap_secret_with_shared(kem_ct, wrapped_pwd)
                try:
                    password_text = recovered_secret.decode('utf-8')
                except UnicodeDecodeError:
                    password_text = recovered_secret.decode('latin-1')
                key_bytes = password_text.encode('utf-8')
                print('🔓 Password recovered via master key')
                if salt_len:
                    derived_key, _ = basefwx._derive_user_key(password_text, salt=salt, kdf=basefwx.USER_KDF)
                    aead_source = derived_key
                else:
                    aead_source = kem_shared
            if legacy_footer:
                png_data = ciphertext
            else:
                aead_key = basefwx._hkdf_sha256(aead_source, info=basefwx.IMAGECIPHER_AEAD_INFO)
                png_data = basefwx._aead_decrypt(aead_key, nonce + ciphertext, basefwx.IMAGECIPHER_AEAD_INFO)

            img = basefwx.Image.open(basefwx.BytesIO(png_data)).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)
            digest = basefwx._derive_key_material(
                key_bytes,
                basefwx.IMAGECIPHER_OFFSET_CONTEXT
            )
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            temp = flat.copy()
            # invert rotate
            for i in range(flat.shape[0]):
                k = (int(offsets[i]) % 7) + 1
                r, g, b = temp[i]
                flat[i] = [
                    ((r >> k) | (r << (8 - k))) & 0xFF,
                    ((g >> k) | (g << (8 - k))) & 0xFF,
                    ((b >> k) | (b << (8 - k))) & 0xFF
                ]
            # invert swap
            temp = flat.copy()
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                p = perms[off % 6]
                inv = [p.index(j) for j in range(3)];
                vals = temp[i]
                flat[i] = [vals[inv[j]] for j in range(3)]
            # invert shift & unshuffle
            recovered = basefwx.np.zeros_like(flat)
            idx_map = basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            out_arr = basefwx.np.zeros_like(flat)
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                r, g, b = flat[i]
                recovered[i] = [
                    (r - off) & 0xFF,
                    (g - off // 2) & 0xFF,
                    (b - off // 3) & 0xFF
                ]
            for i, orig in enumerate(idx_map):
                out_arr[orig] = recovered[i]

            basefwx.Image.fromarray(out_arr.reshape(h, w, 3)).save(output)
            print(f'✅ Decrypted → {output}')

    def _aes_light_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        metadata_blob = basefwx._build_metadata(
            "AES-LIGHT",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used
        )
        body = (path.suffix or "") + basefwx.FWX_DELIM + b64_payload
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body

        if reporter:
            reporter.update(file_index, 0.55, "AES256", path)

        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used
        )
        compressed = basefwx.zlib.compress(ciphertext)

        if reporter:
            reporter.update(file_index, 0.8, "compress", path)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(compressed)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
            reporter.finalize_file(file_index, output_path)

        return output_path, len(compressed)

    @staticmethod
    def _aes_light_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        compressed = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "decompress", path)

        try:
            ciphertext = basefwx.zlib.decompress(compressed)
        except basefwx.zlib.error as exc:
            raise ValueError("Compressed FWX payload is corrupted") from exc

        if reporter:
            reporter.update(file_index, 0.55, "AES256", path)

        use_master_effective = use_master and not strip_metadata
        plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective)
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        meta = basefwx._decode_metadata(metadata_blob)
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "AES-LIGHT")
        basefwx._warn_on_metadata(meta, "AES-LIGHT")

        try:
            ext, b64_payload = payload.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX light payload") from exc

        if reporter:
            reporter.update(file_index, 0.75, "base64", path)

        raw = basefwx.base64.b64decode(b64_payload)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.finalize_file(file_index, target)

        return target, len(raw)

    @staticmethod
    def _aes_heavy_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        pubkey_bytes = master_pubkey if master_pubkey is not None else (basefwx._load_master_pq_public() if use_master else None)
        use_master_effective = use_master and not strip_metadata and pubkey_bytes is not None
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        ext_token = basefwx.pb512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.55, "pb512", path)

        kdf_used = (basefwx.USER_KDF or "argon2id").lower()
        metadata_blob = basefwx._build_metadata(
            "AES-HEAVY",
            strip_metadata,
            use_master_effective,
            kdf=kdf_used
        )
        body = f"{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}"
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        ciphertext = basefwx.encryptAES(
            plaintext,
            password,
            use_master=use_master_effective,
            metadata_blob=metadata_blob,
            master_public_key=pubkey_bytes if use_master_effective else None,
            kdf=kdf_used
        )
        approx_size = len(ciphertext)

        if reporter:
            reporter.update(file_index, 0.8, "AES512", path)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(ciphertext)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
            basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        human = basefwx._human_readable_size(approx_size)
        print(f"{output_path.name}: approx output size {human}")

        if reporter:
            reporter.update(file_index, 0.95, f"write (~{human})", output_path)
            reporter.finalize_file(file_index, output_path)

        return output_path, approx_size

    @staticmethod
    def _aes_heavy_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        ciphertext = path.read_bytes()

        if reporter:
            reporter.update(file_index, 0.35, "AES512", path)

        use_master_effective = use_master and not strip_metadata
        plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective)
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        meta = basefwx._decode_metadata(metadata_blob)
        if meta.get("ENC-MASTER") == "no":
            use_master_effective = False
        basefwx._warn_on_metadata(meta, "AES-HEAVY")

        try:
            ext_token, data_token = payload.split(basefwx.FWX_HEAVY_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX heavy payload") from exc

        if reporter:
            reporter.update(file_index, 0.6, "pb512", path)

        ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
        data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.8, "base64", path)

        raw = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.finalize_file(file_index, target)

        return target, len(raw)

    @staticmethod
    def AESfile(
            files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]",
            password: str = "",
            light: bool = True,
            strip_metadata: bool = False,
            use_master: bool = True,
            master_pubkey: "basefwx.typing.Optional[bytes]" = None
    ):
        basefwx.sys.set_int_max_str_digits(2000000000)
        paths = basefwx._coerce_file_list(files)

        encode_use_master = use_master and not strip_metadata and master_pubkey is not None
        decode_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=encode_use_master)
        except Exception as exc:
            print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        reporter = basefwx._ProgressReporter(len(paths))
        results = {}

        for idx, path in enumerate(paths):
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                reporter.update(idx, 0.0, "missing", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"
                continue

            try:
                if path.suffix.lower() == ".fwx":
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, reporter, idx, strip_metadata, decode_use_master)
                else:
                    if light:
                        basefwx._aes_light_encode_path(path, resolved_password, reporter, idx, strip_metadata, encode_use_master, master_pubkey)
                    else:
                        basefwx._aes_heavy_encode_path(path, resolved_password, reporter, idx, strip_metadata, encode_use_master, master_pubkey)
                results[str(path)] = "SUCCESS!"
            except Exception as exc:
                reporter.update(idx, 0.0, f"error: {exc}", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

    @staticmethod
    def code(string):
        mapping = {
            'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
            'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
            'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
            'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA', 'A': '(&Tav',
            'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(', 'H': '&GH+',
            'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB', 'N': '(*HSA$i',
            'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&', 'T': '|QG6',
            'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&', ' ': 'R7a{',
            '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!', '@': 'l@', '!': '/A',
            '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[', '}': '9j', '[': '[a)',
            ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA', ';': 'K}N=O', ':': 'YGOI&Ah',
            '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha', ',': 'I8ys#', '0': '(HPA7', '1': '}v',
            '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD', '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA',
            '9': 'U&G*C', '"': 'I(a-s'
        }
        return ''.join(mapping.get(c, c) for c in string)

    @staticmethod
    def fwx256bin(string):
        encoded = basefwx.base64.b32hexencode(basefwx.code(string).encode()).decode()
        padding_count = encoded.count("=")
        return encoded.rstrip("=") + str(padding_count)

    @staticmethod
    def decode(sttr):
        mapping = {
            "I(a-s": "\"", "U&G*C": "9", "*GHBA": "8", "(JH*G": "7", "IU(&V": "6", "(*GFD": "5", "IG(A": "4",
            "_)JHS": "3", "*HAl%": "2", "}v": "1", "(HPA7": "0", "I8ys#": ",", "v6Yha": "<", "0{a9": ">",
            "8y)a": ".", "Oa": "?", "YGOI&Ah": ":", "K}N=O": ";", "(&*GHA": "~", ")*HND_": "/", "]Vc!A": "|",
            "*&GBA": "]", "[a)": "[", "9j": "}", "Av[": "{", "{0aD": ")", "I*Ua]": "(", "(U": "*",
            "OIp*a": "^", "/A": "!", "l@": "@", ".aGa!": "#", "y{A3s": "%", "%A": "&", "}J": "+",
            "OJ)_A": "=", "}F": "-", "R7a{": " ", "*;pY&": "Z", "*J": "Y", "_9xlA": "X", "8h^va": "W",
            "hA": "V", "Qd&^": "U", "|QG6": "T", "G)OA&": "S", "*Ha$g": "R", ")P{A]": "Q", "&*FAl": "P",
            "*IHda&gT": "O", "(*HSA$i": "N", "^&FVB": "M", "&F*Va": "L", "(HAF5": "K", "L&VA": "J",
            "&AN)": "I", "&GH+": "H", "*UAK(": "G", "pW": "F", "{A": "E", "*GABD": "D", "*TGA3": "C",
            "t5": "B", "(&Tav": "A", "J.!dA": "z", "{JM": "y", "(*HskW": "x", "&^F*GV": "w", "n):u": "v",
            "O&iA6u": "u", "*(HARR": "t", "{9sl": "s", "O.-P[A": "r", "*YFSA": "q", "*H)PA-G": "p",
            ")i*8A": "o", "*KA^7": "n", "*(oa": "m", "/IHa": "l", "&G{A": "k", "g%": "j", "(aj*a": "i",
            "+*jsGA": "h", "*&GD2": "g", "(*HGA(": "f", "K5a{": "e", "*YHA": "d", "*&Gs": "c", "&hl": "b",
            "e*1": "a"
        }

        # Get all values sorted by length DESC to avoid collisions (like `*` vs `*UAK(`)
        tokens = sorted(mapping.keys(), key=lambda x: -len(x))

        result = ''
        i = 0
        while i < len(sttr):
            for token in tokens:
                if sttr.startswith(token, i):
                    result += mapping[token]
                    i += len(token)
                    break
            else:
                result += sttr[i]
                i += 1
        return result

    @staticmethod
    def fwx256unbin(string):
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        return basefwx.decode(basefwx.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8'))

    @staticmethod
    def b512file_decode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
        try:
            effective_use_master = use_master and not strip_metadata
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_decode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master)
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to decode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def bi512encode(string: str):

        code = string[0] + string[len(string) - 1]

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")).encode(
                'utf-8')).hexdigest()).replace("-", "0")

        return mainenc(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def a512encode(string: str):
        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        code = (str(len(mdcode((string))) * len(mdcode((string)))))

        def mainenc(string):
            return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

        return mainenc(string)

    @staticmethod
    def a512decode(string: str):

        def mcode(strin: str):
            end = strin
            eand = list(end)
            finish = ""
            ht = 0
            len = 0
            oht = 0
            for een in eand:
                ht += 1
                if een != "":
                    if ht == 1:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
                    if ht != 1 and len + oht + 1 == ht:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
            return finish

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def maindc(string):
            result = ""
            try:
                leoa = int(string[0])
                string2 = string[leoa + 1:len(string)]
                cdo = int(string[1:leoa + 1]) * int(string[1:leoa + 1])
                code = (str(cdo))
                string3 = basefwx.fwx256unbin(string2.replace("4G5tRA", "="))
                if string3[0] == "0":
                    string3 = "-" + string3[1:len(string3)]
                result = mcode(str(int(string3) + int(mdcode(code))))
            except:
                result = "AN ERROR OCCURED!"
            return result

        return maindc(string)

    # UNDCODABLE IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙❙
    @staticmethod
    def b1024encode(string: str):

        def fwx1024uBIN(string: str):
            def fwx512iiBIN(string: str):
                code = string[0] + string[len(string) - 1]

                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                def mainenc(string):
                    return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=",
                                                                                                         "4G5tRA")).encode(
                        'utf-8')).hexdigest()).replace("-", "0")

                return mainenc(string)

            def fwx512ciBIN(string: str):
                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                code = (str(len(mdcode((string))) * len(mdcode((string)))))

                def mainenc(string):
                    return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

                return mainenc(string)

            return fwx512iiBIN(fwx512ciBIN(string))

        return fwx1024uBIN(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def b256decode(string):
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        decoded = basefwx.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8')
        return basefwx.decode(decoded)

    @staticmethod
    def b256encode(string):
        raw = basefwx.code(string).encode()
        encoded = basefwx.base64.b32hexencode(raw).decode()
        return encoded.rstrip("=") + str(encoded.count("="))

# ENCRYPTION TYPES:
# BASE64 - b64encode/b64decode  V1.0
# HASH512 - hash512  V1.0
# HASH512U - uhash513 V1.2
# FWX512RP - pb512encode/pb512encode V2.0
# FWX512R - b512encode/b512decode V2.0 ★
# FWX512I - bi512encode V3.4 ★
# FWX512C - a512encode/a512decode V2.0 ❗❗❗ (NOT RECCOMENDED)
# FWX1024I - b1024encode V4.0 ★ (BEST)
# FWX256R - b256encode/b256decode V1.3 ❗❗❗ (NOT RECCOMENDED)

# HOW TO USE: basefwx.ENCRYPTION-TYPE("text","password")


def cli(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="basefwx", description="BASEFWX encryption toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cryptin = subparsers.add_parser(
        "cryptin",
        help="Encrypt/decrypt one or more files using a BASEFWX method"
    )
    cryptin.add_argument(
        "method",
        help="Method name: 512, b512, pb512, aes, aes-light, aes-heavy"
    )
    cryptin.add_argument(
        "paths",
        nargs='+',
        help="One or more file paths"
    )
    cryptin.add_argument(
        "-p", "--password",
        default="",
        help="Password text or path (leave blank to rely on the master key)"
    )
    cryptin.add_argument(
        "--strip", "--trim",
        dest="strip_metadata",
        action="store_true",
        help="Disable metadata emission and zero timestamps"
    )
    cryptin.add_argument(
        "--no-master",
        dest="use_master",
        action="store_false",
        help="Opt out of master key wrapping/unwrapping"
    )
    cryptin.add_argument(
        "--no-obf",
        dest="obfuscate",
        action="store_false",
        help="Disable pre-AEAD obfuscation layers"
    )
    cryptin.set_defaults(use_master=True, obfuscate=True)
    cryptin.add_argument(
        "--use-master-pub",
        dest="master_pub_path",
        default=None,
        help="Path to ML-KEM public key used for master key wrapping"
    )

    args = parser.parse_args(argv)

    if args.command == "cryptin":
        method = args.method.lower()
        password = args.password or ""
        use_master = args.use_master
        if args.strip_metadata:
            use_master = False
        if not args.obfuscate:
            basefwx.ENABLE_OBFUSCATION = False
        try:
            master_pub_bytes = basefwx._resolve_master_pubkey_path(args.master_pub_path)
        except FileNotFoundError as exc:
            print(f"Failed to load master public key: {exc}")
            return 1
        basefwx._set_master_pubkey_override(master_pub_bytes)
        method_map = {
            "512": "b512",
            "b512": "b512",
            "fwx512": "b512",
            "aes": "aes-light",
            "aes-light": "aes-light",
            "256": "aes-light",
            "light": "aes-light",
            "aes-heavy": "aes-heavy",
            "heavy": "aes-heavy",
            "pb512": "aes-heavy",
            "aes512": "aes-heavy"
        }

        normalized = method_map.get(method)
        if not normalized:
            parser.error(f"Unsupported method '{args.method}'")

        if normalized == "b512":
            result = basefwx.b512file(
                args.paths,
                password,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )
        elif normalized == "aes-light":
            result = basefwx.AESfile(
                args.paths,
                password,
                light=True,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )
        else:
            result = basefwx.AESfile(
                args.paths,
                password,
                light=False,
                strip_metadata=args.strip_metadata,
                use_master=use_master,
                master_pubkey=master_pub_bytes
            )

        if isinstance(result, dict):
            failures = 0
            for path, status in result.items():
                print(f"{path}: {status}")
                if status != "SUCCESS!":
                    failures += 1
            return 0 if failures == 0 else 1

        print(result)
        return 0 if result == "SUCCESS!" else 1

    return 0


def main(argv=None) -> int:
    return cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
