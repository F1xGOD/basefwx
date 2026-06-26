# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.


from __future__ import annotations

import warnings

from ._media_shared import basefwx

class ImageCipher:
    """Deterministic image cipher that keeps data inside regular image formats."""

    @staticmethod
    def _default_encrypted_path(path: 'basefwx.pathlib.Path') -> 'basefwx.pathlib.Path':
        return path

    @staticmethod
    def _default_decrypted_path(path: 'basefwx.pathlib.Path') -> 'basefwx.pathlib.Path':
        return path

    @staticmethod
    def _load_image(path: 'basefwx.pathlib.Path', data: bytes | None=None) -> 'basefwx.typing.Tuple[basefwx.np.ndarray, str, str]':
        basefwx._require_pil()
        stream = basefwx.BytesIO(data) if data is not None else None
        with basefwx.Image.open(stream or path) as img:
            format_name = img.format or path.suffix.lstrip('.').upper()
            bands = len(img.getbands())
            if bands == 1:
                work_mode = 'L'
            elif bands >= 4:
                work_mode = 'RGBA'
            else:
                work_mode = 'RGB'
            work_img = img.convert(work_mode)
            arr = basefwx.np.array(work_img, dtype=basefwx.np.uint8, copy=True)
        return (arr, work_mode, format_name)

    @staticmethod
    def _image_primitives(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', num_pixels: int, channels: int, material: bytes | None=None) -> 'basefwx.typing.Tuple[basefwx.np.ndarray, basefwx.typing.Optional[basefwx.np.ndarray], basefwx.np.ndarray, bytes]':
        if material is None:
            if not password:
                raise ValueError('Password is required for image encryption')
            material = basefwx._derive_key_material(password, basefwx.IMAGECIPHER_STREAM_INFO, length=64, iterations=max(200000, basefwx.USER_KDF_ITERATIONS))
        aes_key = material[:32]
        nonce = material[32:48]
        seed_bytes = material[48:]
        seed = int.from_bytes(seed_bytes, 'big') or 1
        cipher = basefwx.Cipher(basefwx.algorithms.AES(aes_key), basefwx.modes.CTR(nonce))
        encryptor = cipher.encryptor()
        total = num_pixels * channels
        mask_bytes = encryptor.update(bytes(total)) + encryptor.finalize()
        mask = basefwx.np.frombuffer(mask_bytes, dtype=basefwx.np.uint8).reshape(num_pixels, channels).copy()
        rng = basefwx.np.random.Generator(basefwx.np.random.PCG64(seed))
        rotations = None
        if channels > 1:
            rotations = rng.integers(0, channels, size=num_pixels, dtype=basefwx.np.uint8)
        perm = rng.permutation(num_pixels)
        return (mask, rotations, perm, material)

    @staticmethod
    def encrypt_image_inv(path: str, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output: str | None=None, *, include_trailer: bool=True, archive_original: bool=True) -> str:
        path_obj = basefwx.pathlib.Path(path)
        basefwx._ensure_existing_file(path_obj)
        password = basefwx._resolve_password(password, use_master=True)
        if not include_trailer:
            if basefwx.os.getenv('BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION') != '1':
                raise ValueError('Image encryption without trailer is deterministic and insecure; set BASEFWX_ALLOW_INSECURE_IMAGE_OBFUSCATION=1 to allow or enable trailer')
            if not password:
                raise ValueError('Password is required for image encryption without trailer')
        output_path = basefwx.pathlib.Path(output) if output else basefwx.ImageCipher._default_encrypted_path(path_obj)
        original_bytes = path_obj.read_bytes()
        arr, mode, fmt = basefwx.ImageCipher._load_image(path_obj, original_bytes)
        shape = arr.shape
        if arr.ndim == 2:
            channels = 1
            flat = arr.reshape(-1, 1).astype(basefwx.np.uint8, copy=True)
        else:
            channels = shape[2]
            flat = arr.reshape(-1, channels).astype(basefwx.np.uint8, copy=True)
        num_pixels = flat.shape[0]
        material_override = None
        archive_key = None
        trailer_header = b''
        if include_trailer:
            _, archive_key, material_override, trailer_header = basefwx._jmg_prepare_keys(password, use_master=True, security_profile=basefwx.JMG_SECURITY_PROFILE_MAX)
        mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(password, num_pixels, channels, material=material_override)
        basefwx.np.bitwise_xor(flat, mask, out=flat)
        if rotations is not None:
            rows = basefwx.np.arange(num_pixels, dtype=basefwx.np.intp)[:, None]
            base_idx = basefwx.np.arange(channels, dtype=basefwx.np.intp)
            idx = (base_idx + rotations[:, None]) % channels
            flat = flat[rows, idx]
        flat = flat.take(perm, axis=0)
        scrambled = flat.reshape(shape)
        image = basefwx.Image.fromarray(scrambled.astype(basefwx.np.uint8), mode)
        save_kwargs: dict[str, basefwx.typing.Any] = {}
        if fmt:
            save_kwargs['format'] = fmt
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = output_path.with_name(f'{output_path.stem}._tmp{output_path.suffix}')
        image.save(temp_path, **save_kwargs)
        image.close()
        basefwx.os.replace(temp_path, output_path)
        if include_trailer:
            if archive_original:
                archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, basefwx._jmg_archive_info_for_profile(basefwx.JMG_SECURITY_PROFILE_MAX))
                trailer_blob = trailer_header + archive_blob
                basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_TRAILER_MAGIC, trailer_blob)
            else:
                basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, trailer_header)
        basefwx._del('mask')
        basefwx._del('rotations')
        basefwx._del('perm')
        basefwx._del('flat')
        basefwx._del('arr')
        basefwx._del('material')
        basefwx._del('archive_key')
        basefwx._del('archive_blob')
        basefwx._del('trailer_header')
        basefwx._del('material_override')
        basefwx._del('original_bytes')
        print(f'🔥 Encrypted image → {output_path}')
        return str(output_path)

    @staticmethod
    def decrypt_image_inv(path: str, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output: str | None=None) -> str:
        path_obj = basefwx.pathlib.Path(path)
        basefwx._ensure_existing_file(path_obj)
        password = basefwx._resolve_password(password, use_master=True)
        output_path = basefwx.pathlib.Path(output) if output else basefwx.ImageCipher._default_decrypted_path(path_obj)
        file_bytes = path_obj.read_bytes()
        orig_blob = None
        key_blob = None
        payload_bytes = file_bytes
        trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_TRAILER_MAGIC)
        if trailer is not None:
            orig_blob, payload_bytes = trailer
        else:
            key_trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
            if key_trailer is not None:
                key_blob, payload_bytes = key_trailer
        arr, mode, fmt = basefwx.ImageCipher._load_image(path_obj, payload_bytes)
        shape = arr.shape
        if arr.ndim == 2:
            channels = 1
            flat = arr.reshape(-1, 1).astype(basefwx.np.uint8, copy=True)
        else:
            channels = shape[2]
            flat = arr.reshape(-1, channels).astype(basefwx.np.uint8, copy=True)
        num_pixels = flat.shape[0]
        material_override = None
        if orig_blob is not None:
            header = basefwx._jmg_parse_key_header(orig_blob, password, use_master=True)
            if header is not None:
                header_len, _, archive_key, material_override, profile_id = header
                archive_blob = orig_blob[header_len:]
                archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
            else:
                if not password:
                    raise ValueError('Password required for legacy image trailer decryption')
                material_legacy = basefwx._derive_key_material(password, basefwx.IMAGECIPHER_STREAM_INFO, length=64, iterations=max(200000, basefwx.USER_KDF_ITERATIONS))
                archive_key = basefwx._hkdf_sha256(material_legacy, info=basefwx.IMAGECIPHER_ARCHIVE_INFO)
                archive_blob = orig_blob
                archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
            try:
                original_bytes = basefwx._aead_decrypt(archive_key, archive_blob, archive_info)
                output_path.write_bytes(original_bytes)
                basefwx._del('mask')
                basefwx._del('rotations')
                basefwx._del('perm')
                basefwx._del('flat')
                basefwx._del('arr')
                basefwx._del('archive_key')
                basefwx._del('archive_blob')
                basefwx._del('material_legacy')
                print(f'✅ Decrypted image → {output_path}')
                return str(output_path)
            except Exception:
                pass
        if key_blob is not None:
            header = basefwx._jmg_parse_key_header(key_blob, password, use_master=True)
            if header is None:
                raise ValueError('Invalid JMG key trailer')
            header_len, _, _, material_override, _ = header
            if header_len != len(key_blob):
                raise ValueError('Invalid JMG key trailer payload')
            warnings.warn('jMG no-archive payload detected; restored media may not be byte-identical to the original input.', UserWarning)
        mask, rotations, perm, material = basefwx.ImageCipher._image_primitives(password, num_pixels, channels, material=material_override)
        inv_perm = basefwx.np.empty_like(perm)
        inv_perm[perm] = basefwx.np.arange(num_pixels, dtype=perm.dtype)
        flat = flat.take(inv_perm, axis=0)
        if rotations is not None:
            rows = basefwx.np.arange(num_pixels, dtype=basefwx.np.intp)[:, None]
            base_idx = basefwx.np.arange(channels, dtype=basefwx.np.intp)
            idx = (base_idx - rotations[:, None]) % channels
            flat = flat[rows, idx]
        basefwx.np.bitwise_xor(flat, mask, out=flat)
        recovered = flat.reshape(shape)
        image = basefwx.Image.fromarray(recovered.astype(basefwx.np.uint8), mode)
        save_kwargs: dict[str, basefwx.typing.Any] = {}
        if fmt:
            save_kwargs['format'] = fmt
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = output_path.with_name(f'{output_path.stem}._tmp{output_path.suffix}')
        image.save(temp_path, **save_kwargs)
        image.close()
        basefwx.os.replace(temp_path, output_path)
        basefwx._del('mask')
        basefwx._del('rotations')
        basefwx._del('perm')
        basefwx._del('flat')
        basefwx._del('arr')
        basefwx._del('material')
        basefwx._del('archive_key')
        print(f'✅ Decrypted image → {output_path}')
        return str(output_path)
