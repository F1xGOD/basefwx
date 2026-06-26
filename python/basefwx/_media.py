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
            _warnings_module.warn('jMG no-archive payload detected; restored media may not be byte-identical to the original input.', UserWarning)
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


class MediaCipher:
    """Media cipher for images/videos/audio with deterministic shuffling + AES-CTR masking."""
    VIDEO_GROUP_SECONDS = 1.0
    VIDEO_GROUP_MAX_FRAMES = 12
    VIDEO_BLOCK_SIZE = 2
    VIDEO_MASK_BITS = 6
    VIDEO_MASK_BITS_MAX = 8
    AUDIO_BLOCK_SECONDS = 0.15
    AUDIO_GROUP_SECONDS = 1.0
    AUDIO_MASK_BITS = 13
    AUDIO_MASK_BITS_MAX = 16
    DEFAULT_SECURITY_PROFILE = 1
    JMG_TARGET_GROWTH = 1.1
    JMG_MAX_GROWTH = 2.0
    JMG_MIN_AUDIO_BPS = 64000
    JMG_MIN_VIDEO_BPS = 200000
    TRAILER_FALLBACK_MAX = 64 * 1024 * 1024
    WORKSPACE_RESERVE_BYTES = 64 * 1024 * 1024
    IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.bmp', '.tga', '.gif', '.webp', '.tif', '.tiff', '.heic', '.heif', '.avif', '.ico'}
    VIDEO_EXTS = {'.mp4', '.mkv', '.mov', '.avi', '.webm', '.m4v', '.flv', '.wmv', '.mpg', '.mpeg', '.3gp', '.3g2', '.ts', '.m2ts'}
    AUDIO_EXTS = {'.mp3', '.wav', '.flac', '.aac', '.m4a', '.ogg', '.opus', '.wma', '.aiff', '.alac'}
    HWACCEL_ENV = 'BASEFWX_HWACCEL'
    HWACCEL_STRICT_ENV = 'BASEFWX_HWACCEL_STRICT'
    GPU_PIXELS_ENV = 'BASEFWX_GPU_PIXELS'
    GPU_PIXELS_MIN_BYTES_ENV = 'BASEFWX_GPU_PIXELS_MIN_BYTES'
    GPU_PIXELS_MIN_BYTES_DEFAULT = 1000000
    GPU_PIXELS_AUTO_MIN_BYTES = 8 * 1024 * 1024
    _HWACCEL_CACHE: 'basefwx.typing.Optional[str]' = None
    _HWACCEL_READY = False
    _HWACCEL_ENV_CACHE: 'basefwx.typing.Optional[str]' = None
    _ENCODER_CACHE: 'basefwx.typing.Optional[set[str]]' = None
    _HWACCELS_CACHE: 'basefwx.typing.Optional[set[str]]' = None
    _CUDA_RUNTIME_READY: 'basefwx.typing.Optional[bool]' = None
    _CUDA_RUNTIME_ERROR: str = ''
    _CUDA_RUNTIME_ENV_CACHE: 'basefwx.typing.Optional[str]' = None

    @staticmethod
    def _ensure_ffmpeg() -> None:
        if basefwx.shutil.which('ffmpeg') and basefwx.shutil.which('ffprobe'):
            return
        raise RuntimeError('ffmpeg/ffprobe are required for audio/video processing')

    @staticmethod
    def _ffmpeg_encoder_set() -> 'set[str]':
        cached = basefwx.MediaCipher._ENCODER_CACHE
        if cached is not None:
            return cached
        encoders: set[str] = set()
        try:
            result = basefwx.subprocess.run(['ffmpeg', '-hide_banner', '-encoders'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in (result.stdout or '').splitlines():
                    line = line.strip()
                    if not line or line.startswith('--'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        encoders.add(parts[1])
        except Exception:
            encoders = set()
        basefwx.MediaCipher._ENCODER_CACHE = encoders
        return encoders

    @staticmethod
    def _ffmpeg_hwaccel_set() -> 'set[str]':
        cached = basefwx.MediaCipher._HWACCELS_CACHE
        if cached is not None:
            return cached
        hwaccels: set[str] = set()
        try:
            result = basefwx.subprocess.run(['ffmpeg', '-hide_banner', '-hwaccels'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in (result.stdout or '').splitlines():
                    line = line.strip().lower()
                    if not line or line.startswith('hardware acceleration methods'):
                        continue
                    hwaccels.add(line)
        except Exception:
            hwaccels = set()
        basefwx.MediaCipher._HWACCELS_CACHE = hwaccels
        return hwaccels

    @staticmethod
    def _cuda_runtime_env_key() -> str:
        return f'CUDA_PATH={basefwx.os.getenv('CUDA_PATH', '')}|LD_LIBRARY_PATH={basefwx.os.getenv('LD_LIBRARY_PATH', '')}'

    @classmethod
    def _set_cuda_runtime_state(cls, ready: bool, error: str) -> None:
        cls._CUDA_RUNTIME_READY = ready
        cls._CUDA_RUNTIME_ERROR = error

    @staticmethod
    def _format_cuda_error(exc: Exception) -> str:
        msg = str(exc).strip().replace('\n', ' ')
        if len(msg) > 220:
            msg = msg[:220] + '...'
        if 'cudaErrorInsufficientDriver' in msg:
            msg += ' (driver/runtime mismatch; install a CuPy build matching your NVIDIA driver/CUDA runtime)'
        if 'cuda_fp16.h' in msg:
            msg = 'CUDA headers missing for CuPy JIT (cuda_fp16.h not found). Set CUDA_PATH to your toolkit root (for example /usr or /usr/local/cuda) and ensure include/cuda_fp16.h is present.'
        return msg or exc.__class__.__name__

    @classmethod
    def _cuda_runtime_status(cls) -> 'tuple[bool, str]':
        env_key = cls._cuda_runtime_env_key()
        if cls._CUDA_RUNTIME_ENV_CACHE == env_key and cls._CUDA_RUNTIME_READY is not None:
            return (bool(cls._CUDA_RUNTIME_READY), cls._CUDA_RUNTIME_ERROR)
        cls._CUDA_RUNTIME_ENV_CACHE = env_key
        basefwx._ensure_cp()
        if basefwx.cp is None:
            cls._set_cuda_runtime_state(False, 'CuPy is unavailable')
            return (False, cls._CUDA_RUNTIME_ERROR)
        try:
            count = int(basefwx.cp.cuda.runtime.getDeviceCount())
        except Exception as exc:
            cls._set_cuda_runtime_state(False, cls._format_cuda_error(exc))
            return (False, cls._CUDA_RUNTIME_ERROR)
        if count <= 0:
            cls._set_cuda_runtime_state(False, 'CUDA runtime reports no available devices')
            return (False, cls._CUDA_RUNTIME_ERROR)
        try:
            probe = basefwx.cp.asarray([1], dtype=basefwx.cp.uint8)
            probe ^= basefwx.cp.asarray([1], dtype=basefwx.cp.uint8)
            _ = probe.get()
        except Exception as exc:
            cls._set_cuda_runtime_state(False, cls._format_cuda_error(exc))
            return (False, cls._CUDA_RUNTIME_ERROR)
        cls._set_cuda_runtime_state(True, '')
        return (True, '')

    @staticmethod
    def _hwaccel_strict() -> bool:
        raw = basefwx.os.getenv(basefwx.MediaCipher.HWACCEL_STRICT_ENV, '').strip().lower()
        return raw in {'1', 'true', 'yes', 'on'}

    @staticmethod
    def _has_nvidia_hint() -> bool:
        if basefwx.shutil.which('nvidia-smi') is None:
            return False
        try:
            result = basefwx.subprocess.run(['nvidia-smi', '-L'], capture_output=True, text=True)
            return result.returncode == 0 and bool((result.stdout or '').strip())
        except Exception:
            return False

    @staticmethod
    def _has_qsv_hint() -> bool:
        if basefwx.sys.platform.startswith('linux'):
            return basefwx.os.path.exists('/dev/dri/renderD128')
        if basefwx.sys.platform.startswith('win'):
            return True
        return True

    @staticmethod
    def _has_vaapi_hint() -> bool:
        device = basefwx.os.getenv('BASEFWX_VAAPI_DEVICE', '/dev/dri/renderD128')
        return basefwx.os.path.exists(device)

    @classmethod
    def _select_hwaccel(cls, reasons: 'basefwx.typing.Optional[list[str]]'=None) -> 'basefwx.typing.Optional[str]':
        raw = basefwx.os.getenv(cls.HWACCEL_ENV, 'auto').strip().lower()
        strict = cls._hwaccel_strict()
        vaapi_device = basefwx.os.getenv('BASEFWX_VAAPI_DEVICE', '/dev/dri/renderD128')
        cache_key = f'{raw}|strict={(1 if strict else 0)}|vaapi={vaapi_device}'
        if cls._HWACCEL_READY and cache_key == (cls._HWACCEL_ENV_CACHE or ''):
            if reasons is not None:
                cached = cls._HWACCEL_CACHE or 'cpu'
                reasons.append(f'cached selection reused ({cached})')
            return cls._HWACCEL_CACHE
        cls._HWACCEL_READY = True
        cls._HWACCEL_ENV_CACHE = cache_key
        if raw in {'0', 'off', 'false', 'no'}:
            if reasons is not None:
                reasons.append(f'{cls.HWACCEL_ENV} requested CPU-only mode')
            cls._HWACCEL_CACHE = None
            return None
        if raw in {'1', 'true', 'yes', ''}:
            raw = 'auto'
        encoders = cls._ffmpeg_encoder_set()
        hwaccels = cls._ffmpeg_hwaccel_set()

        def _available(mode: str) -> bool:
            if mode == 'nvenc':
                return 'h264_nvenc' in encoders and 'cuda' in hwaccels and cls._has_nvidia_hint()
            if mode == 'qsv':
                return 'h264_qsv' in encoders and 'qsv' in hwaccels and cls._has_qsv_hint()
            if mode == 'vaapi':
                return 'h264_vaapi' in encoders and 'vaapi' in hwaccels and cls._has_vaapi_hint()
            return False
        prefer = None
        if raw in {'cuda', 'nvenc', 'nvidia'}:
            prefer = 'nvenc'
        elif raw in {'qsv', 'intel'}:
            prefer = 'qsv'
        elif raw in {'vaapi'}:
            prefer = 'vaapi'
        elif raw in {'cpu'}:
            if reasons is not None:
                reasons.append(f'{cls.HWACCEL_ENV}=cpu forces CPU-only encode/decode')
            prefer = None
        elif raw != 'auto':
            if reasons is not None:
                reasons.append(f"unrecognized {cls.HWACCEL_ENV} value '{raw}', falling back to auto")
            raw = 'auto'
        if prefer:
            if _available(prefer):
                if reasons is not None:
                    reasons.append(f'{cls.HWACCEL_ENV} explicitly requested {prefer}')
                cls._HWACCEL_CACHE = prefer
                return prefer
            cls._HWACCEL_CACHE = None
            if reasons is not None:
                reasons.append(f'{cls.HWACCEL_ENV} requested {prefer} but it is unavailable')
            if strict:
                raise RuntimeError(f'{cls.HWACCEL_ENV}={prefer} requested but unavailable; set BASEFWX_HWACCEL=auto or disable strict mode')
            if reasons is not None:
                reasons.append('strict mode disabled, falling back to CPU')
            return None
        if raw == 'auto':
            if _available('nvenc'):
                if reasons is not None:
                    reasons.append('auto selected nvenc (NVIDIA preferred)')
                cls._HWACCEL_CACHE = 'nvenc'
                return 'nvenc'
            if _available('qsv'):
                if reasons is not None:
                    reasons.append('auto selected qsv (Intel fallback)')
                cls._HWACCEL_CACHE = 'qsv'
                return 'qsv'
            if _available('vaapi'):
                if reasons is not None:
                    reasons.append('auto selected vaapi (generic GPU fallback)')
                cls._HWACCEL_CACHE = 'vaapi'
                return 'vaapi'
            if reasons is not None:
                reasons.append('auto could not find usable GPU acceleration')
        cls._HWACCEL_CACHE = None
        return None

    @staticmethod
    def _ffmpeg_video_decode_args(hwaccel: 'basefwx.typing.Optional[str]') -> 'list[str]':
        if hwaccel == 'nvenc':
            return ['-hwaccel', 'cuda', '-hwaccel_output_format', 'cuda']
        if hwaccel == 'qsv':
            return ['-hwaccel', 'qsv']
        if hwaccel == 'vaapi':
            device = basefwx.os.getenv('BASEFWX_VAAPI_DEVICE', '/dev/dri/renderD128')
            return ['-hwaccel', 'vaapi', '-hwaccel_device', device]
        return []

    @staticmethod
    def _detect_aes_accel_state() -> str:
        try:
            if basefwx.sys.platform.startswith('linux'):
                with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='ignore') as handle:
                    data = handle.read().lower()
                return 'aesni' if ' aes ' in f' {data.replace(chr(10), ' ')} ' else 'unknown'
            if basefwx.sys.platform == 'darwin':
                cmd = ['sysctl', '-n', 'machdep.cpu.features']
                result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
                features = (result.stdout or '').upper()
                if 'AES' in features:
                    return 'aesni'
                cmd = ['sysctl', '-n', 'machdep.cpu.leaf7_features']
                result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
                if 'AES' in (result.stdout or '').upper():
                    return 'aesni'
                return 'unknown'
            if basefwx.sys.platform.startswith('win'):
                return 'unknown'
        except Exception:
            return 'unknown'
        return 'unknown'

    @classmethod
    def _gpu_pixels_policy(cls) -> 'tuple[str, int]':
        mode = basefwx.os.getenv(cls.GPU_PIXELS_ENV, 'auto').strip().lower()
        if mode in {'', '1', 'true', 'yes', 'on'}:
            mode = 'auto'
        elif mode in {'0', 'off', 'false', 'no'}:
            mode = 'cpu'
        elif mode not in {'auto', 'cuda', 'cpu'}:
            mode = 'auto'
        raw_min = basefwx.os.getenv(cls.GPU_PIXELS_MIN_BYTES_ENV, '').strip()
        min_bytes = cls.GPU_PIXELS_MIN_BYTES_DEFAULT
        if raw_min:
            try:
                min_bytes = max(1, int(raw_min))
            except Exception:
                min_bytes = cls.GPU_PIXELS_MIN_BYTES_DEFAULT
        return (mode, min_bytes)

    @classmethod
    def _build_hw_execution_plan(cls, op_name: str, *, stream_type: str='bytes', frame_bytes: int=0, allow_pixel_gpu: bool=False, prefer_cpu_decode: bool=True) -> 'dict[str, basefwx.typing.Any]':
        reasons: 'list[str]' = []
        selected_accel: 'basefwx.typing.Optional[str]' = None
        if stream_type in {'video', 'live'}:
            selected_accel = cls._select_hwaccel(reasons=reasons)
        else:
            reasons.append('non-video pipeline uses CPU-only media path')
        encode_device = selected_accel or 'cpu'
        decode_device = 'cpu' if prefer_cpu_decode else encode_device
        pixel_backend = 'cpu'
        gpu_pixels_strict = False
        pixel_workers = cls._media_workers()
        parallel_workers = cls._media_workers()
        parallel_enabled = parallel_workers > 1
        gpu_pixels_mode = 'cpu'
        if allow_pixel_gpu:
            mode, min_bytes = cls._gpu_pixels_policy()
            gpu_pixels_mode = mode
            if mode == 'cuda':
                min_bytes = 0
            if mode == 'cpu':
                reasons.append(f'{cls.GPU_PIXELS_ENV}=cpu forces CPU pixel transforms')
            elif selected_accel != 'nvenc':
                reasons.append('CUDA pixel path disabled because NVIDIA backend is unavailable')
                if mode == 'cuda' and cls._hwaccel_strict():
                    raise RuntimeError('BASEFWX_GPU_PIXELS=cuda requested but NVIDIA/CUDA hwaccel is unavailable')
            elif mode == 'auto' and frame_bytes < max(min_bytes, cls.GPU_PIXELS_AUTO_MIN_BYTES):
                reasons.append(f'CUDA pixel path skipped in auto mode (frame={frame_bytes}B below auto threshold={max(min_bytes, cls.GPU_PIXELS_AUTO_MIN_BYTES)}B)')
            elif frame_bytes < min_bytes:
                reasons.append(f'CUDA pixel path skipped (frame={frame_bytes}B < threshold={min_bytes}B)')
            else:
                cuda_ready, cuda_error = cls._cuda_runtime_status()
                if not cuda_ready:
                    reasons.append(f'CUDA pixel path skipped because {cuda_error}')
                    if mode == 'cuda' and cls._hwaccel_strict():
                        raise RuntimeError(f'BASEFWX_GPU_PIXELS=cuda requested but CUDA runtime is unavailable: {cuda_error}')
                else:
                    pixel_backend = 'cuda'
                    if pixel_workers > 1:
                        pixel_workers = 1
                        reasons.append('CUDA pixel path forces single worker to avoid GPU thread contention')
                    reasons.append('CUDA pixel path enabled for large-frame masking')
            if mode == 'cuda' and cls._hwaccel_strict() and (pixel_backend != 'cuda'):
                raise RuntimeError('BASEFWX_GPU_PIXELS=cuda requested but CUDA pixel backend could not be enabled')
            gpu_pixels_strict = bool(mode == 'cuda' and cls._hwaccel_strict())
        if prefer_cpu_decode and selected_accel and (stream_type == 'video'):
            reasons.append('decode pinned to CPU to avoid hwdownload for CPU-side transforms')
        aes_accel_state = cls._detect_aes_accel_state()
        reasons.append('AES operations remain on CPU (OpenSSL/cryptography path)')
        if stream_type == 'live':
            reasons.append('live stream helpers keep crypto on CPU; codec hwaccel is delegated to ffmpeg command')
        return {'op_name': op_name, 'stream_type': stream_type, 'selected_accel': selected_accel, 'encode_device': encode_device, 'decode_device': decode_device, 'pixel_backend': pixel_backend, 'gpu_pixels_strict': gpu_pixels_strict, 'pixel_workers': pixel_workers, 'parallel_enabled': parallel_enabled, 'parallel_workers': parallel_workers, 'crypto_device': 'cpu', 'aes_accel_state': aes_accel_state, 'reasons': reasons}

    @staticmethod
    def _hw_log_color_enabled() -> bool:
        if basefwx.os.getenv('NO_COLOR'):
            return False
        stream = getattr(basefwx.sys, 'stderr', None)
        return bool(stream and hasattr(stream, 'isatty') and stream.isatty())

    @staticmethod
    def _hw_color(text: str, code: str) -> str:
        if not basefwx.MediaCipher._hw_log_color_enabled():
            return text
        return f'\x1b[{code}m{text}\x1b[0m'

    @staticmethod
    def _hw_verbose_enabled() -> bool:
        raw = basefwx.os.getenv('BASEFWX_VERBOSE', '').strip().lower()
        return raw in {'1', 'true', 'yes', 'on'}

    @staticmethod
    def _log_hw_execution_plan(plan: 'dict[str, basefwx.typing.Any]') -> None:
        reason = '; '.join(plan.get('reasons', []))
        encode = str(plan.get('encode_device', 'cpu')).upper()
        decode = str(plan.get('decode_device', 'cpu')).upper()
        pixels = str(plan.get('pixel_backend', 'cpu')).upper()
        crypto = str(plan.get('crypto_device', 'cpu')).upper()
        aes = str(plan.get('aes_accel_state', 'unknown'))
        parallel_enabled = bool(plan.get('parallel_enabled', False))
        parallel_workers = int(plan.get('parallel_workers') or 1)
        parallel_text = f'ON({parallel_workers}w)' if parallel_enabled else 'OFF'
        header = f'🎛️ [basefwx.hw] op={plan.get('op_name', 'unknown')} encode={encode} decode={decode} pixels={pixels} parallel={parallel_text} crypto={crypto} aes_accel={aes}'
        detail = f'   reason: {reason or 'n/a'}'
        if basefwx.MediaCipher._hw_log_color_enabled():
            header = f'🎛️ {basefwx.MediaCipher._hw_color('[basefwx.hw]', '36;1')} op={basefwx.MediaCipher._hw_color(str(plan.get('op_name', 'unknown')), '1')} encode={basefwx.MediaCipher._hw_color(encode, '32;1')} decode={basefwx.MediaCipher._hw_color(decode, '33;1')} pixels={basefwx.MediaCipher._hw_color(pixels, '35;1')} parallel={basefwx.MediaCipher._hw_color(parallel_text, '37;1')} crypto={basefwx.MediaCipher._hw_color(crypto, '34;1')} aes_accel={basefwx.MediaCipher._hw_color(aes, '36')}'
            detail = f'   {basefwx.MediaCipher._hw_color('reason:', '2')} {reason or 'n/a'}'
        if basefwx.MediaCipher._hw_verbose_enabled():
            msg = f'{header}\n{detail}'
        else:
            msg = header
        try:
            print(msg, file=basefwx.sys.stderr)
        except Exception:
            pass

    @staticmethod
    def _parse_rate(rate: str) -> float:
        if not rate or rate == '0/0':
            return 0.0
        if '/' in rate:
            num, den = rate.split('/', 1)
            try:
                return float(num) / float(den)
            except Exception:
                return 0.0
        try:
            return float(rate)
        except Exception:
            return 0.0

    @staticmethod
    def _probe_streams(path: 'basefwx.pathlib.Path') -> 'dict[str, basefwx.typing.Any]':
        basefwx.MediaCipher._ensure_ffmpeg()
        cmd = ['ffprobe', '-v', 'error', '-show_entries', 'stream=codec_type,width,height,avg_frame_rate,r_frame_rate,sample_rate,channels,bit_rate:stream_disposition=attached_pic:format=duration,bit_rate', '-of', 'json', str(path)]
        result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f'ffprobe failed: {result.stderr.strip() or 'unknown error'}')
        data = basefwx.json.loads(result.stdout or '{}')
        streams = data.get('streams', []) or []
        video = None
        audio = None
        has_audio_stream = any((stream.get('codec_type') == 'audio' for stream in streams))
        for stream in streams:
            if stream.get('codec_type') == 'video':
                disposition = stream.get('disposition') or {}
                try:
                    attached_pic = int(disposition.get('attached_pic') or 0) == 1
                except Exception:
                    attached_pic = False
                if not attached_pic and has_audio_stream:
                    try:
                        rate_hint = basefwx.MediaCipher._parse_rate(stream.get('avg_frame_rate') or stream.get('r_frame_rate') or '')
                    except Exception:
                        rate_hint = 0.0
                    try:
                        bitrate_hint = int(float(stream.get('bit_rate') or 0.0))
                    except Exception:
                        bitrate_hint = 0
                    if rate_hint <= 0.0 and bitrate_hint <= 0:
                        attached_pic = True
                if attached_pic:
                    continue
            if stream.get('codec_type') == 'video' and video is None:
                video = stream
            elif stream.get('codec_type') == 'audio' and audio is None:
                audio = stream
        info: dict[str, basefwx.typing.Any] = {}
        fmt = data.get('format', {}) or {}
        try:
            info['duration'] = float(fmt.get('duration') or 0.0)
        except Exception:
            info['duration'] = 0.0
        try:
            info['bit_rate'] = int(float(fmt.get('bit_rate') or 0.0))
        except Exception:
            info['bit_rate'] = 0
        if video:
            fps = basefwx.MediaCipher._parse_rate(video.get('avg_frame_rate') or video.get('r_frame_rate') or '')
            try:
                video_bps = int(float(video.get('bit_rate') or 0.0))
            except Exception:
                video_bps = 0
            info['video'] = {'width': int(video.get('width') or 0), 'height': int(video.get('height') or 0), 'fps': fps, 'bit_rate': video_bps}
        if audio:
            try:
                audio_bps = int(float(audio.get('bit_rate') or 0.0))
            except Exception:
                audio_bps = 0
            info['audio'] = {'sample_rate': int(audio.get('sample_rate') or 0), 'channels': int(audio.get('channels') or 0), 'bit_rate': audio_bps}
        return info

    @staticmethod
    def _estimate_bitrates(path: 'basefwx.pathlib.Path', info: 'dict[str, basefwx.typing.Any]') -> 'tuple[int | None, int | None]':
        total_bps = int(info.get('bit_rate') or 0)
        duration = float(info.get('duration') or 0.0)
        if total_bps <= 0 and duration > 0:
            try:
                total_bps = int(path.stat().st_size * 8 / duration)
            except Exception:
                total_bps = 0
        video_bps = int((info.get('video') or {}).get('bit_rate') or 0)
        audio_bps = int((info.get('audio') or {}).get('bit_rate') or 0)
        if total_bps > 0:
            target_total = int(total_bps * basefwx.MediaCipher.JMG_TARGET_GROWTH)
            max_total = int(total_bps * basefwx.MediaCipher.JMG_MAX_GROWTH)
            if target_total <= 0:
                target_total = total_bps
            if target_total > max_total:
                target_total = max_total
            if info.get('video') and video_bps <= 0:
                if audio_bps > 0:
                    video_bps = max(1, target_total - audio_bps)
                else:
                    video_bps = max(basefwx.MediaCipher.JMG_MIN_VIDEO_BPS, int(target_total * 0.85))
            if info.get('audio') and audio_bps <= 0:
                audio_bps = max(basefwx.MediaCipher.JMG_MIN_AUDIO_BPS, int(target_total * 0.15))
            if video_bps > 0:
                video_bps = min(video_bps, max_total)
            if audio_bps > 0:
                audio_bps = min(audio_bps, max_total)
        return (video_bps or None, audio_bps or None)

    @staticmethod
    def _format_bytes(value: int) -> str:
        units = ('B', 'KiB', 'MiB', 'GiB', 'TiB')
        amount = float(max(0, int(value)))
        for unit in units:
            if amount < 1024.0 or unit == units[-1]:
                if unit == 'B':
                    return f'{int(amount)}{unit}'
                return f'{amount:.1f}{unit}'
            amount /= 1024.0
        return f'{int(value)}B'

    @staticmethod
    def _workspace_free_bytes(path: 'basefwx.pathlib.Path') -> int:
        try:
            return int(basefwx.shutil.disk_usage(path).free)
        except Exception:
            return -1

    @classmethod
    def _ensure_workspace_free(cls, workspace: 'basefwx.pathlib.Path', required: int, stage: str) -> None:
        if required <= 0:
            return
        free = cls._workspace_free_bytes(workspace)
        if free < 0 or free >= required:
            return
        raise RuntimeError(f"Insufficient temp workspace for {stage}: need about {cls._format_bytes(required)}, have {cls._format_bytes(free)} free at '{workspace}'. This jMG pipeline uses raw media scratch files; reduce input duration/resolution, free disk space, or point TMPDIR to a larger filesystem.")

    @classmethod
    def _estimate_video_workspace_need(cls, info: 'dict[str, basefwx.typing.Any]') -> int:
        video = info.get('video') or {}
        audio = info.get('audio') or {}
        width = int(video.get('width') or 0)
        height = int(video.get('height') or 0)
        fps = float(video.get('fps') or 0.0)
        duration = float(info.get('duration') or 0.0)
        if width <= 0 or height <= 0 or fps <= 0.0 or (duration <= 0.0):
            return 0
        frame_size = width * height * 3
        frame_count = max(1, int(duration * fps + 0.999))
        video_raw = frame_size * frame_count
        audio_raw = 0
        sample_rate = int(audio.get('sample_rate') or 0)
        channels = int(audio.get('channels') or 0)
        if sample_rate > 0 and channels > 0:
            audio_raw = int(duration * sample_rate * channels * 2)
        return 2 * video_raw + 2 * audio_raw + cls.WORKSPACE_RESERVE_BYTES

    @classmethod
    def _estimate_audio_workspace_need(cls, info: 'dict[str, basefwx.typing.Any]') -> int:
        audio = info.get('audio') or {}
        duration = float(info.get('duration') or 0.0)
        sample_rate = int(audio.get('sample_rate') or 0)
        channels = int(audio.get('channels') or 0)
        if duration <= 0.0 or sample_rate <= 0 or channels <= 0:
            return cls.WORKSPACE_RESERVE_BYTES
        audio_raw = int(duration * sample_rate * channels * 2)
        return 2 * audio_raw + cls.WORKSPACE_RESERVE_BYTES

    @staticmethod
    def _probe_metadata(path: 'basefwx.pathlib.Path') -> 'dict[str, str]':
        basefwx.MediaCipher._ensure_ffmpeg()
        cmd = ['ffprobe', '-v', 'error', '-show_entries', 'format_tags', '-of', 'json', str(path)]
        result = basefwx.subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {}
        data = basefwx.json.loads(result.stdout or '{}')
        tags = (data.get('format', {}) or {}).get('tags', {}) or {}
        clean: dict[str, str] = {}
        for key, value in tags.items():
            if isinstance(value, str) and value:
                clean[str(key)] = value
        return clean

    @staticmethod
    def _derive_base_key(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, security_profile: int=0) -> bytes:
        material = basefwx.MediaCipher._derive_media_material(password, security_profile=security_profile)
        return material[:32]

    @staticmethod
    def _derive_media_material(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', *, security_profile: int=0) -> bytes:
        return basefwx._derive_key_material(basefwx._coerce_password_bytes(password), basefwx._jmg_stream_info_for_profile(security_profile), length=64, iterations=max(200000, basefwx.USER_KDF_ITERATIONS))

    @staticmethod
    def _unit_material(base_key: bytes, label: bytes, index: int, length: int) -> bytes:
        info = label + index.to_bytes(8, 'big')
        return basefwx._hkdf_sha256(base_key, info=info, length=length)

    @staticmethod
    def _permute_indices(count: int, seed: int) -> 'list[int]':
        order = list(range(count))
        st = seed & (1 << 64) - 1
        for i in range(count - 1, 0, -1):
            st, rnd = basefwx._splitmix64(st)
            j = rnd % (i + 1)
            if j != i:
                order[i], order[j] = (order[j], order[i])
        return order

    @staticmethod
    def _aes_ctr_transform(data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def _audio_mask_transform(data: bytes, key: bytes, iv: bytes, *, mask_bits: int | None=None) -> bytes:
        if not data:
            return b''
        tail = b''
        if len(data) % 2:
            tail = data[-1:]
            data = data[:-1]
        cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
        encryptor = cipher.encryptor()
        keystream = encryptor.update(bytes(len(data))) + encryptor.finalize()
        bits = basefwx.MediaCipher.AUDIO_MASK_BITS if mask_bits is None else max(1, min(16, int(mask_bits)))
        mask = (1 << bits) - 1
        out = bytearray(len(data))
        if basefwx.np is not None and len(data) >= 2:
            try:
                np_samples = basefwx.np.frombuffer(data, dtype=basefwx.np.dtype('<u2')).copy()
                np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.dtype('<u2'))
                basefwx.np.bitwise_xor(np_samples, basefwx.np.bitwise_and(np_keystream, mask), out=np_samples)
                return np_samples.tobytes() + tail
            except Exception:
                pass
        for i in range(0, len(data), 2):
            sample = int.from_bytes(data[i:i + 2], 'little', signed=False)
            ks = keystream[i] | keystream[i + 1] << 8
            sample ^= ks & mask
            out[i:i + 2] = sample.to_bytes(2, 'little', signed=False)
        return bytes(out) + tail

    @staticmethod
    def _video_mask_transform(data: bytes, key: bytes, iv: bytes, *, mask_bits: int | None=None, use_cuda: bool=False, cuda_strict: bool=False) -> bytes:
        if not data:
            return b''
        cipher = basefwx.Cipher(basefwx.algorithms.AES(key), basefwx.modes.CTR(iv))
        encryptor = cipher.encryptor()
        keystream = encryptor.update(bytes(len(data))) + encryptor.finalize()
        bits = basefwx.MediaCipher.VIDEO_MASK_BITS if mask_bits is None else max(1, min(8, int(mask_bits)))
        mask = (1 << bits) - 1
        if use_cuda:
            basefwx._ensure_cp()
            if basefwx.cp is None or basefwx.np is None:
                if cuda_strict:
                    raise RuntimeError('CUDA pixel path requested but CuPy/NumPy is unavailable')
            else:
                ready, reason = basefwx.MediaCipher._cuda_runtime_status()
                if not ready:
                    if cuda_strict:
                        raise RuntimeError(f'CUDA pixel path requested but CUDA runtime is unavailable: {reason}')
                    use_cuda = False
                if use_cuda:
                    try:
                        np_data = basefwx.np.frombuffer(data, dtype=basefwx.np.uint8).copy()
                        np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.uint8)
                        gpu_data = basefwx.cp.asarray(np_data)
                        gpu_keystream = basefwx.cp.asarray(np_keystream)
                        gpu_data ^= gpu_keystream & mask
                        return basefwx.cp.asnumpy(gpu_data).tobytes()
                    except Exception as exc:
                        err = str(exc).strip().replace('\n', ' ')
                        if len(err) > 220:
                            err = err[:220] + '...'
                        basefwx.MediaCipher._set_cuda_runtime_state(False, err or exc.__class__.__name__)
                        if cuda_strict:
                            raise RuntimeError(f'CUDA pixel path failed during frame transform: {err or exc.__class__.__name__}') from None
        if basefwx.np is not None:
            try:
                np_data = basefwx.np.frombuffer(data, dtype=basefwx.np.uint8).copy()
                np_keystream = basefwx.np.frombuffer(keystream, dtype=basefwx.np.uint8)
                basefwx.np.bitwise_xor(np_data, basefwx.np.bitwise_and(np_keystream, mask), out=np_data)
                return np_data.tobytes()
            except Exception:
                pass
        out = bytearray(data)
        for i in range(len(out)):
            out[i] ^= keystream[i] & mask
        return bytes(out)

    @staticmethod
    def _ffmpeg_video_codec_args(output_path: 'basefwx.pathlib.Path', target_bitrate: int | None=None, hwaccel: 'basefwx.typing.Optional[str]'=None, *, lossless: bool=False) -> 'list[str]':

        def _video_rate_kbps(bits_per_second: int) -> 'tuple[int, int]':
            max_kbps = 2000000
            rate_kbps = max(100, min(bits_per_second // 1000, max_kbps))
            buf_kbps = max(rate_kbps, min(rate_kbps * 2, max_kbps))
            return (rate_kbps, buf_kbps)
        ext = output_path.suffix.lower()
        if lossless:
            if ext in {'.mkv', '.avi'}:
                return ['-c:v', 'ffv1', '-level', '3', '-g', '1', '-pix_fmt', 'rgb24']
            if ext == '.webm':
                return ['-c:v', 'libvpx-vp9', '-lossless', '1', '-pix_fmt', 'yuv444p']
            return ['-c:v', 'libx264rgb', '-preset', 'veryfast', '-crf', '0', '-pix_fmt', 'rgb24']
        if target_bitrate and target_bitrate > 0:
            kbps, buf_kbps = _video_rate_kbps(target_bitrate)
            if ext == '.webm':
                return ['-c:v', 'libvpx-vp9', '-b:v', f'{kbps}k', '-crf', '33', '-pix_fmt', 'yuv420p']
            if hwaccel == 'nvenc':
                return ['-c:v', 'h264_nvenc', '-preset', 'p4', '-b:v', f'{kbps}k', '-maxrate', f'{kbps}k', '-bufsize', f'{buf_kbps}k', '-pix_fmt', 'yuv420p']
            if hwaccel == 'qsv':
                return ['-c:v', 'h264_qsv', '-b:v', f'{kbps}k', '-maxrate', f'{kbps}k', '-bufsize', f'{buf_kbps}k', '-pix_fmt', 'yuv420p']
            if hwaccel == 'vaapi':
                device = basefwx.os.getenv('BASEFWX_VAAPI_DEVICE', '/dev/dri/renderD128')
                return ['-vaapi_device', device, '-vf', 'format=nv12,hwupload', '-c:v', 'h264_vaapi', '-b:v', f'{kbps}k', '-maxrate', f'{kbps}k', '-bufsize', f'{buf_kbps}k']
            return ['-c:v', 'libx264', '-preset', 'veryfast', '-b:v', f'{kbps}k', '-maxrate', f'{kbps}k', '-bufsize', f'{buf_kbps}k', '-pix_fmt', 'yuv420p']
        if ext == '.webm':
            return ['-c:v', 'libvpx-vp9', '-b:v', '0', '-crf', '32', '-pix_fmt', 'yuv420p']
        if hwaccel == 'nvenc':
            return ['-c:v', 'h264_nvenc', '-preset', 'p4', '-cq', '23', '-pix_fmt', 'yuv420p']
        if hwaccel == 'qsv':
            return ['-c:v', 'h264_qsv', '-global_quality', '23', '-pix_fmt', 'yuv420p']
        if hwaccel == 'vaapi':
            device = basefwx.os.getenv('BASEFWX_VAAPI_DEVICE', '/dev/dri/renderD128')
            return ['-vaapi_device', device, '-vf', 'format=nv12,hwupload', '-c:v', 'h264_vaapi', '-qp', '23']
        return ['-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23', '-pix_fmt', 'yuv420p']

    @staticmethod
    def _ffmpeg_audio_codec_args(output_path: 'basefwx.pathlib.Path', target_bitrate: int | None=None, *, lossless: bool=False) -> 'list[str]':
        ext = output_path.suffix.lower()
        if lossless:
            if ext in {'.mp4', '.m4v', '.mov', '.m4a'}:
                return ['-c:a', 'alac']
            if ext in {'.mkv', '.flac'}:
                return ['-c:a', 'flac']
            if ext in {'.wav', '.aiff', '.aif', '.avi'}:
                return ['-c:a', 'pcm_s16le']
        if target_bitrate and target_bitrate > 0:
            kbps = max(48, target_bitrate // 1000)
        else:
            kbps = 0
        if ext == '.mp3':
            return ['-c:a', 'libmp3lame', '-b:a', f'{kbps or 192}k']
        if ext in {'.flac'}:
            return ['-c:a', 'flac']
        if ext in {'.wav', '.aiff', '.aif'}:
            return ['-c:a', 'pcm_s16le']
        if ext in {'.ogg', '.opus', '.webm'}:
            return ['-c:a', 'libopus', '-b:a', f'{kbps or 96}k']
        if ext in {'.m4a', '.aac'}:
            return ['-c:a', 'aac', '-b:a', f'{kbps or 160}k']
        return ['-c:a', 'aac', '-b:a', f'{kbps or 160}k']

    @staticmethod
    def _ffmpeg_container_args(output_path: 'basefwx.pathlib.Path') -> 'list[str]':
        if output_path.suffix.lower() in {'.mp4', '.m4v', '.mov', '.m4a'}:
            return ['-movflags', '+faststart']
        return []

    @staticmethod
    def _media_workers() -> int:
        raw = basefwx.os.getenv('BASEFWX_MEDIA_WORKERS')
        if raw:
            try:
                value = int(raw)
                return max(1, value)
            except Exception:
                pass
        return max(1, basefwx.os.cpu_count() or 1)

    @staticmethod
    def _jmg_lossless_no_archive() -> bool:
        raw = basefwx.os.getenv('BASEFWX_JMG_NOARCHIVE_LOSSLESS', '1').strip().lower()
        return raw not in {'0', 'false', 'no', 'off'}

    @staticmethod
    def _jmg_profile_label(label: bytes, security_profile: int) -> bytes:
        if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
            return label + b'.max'
        return label

    @staticmethod
    def _jmg_video_mask_bits(security_profile: int) -> int:
        if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
            return basefwx.MediaCipher.VIDEO_MASK_BITS_MAX
        return basefwx.MediaCipher.VIDEO_MASK_BITS

    @staticmethod
    def _jmg_audio_mask_bits(security_profile: int) -> int:
        if security_profile == basefwx.JMG_SECURITY_PROFILE_MAX:
            return basefwx.MediaCipher.AUDIO_MASK_BITS_MAX
        return basefwx.MediaCipher.AUDIO_MASK_BITS

    @staticmethod
    def _shuffle_frame_blocks(frame: bytes, width: int, height: int, channels: int, seed: int, block_size: int) -> bytes:
        blocks_x = (width + block_size - 1) // block_size
        blocks_y = (height + block_size - 1) // block_size
        total_blocks = blocks_x * blocks_y
        perm = basefwx.MediaCipher._permute_indices(total_blocks, seed)
        if basefwx.np is not None and channels > 0 and (len(frame) == width * height * channels) and (width % block_size == 0) and (height % block_size == 0):
            try:
                arr = basefwx.np.frombuffer(frame, dtype=basefwx.np.uint8).reshape(height, width, channels)
                blocks = arr.reshape(blocks_y, block_size, blocks_x, block_size, channels).transpose(0, 2, 1, 3, 4).reshape(total_blocks, block_size, block_size, channels)
                perm_arr = basefwx.np.asarray(perm, dtype=basefwx.np.intp)
                shuffled = blocks[perm_arr]
                out_arr = shuffled.reshape(blocks_y, blocks_x, block_size, block_size, channels).transpose(0, 2, 1, 3, 4).reshape(height, width, channels)
                return out_arr.tobytes()
            except Exception:
                pass
        out = bytearray(len(frame))
        for dest_idx in range(total_blocks):
            src_idx = perm[dest_idx]
            dx = dest_idx % blocks_x * block_size
            dy = dest_idx // blocks_x * block_size
            sx = src_idx % blocks_x * block_size
            sy = src_idx // blocks_x * block_size
            copy_w = min(block_size, width - dx, width - sx)
            copy_h = min(block_size, height - dy, height - sy)
            for row in range(copy_h):
                src_off = ((sy + row) * width + sx) * channels
                dst_off = ((dy + row) * width + dx) * channels
                end = src_off + copy_w * channels
                out[dst_off:dst_off + copy_w * channels] = frame[src_off:end]
        return bytes(out)

    @staticmethod
    def _unshuffle_frame_blocks(frame: bytes, width: int, height: int, channels: int, seed: int, block_size: int) -> bytes:
        blocks_x = (width + block_size - 1) // block_size
        blocks_y = (height + block_size - 1) // block_size
        total_blocks = blocks_x * blocks_y
        perm = basefwx.MediaCipher._permute_indices(total_blocks, seed)
        if basefwx.np is not None and channels > 0 and (len(frame) == width * height * channels) and (width % block_size == 0) and (height % block_size == 0):
            try:
                arr = basefwx.np.frombuffer(frame, dtype=basefwx.np.uint8).reshape(height, width, channels)
                blocks = arr.reshape(blocks_y, block_size, blocks_x, block_size, channels).transpose(0, 2, 1, 3, 4).reshape(total_blocks, block_size, block_size, channels)
                inv = basefwx.np.empty(total_blocks, dtype=basefwx.np.intp)
                inv[basefwx.np.asarray(perm, dtype=basefwx.np.intp)] = basefwx.np.arange(total_blocks, dtype=basefwx.np.intp)
                restored = blocks[inv]
                out_arr = restored.reshape(blocks_y, blocks_x, block_size, block_size, channels).transpose(0, 2, 1, 3, 4).reshape(height, width, channels)
                return out_arr.tobytes()
            except Exception:
                pass
        out = bytearray(len(frame))
        for dest_idx in range(total_blocks):
            src_idx = perm[dest_idx]
            dx = dest_idx % blocks_x * block_size
            dy = dest_idx // blocks_x * block_size
            sx = src_idx % blocks_x * block_size
            sy = src_idx // blocks_x * block_size
            copy_w = min(block_size, width - dx, width - sx)
            copy_h = min(block_size, height - dy, height - sy)
            for row in range(copy_h):
                src_off = ((dy + row) * width + dx) * channels
                dst_off = ((sy + row) * width + sx) * channels
                end = src_off + copy_w * channels
                out[dst_off:dst_off + copy_w * channels] = frame[src_off:end]
        return bytes(out)

    @staticmethod
    def _shuffle_audio_samples(block: bytes, seed: int) -> bytes:
        if not block:
            return block
        tail = b''
        if len(block) % 2:
            tail = block[-1:]
            block = block[:-1]
        samples = len(block) // 2
        if samples <= 1:
            return block + tail
        perm = basefwx.MediaCipher._permute_indices(samples, seed)
        if basefwx.np is not None:
            try:
                arr = basefwx.np.frombuffer(block, dtype=basefwx.np.dtype('<u2'))
                shuffled = arr[basefwx.np.asarray(perm, dtype=basefwx.np.intp)]
                return shuffled.tobytes() + tail
            except Exception:
                pass
        out = bytearray(len(block))
        for dest_idx, src_idx in enumerate(perm):
            src_off = src_idx * 2
            dst_off = dest_idx * 2
            out[dst_off:dst_off + 2] = block[src_off:src_off + 2]
        return bytes(out) + tail

    @staticmethod
    def _unshuffle_audio_samples(block: bytes, seed: int) -> bytes:
        if not block:
            return block
        tail = b''
        if len(block) % 2:
            tail = block[-1:]
            block = block[:-1]
        samples = len(block) // 2
        if samples <= 1:
            return block + tail
        perm = basefwx.MediaCipher._permute_indices(samples, seed)
        if basefwx.np is not None:
            try:
                arr = basefwx.np.frombuffer(block, dtype=basefwx.np.dtype('<u2'))
                out_arr = basefwx.np.empty(samples, dtype=basefwx.np.dtype('<u2'))
                out_arr[basefwx.np.asarray(perm, dtype=basefwx.np.intp)] = arr
                return out_arr.tobytes() + tail
            except Exception:
                pass
        out = bytearray(len(block))
        for dest_idx, src_idx in enumerate(perm):
            src_off = src_idx * 2
            dst_off = dest_idx * 2
            out[src_off:src_off + 2] = block[dst_off:dst_off + 2]
        return bytes(out) + tail

    @staticmethod
    def _video_group_frames(fps: float) -> int:
        group_frames = max(2, int(round((fps or 30.0) * basefwx.MediaCipher.VIDEO_GROUP_SECONDS)))
        max_frames = basefwx.MediaCipher.VIDEO_GROUP_MAX_FRAMES
        raw = basefwx.os.getenv('BASEFWX_VIDEO_GROUP_MAX_FRAMES', '').strip()
        if raw:
            try:
                max_frames = max(2, min(240, int(raw)))
            except Exception:
                max_frames = basefwx.MediaCipher.VIDEO_GROUP_MAX_FRAMES
        return min(group_frames, max_frames)

    @staticmethod
    def _scramble_video_raw(raw_in: 'basefwx.pathlib.Path', raw_out: 'basefwx.pathlib.Path', width: int, height: int, fps: float, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None, use_gpu_pixels: bool=False, gpu_pixels_strict: bool=False) -> None:
        frame_size = width * height * 3
        if frame_size <= 0:
            raise ValueError('Invalid video dimensions')
        group_frames = basefwx.MediaCipher._video_group_frames(fps)
        total_frames = 0
        if progress_cb:
            try:
                total_frames = raw_in.stat().st_size // frame_size
            except Exception:
                total_frames = 0
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_frames))
        processed_frames = 0
        cancelled = False
        frame_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-frame', security_profile)
        frame_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fblk', security_profile)
        frame_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fgrp', security_profile)
        video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
        try:
            with open(raw_in, 'rb') as src, open(raw_out, 'wb') as dst:
                frame_index = 0
                group_index = 0
                while True:
                    group_start_index = frame_index
                    raw_frames: 'list[bytes]' = []
                    for _ in range(group_frames):
                        data = src.read(frame_size)
                        if not data or len(data) < frame_size:
                            break
                        raw_frames.append(data)
                    if not raw_frames:
                        break

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, frame = item
                        frame_id = group_start_index + idx
                        material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        masked = basefwx.MediaCipher._video_mask_transform(frame, key, iv, mask_bits=video_mask_bits, use_cuda=use_gpu_pixels, cuda_strict=gpu_pixels_strict)
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                        seed = int.from_bytes(seed_bytes, 'big')
                        return basefwx.MediaCipher._shuffle_frame_blocks(masked, width, height, 3, seed, basefwx.MediaCipher.VIDEO_BLOCK_SIZE)
                    if executor:
                        frames = list(executor.map(_process, enumerate(raw_frames)))
                    else:
                        frames = [_process(item) for item in enumerate(raw_frames)]
                    seed_index = group_index * 11400714819323198485 ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, 'big')
                    perm = basefwx.MediaCipher._permute_indices(len(frames), seed)
                    for idx in perm:
                        dst.write(frames[idx])
                    processed_frames += len(frames)
                    if progress_cb and total_frames:
                        progress_cb(min(1.0, processed_frames / total_frames))
                    frame_index += len(frames)
                    group_index += 1
        except OSError as exc:
            if getattr(exc, 'errno', None) == 28:
                free = basefwx.MediaCipher._workspace_free_bytes(raw_out.parent)
                raise RuntimeError(f"No space left on device while writing video scratch data ('{raw_out.parent}', free={basefwx.MediaCipher._format_bytes(max(0, free))}). jMG currently needs room for both decoded and transformed raw streams.") from None
            raise
        except KeyboardInterrupt:
            cancelled = True
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)

    @staticmethod
    def _unscramble_video_raw(raw_in: 'basefwx.pathlib.Path', raw_out: 'basefwx.pathlib.Path', width: int, height: int, fps: float, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None, use_gpu_pixels: bool=False, gpu_pixels_strict: bool=False) -> None:
        frame_size = width * height * 3
        if frame_size <= 0:
            raise ValueError('Invalid video dimensions')
        group_frames = basefwx.MediaCipher._video_group_frames(fps)
        total_frames = 0
        if progress_cb:
            try:
                total_frames = raw_in.stat().st_size // frame_size
            except Exception:
                total_frames = 0
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_frames))
        processed_frames = 0
        cancelled = False
        frame_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-frame', security_profile)
        frame_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fblk', security_profile)
        frame_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fgrp', security_profile)
        video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
        try:
            with open(raw_in, 'rb') as src, open(raw_out, 'wb') as dst:
                frame_index = 0
                group_index = 0
                while True:
                    group_start_index = frame_index
                    scrambled_frames: 'list[bytes]' = []
                    for _ in range(group_frames):
                        data = src.read(frame_size)
                        if not data or len(data) < frame_size:
                            break
                        scrambled_frames.append(data)
                    if not scrambled_frames:
                        break
                    seed_index = group_index * 11400714819323198485 ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, 'big')
                    perm = basefwx.MediaCipher._permute_indices(len(scrambled_frames), seed)
                    ordered: 'list[bytes]' = [b''] * len(scrambled_frames)
                    for dest_idx, src_idx in enumerate(perm):
                        ordered[src_idx] = scrambled_frames[dest_idx]

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, frame = item
                        frame_id = group_start_index + idx
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                        seed_local = int.from_bytes(seed_bytes, 'big')
                        unshuffled = basefwx.MediaCipher._unshuffle_frame_blocks(frame, width, height, 3, seed_local, basefwx.MediaCipher.VIDEO_BLOCK_SIZE)
                        material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        return basefwx.MediaCipher._video_mask_transform(unshuffled, key, iv, mask_bits=video_mask_bits, use_cuda=use_gpu_pixels, cuda_strict=gpu_pixels_strict)
                    if executor:
                        restored = list(executor.map(_process, enumerate(ordered)))
                    else:
                        restored = [_process(item) for item in enumerate(ordered)]
                    for frame in restored:
                        dst.write(frame)
                    processed_frames += len(restored)
                    if progress_cb and total_frames:
                        progress_cb(min(1.0, processed_frames / total_frames))
                    frame_index += len(restored)
                    group_index += 1
        except OSError as exc:
            if getattr(exc, 'errno', None) == 28:
                free = basefwx.MediaCipher._workspace_free_bytes(raw_out.parent)
                raise RuntimeError(f"No space left on device while writing video scratch data ('{raw_out.parent}', free={basefwx.MediaCipher._format_bytes(max(0, free))}). jMG currently needs room for both decoded and transformed raw streams.") from None
            raise
        except KeyboardInterrupt:
            cancelled = True
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)

    @staticmethod
    def _read_exact(stream: 'basefwx.typing.BinaryIO', size: int) -> bytes:
        if size <= 0:
            return b''
        out = bytearray()
        while len(out) < size:
            chunk = stream.read(size - len(out))
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)

    @staticmethod
    def _drain_process_stderr(proc: 'basefwx.subprocess.Popen[bytes]') -> str:
        try:
            if proc.stderr is None:
                return ''
            data = proc.stderr.read()
            if not data:
                return ''
            return data.decode('utf-8', 'replace')
        except Exception:
            return ''

    @staticmethod
    def _scramble_video_stream(decode_cmd: 'list[str]', encode_cmd: 'list[str]', width: int, height: int, fps: float, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None, use_gpu_pixels: bool=False, gpu_pixels_strict: bool=False, total_frames_hint: int=0) -> None:
        frame_size = width * height * 3
        if frame_size <= 0:
            raise ValueError('Invalid video dimensions')
        group_frames = basefwx.MediaCipher._video_group_frames(fps)
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_frames))
        frame_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-frame', security_profile)
        frame_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fblk', security_profile)
        frame_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fgrp', security_profile)
        video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
        decode_proc = basefwx.subprocess.Popen([str(part) for part in decode_cmd], stdout=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE)
        encode_proc = basefwx.subprocess.Popen([str(part) for part in encode_cmd], stdin=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE)
        cancelled = False
        try:
            frame_index = 0
            group_index = 0
            processed_frames = 0
            while True:
                group_start_index = frame_index
                raw_frames: 'list[bytes]' = []
                for _ in range(group_frames):
                    if decode_proc.stdout is None:
                        break
                    data = basefwx.MediaCipher._read_exact(decode_proc.stdout, frame_size)
                    if not data:
                        break
                    if len(data) < frame_size:
                        raise RuntimeError('ffmpeg produced a truncated raw video frame')
                    raw_frames.append(data)
                if not raw_frames:
                    break

                def _process(item: tuple[int, bytes]) -> bytes:
                    idx, frame = item
                    frame_id = group_start_index + idx
                    material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                    key = material[:32]
                    iv = material[32:48]
                    masked = basefwx.MediaCipher._video_mask_transform(frame, key, iv, mask_bits=video_mask_bits, use_cuda=use_gpu_pixels, cuda_strict=gpu_pixels_strict)
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                    seed = int.from_bytes(seed_bytes, 'big')
                    return basefwx.MediaCipher._shuffle_frame_blocks(masked, width, height, 3, seed, basefwx.MediaCipher.VIDEO_BLOCK_SIZE)
                if executor:
                    frames = list(executor.map(_process, enumerate(raw_frames)))
                else:
                    frames = [_process(item) for item in enumerate(raw_frames)]
                seed_index = group_index * 11400714819323198485 ^ group_start_index
                seed_index &= (1 << 64) - 1
                seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                seed = int.from_bytes(seed_bytes, 'big')
                perm = basefwx.MediaCipher._permute_indices(len(frames), seed)
                if encode_proc.stdin is None:
                    raise RuntimeError('ffmpeg encode pipe is unavailable')
                for idx in perm:
                    try:
                        encode_proc.stdin.write(frames[idx])
                    except (BrokenPipeError, OSError) as exc:
                        if isinstance(exc, BrokenPipeError) or getattr(exc, 'errno', None) == 32:
                            encode_rc = encode_proc.wait()
                            encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                            raise RuntimeError(encode_err.strip() or f'ffmpeg video encode pipe closed unexpectedly (rc={encode_rc})') from None
                        raise
                processed_frames += len(frames)
                if progress_cb and total_frames_hint > 0:
                    progress_cb(min(1.0, processed_frames / total_frames_hint))
                frame_index += len(frames)
                group_index += 1
            if encode_proc.stdin is not None:
                encode_proc.stdin.close()
            decode_rc = decode_proc.wait()
            encode_rc = encode_proc.wait()
            decode_err = basefwx.MediaCipher._drain_process_stderr(decode_proc)
            encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
            if decode_rc != 0:
                raise RuntimeError(decode_err.strip() or 'ffmpeg video decode failed')
            if encode_rc != 0:
                raise RuntimeError(encode_err.strip() or 'ffmpeg video encode failed')
        except OSError as exc:
            if getattr(exc, 'errno', None) == 28:
                raise RuntimeError('No space left on device while streaming jMG video transform output.') from None
            raise
        except KeyboardInterrupt:
            cancelled = True
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)
            if executor and cancelled:
                executor.shutdown(wait=False, cancel_futures=True)
            with basefwx.contextlib.suppress(Exception):
                if decode_proc.poll() is None:
                    decode_proc.terminate()
            with basefwx.contextlib.suppress(Exception):
                if encode_proc.poll() is None:
                    encode_proc.terminate()
            with basefwx.contextlib.suppress(Exception):
                if decode_proc.poll() is None:
                    decode_proc.kill()
            with basefwx.contextlib.suppress(Exception):
                if encode_proc.poll() is None:
                    encode_proc.kill()

    @staticmethod
    def _unscramble_video_stream(decode_cmd: 'list[str]', encode_cmd: 'list[str]', width: int, height: int, fps: float, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None, use_gpu_pixels: bool=False, gpu_pixels_strict: bool=False, total_frames_hint: int=0) -> None:
        frame_size = width * height * 3
        if frame_size <= 0:
            raise ValueError('Invalid video dimensions')
        group_frames = basefwx.MediaCipher._video_group_frames(fps)
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_frames))
        frame_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-frame', security_profile)
        frame_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fblk', security_profile)
        frame_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-fgrp', security_profile)
        video_mask_bits = basefwx.MediaCipher._jmg_video_mask_bits(security_profile)
        decode_proc = basefwx.subprocess.Popen([str(part) for part in decode_cmd], stdout=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE)
        encode_proc = basefwx.subprocess.Popen([str(part) for part in encode_cmd], stdin=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE)
        cancelled = False
        try:
            frame_index = 0
            group_index = 0
            processed_frames = 0
            while True:
                group_start_index = frame_index
                scrambled_frames: 'list[bytes]' = []
                for _ in range(group_frames):
                    if decode_proc.stdout is None:
                        break
                    data = basefwx.MediaCipher._read_exact(decode_proc.stdout, frame_size)
                    if not data:
                        break
                    if len(data) < frame_size:
                        raise RuntimeError('ffmpeg produced a truncated raw video frame')
                    scrambled_frames.append(data)
                if not scrambled_frames:
                    break
                seed_index = group_index * 11400714819323198485 ^ group_start_index
                seed_index &= (1 << 64) - 1
                seed_bytes = basefwx.MediaCipher._unit_material(base_key, frame_group_label, seed_index, 16)
                seed = int.from_bytes(seed_bytes, 'big')
                perm = basefwx.MediaCipher._permute_indices(len(scrambled_frames), seed)
                ordered: 'list[bytes]' = [b''] * len(scrambled_frames)
                for dest_idx, src_idx in enumerate(perm):
                    ordered[src_idx] = scrambled_frames[dest_idx]

                def _process(item: tuple[int, bytes]) -> bytes:
                    idx, frame = item
                    frame_id = group_start_index + idx
                    seed_bytes_local = basefwx.MediaCipher._unit_material(base_key, frame_block_label, frame_id, 16)
                    seed_local = int.from_bytes(seed_bytes_local, 'big')
                    unshuffled = basefwx.MediaCipher._unshuffle_frame_blocks(frame, width, height, 3, seed_local, basefwx.MediaCipher.VIDEO_BLOCK_SIZE)
                    material = basefwx.MediaCipher._unit_material(base_key, frame_label, frame_id, 48)
                    key = material[:32]
                    iv = material[32:48]
                    return basefwx.MediaCipher._video_mask_transform(unshuffled, key, iv, mask_bits=video_mask_bits, use_cuda=use_gpu_pixels, cuda_strict=gpu_pixels_strict)
                if executor:
                    restored = list(executor.map(_process, enumerate(ordered)))
                else:
                    restored = [_process(item) for item in enumerate(ordered)]
                if encode_proc.stdin is None:
                    raise RuntimeError('ffmpeg encode pipe is unavailable')
                for frame in restored:
                    try:
                        encode_proc.stdin.write(frame)
                    except (BrokenPipeError, OSError) as exc:
                        if isinstance(exc, BrokenPipeError) or getattr(exc, 'errno', None) == 32:
                            encode_rc = encode_proc.wait()
                            encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
                            raise RuntimeError(encode_err.strip() or f'ffmpeg video encode pipe closed unexpectedly (rc={encode_rc})') from None
                        raise
                processed_frames += len(restored)
                if progress_cb and total_frames_hint > 0:
                    progress_cb(min(1.0, processed_frames / total_frames_hint))
                frame_index += len(restored)
                group_index += 1
            if encode_proc.stdin is not None:
                encode_proc.stdin.close()
            decode_rc = decode_proc.wait()
            encode_rc = encode_proc.wait()
            decode_err = basefwx.MediaCipher._drain_process_stderr(decode_proc)
            encode_err = basefwx.MediaCipher._drain_process_stderr(encode_proc)
            if decode_rc != 0:
                raise RuntimeError(decode_err.strip() or 'ffmpeg video decode failed')
            if encode_rc != 0:
                raise RuntimeError(encode_err.strip() or 'ffmpeg video encode failed')
        except OSError as exc:
            if getattr(exc, 'errno', None) == 28:
                raise RuntimeError('No space left on device while streaming jMG video transform output.') from None
            raise
        except KeyboardInterrupt:
            cancelled = True
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)
            if executor and cancelled:
                executor.shutdown(wait=False, cancel_futures=True)
            with basefwx.contextlib.suppress(Exception):
                if decode_proc.poll() is None:
                    decode_proc.terminate()
            with basefwx.contextlib.suppress(Exception):
                if encode_proc.poll() is None:
                    encode_proc.terminate()
            with basefwx.contextlib.suppress(Exception):
                if decode_proc.poll() is None:
                    decode_proc.kill()
            with basefwx.contextlib.suppress(Exception):
                if encode_proc.poll() is None:
                    encode_proc.kill()

    @staticmethod
    def _scramble_audio_raw(raw_in: 'basefwx.pathlib.Path', raw_out: 'basefwx.pathlib.Path', sample_rate: int, channels: int, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None) -> None:
        if sample_rate <= 0 or channels <= 0:
            raise ValueError('Invalid audio stream parameters')
        samples_per_block = max(1, int(round(sample_rate * basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
        block_size = samples_per_block * channels * 2
        group_blocks = max(2, int(round(basefwx.MediaCipher.AUDIO_GROUP_SECONDS / basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
        total_blocks = 0
        if progress_cb:
            try:
                total_blocks = (raw_in.stat().st_size + block_size - 1) // block_size
            except Exception:
                total_blocks = 0
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_blocks))
        processed_blocks = 0
        cancelled = False
        audio_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-ablock', security_profile)
        audio_sample_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-asamp', security_profile)
        audio_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-agrp', security_profile)
        audio_mask_bits = basefwx.MediaCipher._jmg_audio_mask_bits(security_profile)
        try:
            with open(raw_in, 'rb') as src, open(raw_out, 'wb') as dst:
                block_index = 0
                group_index = 0
                while True:
                    group_start_index = block_index
                    raw_blocks: 'list[bytes]' = []
                    for _ in range(group_blocks):
                        data = src.read(block_size)
                        if not data:
                            break
                        raw_blocks.append(data)
                    if not raw_blocks:
                        break

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, block = item
                        block_id = group_start_index + idx
                        material = basefwx.MediaCipher._unit_material(base_key, audio_block_label, block_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        masked = basefwx.MediaCipher._audio_mask_transform(block, key, iv, mask_bits=audio_mask_bits)
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_sample_label, block_id, 16)
                        seed = int.from_bytes(seed_bytes, 'big')
                        return basefwx.MediaCipher._shuffle_audio_samples(masked, seed)
                    if executor:
                        blocks = list(executor.map(_process, enumerate(raw_blocks)))
                    else:
                        blocks = [_process(item) for item in enumerate(raw_blocks)]
                    seed_index = group_index * 11400714819323198485 ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, 'big')
                    perm = basefwx.MediaCipher._permute_indices(len(blocks), seed)
                    for idx in perm:
                        dst.write(blocks[idx])
                    processed_blocks += len(blocks)
                    if progress_cb and total_blocks:
                        progress_cb(min(1.0, processed_blocks / total_blocks))
                    block_index += len(blocks)
                    group_index += 1
        except KeyboardInterrupt:
            cancelled = True
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)

    @staticmethod
    def _unscramble_audio_raw(raw_in: 'basefwx.pathlib.Path', raw_out: 'basefwx.pathlib.Path', sample_rate: int, channels: int, base_key: bytes, *, security_profile: int=0, progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, workers: 'basefwx.typing.Optional[int]'=None) -> None:
        if sample_rate <= 0 or channels <= 0:
            raise ValueError('Invalid audio stream parameters')
        samples_per_block = max(1, int(round(sample_rate * basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
        block_size = samples_per_block * channels * 2
        group_blocks = max(2, int(round(basefwx.MediaCipher.AUDIO_GROUP_SECONDS / basefwx.MediaCipher.AUDIO_BLOCK_SECONDS)))
        total_blocks = 0
        if progress_cb:
            try:
                total_blocks = (raw_in.stat().st_size + block_size - 1) // block_size
            except Exception:
                total_blocks = 0
        use_workers = workers or basefwx.MediaCipher._media_workers()
        executor = None
        if use_workers > 1:
            executor = basefwx.concurrent.futures.ThreadPoolExecutor(max_workers=min(use_workers, group_blocks))
        processed_blocks = 0
        cancelled = False
        audio_block_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-ablock', security_profile)
        audio_sample_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-asamp', security_profile)
        audio_group_label = basefwx.MediaCipher._jmg_profile_label(b'jmg-agrp', security_profile)
        audio_mask_bits = basefwx.MediaCipher._jmg_audio_mask_bits(security_profile)
        try:
            with open(raw_in, 'rb') as src, open(raw_out, 'wb') as dst:
                block_index = 0
                group_index = 0
                while True:
                    group_start_index = block_index
                    scrambled_blocks: 'list[bytes]' = []
                    for _ in range(group_blocks):
                        data = src.read(block_size)
                        if not data:
                            break
                        scrambled_blocks.append(data)
                    if not scrambled_blocks:
                        break
                    seed_index = group_index * 11400714819323198485 ^ group_start_index
                    seed_index &= (1 << 64) - 1
                    seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_group_label, seed_index, 16)
                    seed = int.from_bytes(seed_bytes, 'big')
                    perm = basefwx.MediaCipher._permute_indices(len(scrambled_blocks), seed)
                    ordered: 'list[bytes]' = [b''] * len(scrambled_blocks)
                    for dest_idx, src_idx in enumerate(perm):
                        ordered[src_idx] = scrambled_blocks[dest_idx]

                    def _process(item: tuple[int, bytes]) -> bytes:
                        idx, block = item
                        block_id = group_start_index + idx
                        seed_bytes = basefwx.MediaCipher._unit_material(base_key, audio_sample_label, block_id, 16)
                        seed_local = int.from_bytes(seed_bytes, 'big')
                        unshuffled = basefwx.MediaCipher._unshuffle_audio_samples(block, seed_local)
                        material = basefwx.MediaCipher._unit_material(base_key, audio_block_label, block_id, 48)
                        key = material[:32]
                        iv = material[32:48]
                        return basefwx.MediaCipher._audio_mask_transform(unshuffled, key, iv, mask_bits=audio_mask_bits)
                    if executor:
                        restored = list(executor.map(_process, enumerate(ordered)))
                    else:
                        restored = [_process(item) for item in enumerate(ordered)]
                    for block in restored:
                        dst.write(block)
                    processed_blocks += len(restored)
                    if progress_cb and total_blocks:
                        progress_cb(min(1.0, processed_blocks / total_blocks))
                    block_index += len(restored)
                    group_index += 1
        except KeyboardInterrupt:
            cancelled = True
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if executor and (not cancelled):
                executor.shutdown(wait=True)

    @staticmethod
    def _encrypt_metadata(tags: 'dict[str, str]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'list[str]':
        encoded_args: 'list[str]' = []
        for key, value in tags.items():
            try:
                enc = basefwx.b512encode(value, password, use_master=False)
            except Exception:
                continue
            encoded_args.append(f'{key}={enc}')
        return encoded_args

    @staticmethod
    def _decrypt_metadata(tags: 'dict[str, str]', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'list[str]':
        decoded_args: 'list[str]' = []
        for key, value in tags.items():
            try:
                dec = basefwx.b512decode(value, password, use_master=False)
            except Exception:
                continue
            decoded_args.append(f'{key}={dec}')
        return decoded_args

    @staticmethod
    def _append_trailer(output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', original_bytes: bytes, *, archive_key: 'basefwx.typing.Optional[bytes]'=None, key_header: bytes=b'') -> None:
        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
        if key_header:
            profile_id = basefwx._jmg_profile_from_key_header(key_header)
        archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        if archive_key is None:
            material = basefwx.MediaCipher._derive_media_material(password, security_profile=profile_id)
            archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
        archive_blob = basefwx._aead_encrypt(archive_key, original_bytes, archive_info)
        trailer_blob = key_header + archive_blob
        basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_TRAILER_MAGIC, trailer_blob)

    @staticmethod
    def _append_trailer_stream(output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', original_path: 'basefwx.pathlib.Path', progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None, *, archive_key: 'basefwx.typing.Optional[bytes]'=None, key_header: bytes=b'') -> None:
        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
        if key_header:
            profile_id = basefwx._jmg_profile_from_key_header(key_header)
        archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        if archive_key is None:
            material = basefwx.MediaCipher._derive_media_material(password, security_profile=profile_id)
            archive_key = basefwx._hkdf_sha256(material, info=archive_info, length=32)
        aad = archive_info
        size = original_path.stat().st_size
        blob_len = len(key_header) + basefwx.AEAD_NONCE_LEN + size + basefwx.AEAD_TAG_LEN
        if blob_len > 4294967295:
            raise ValueError('Trailer too large for 4-byte length field')
        nonce = basefwx.os.urandom(basefwx.AEAD_NONCE_LEN)
        cipher = basefwx.Cipher(basefwx.algorithms.AES(archive_key), basefwx.modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        chunk_size = 1024 * 1024
        with open(output_path, 'ab') as out_handle, open(original_path, 'rb') as src_handle:
            out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
            out_handle.write(blob_len.to_bytes(4, 'big'))
            if key_header:
                out_handle.write(key_header)
            out_handle.write(nonce)
            processed = 0
            while True:
                chunk = src_handle.read(chunk_size)
                if not chunk:
                    break
                out_handle.write(encryptor.update(chunk))
                processed += len(chunk)
                if progress_cb and size:
                    progress_cb(min(1.0, processed / size))
            encryptor.finalize()
            out_handle.write(encryptor.tag)
            out_handle.write(basefwx.IMAGECIPHER_TRAILER_MAGIC)
            out_handle.write(blob_len.to_bytes(4, 'big'))

    @staticmethod
    def _append_key_trailer(output_path: 'basefwx.pathlib.Path', key_header: bytes) -> None:
        if not key_header:
            raise ValueError('Missing JMG key header for no-archive mode')
        basefwx._append_balanced_trailer(output_path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, key_header)

    @staticmethod
    def _load_base_key_from_key_trailer(path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[tuple[bytes, int]]':
        info = basefwx._extract_balanced_trailer_info(path, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
        if info is None:
            return None
        blob_start, blob_len, _ = info
        with open(path, 'rb') as handle:
            handle.seek(blob_start)
            blob = handle.read(blob_len)
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is None:
            raise ValueError('Invalid JMG key trailer')
        header_len, base_key, _, _, profile_id = header
        if header_len != len(blob):
            raise ValueError('Invalid JMG key trailer payload')
        return (base_key, profile_id)

    @staticmethod
    def _load_base_key_from_key_trailer_bytes(file_bytes: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[tuple[bytes, int]]':
        trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC)
        if trailer is None:
            return None
        blob, _ = trailer
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is None:
            raise ValueError('Invalid JMG key trailer')
        header_len, base_key, _, _, profile_id = header
        if header_len != len(blob):
            raise ValueError('Invalid JMG key trailer payload')
        return (base_key, profile_id)

    @staticmethod
    def _decrypt_trailer(file_bytes: bytes, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]') -> 'basefwx.typing.Optional[bytes]':
        trailer = basefwx._extract_balanced_trailer_from_bytes(file_bytes, basefwx.IMAGECIPHER_TRAILER_MAGIC)
        if trailer is None:
            return None
        blob, _ = trailer
        header = basefwx._jmg_parse_key_header(blob, password, use_master=True)
        if header is not None:
            header_len, _, archive_key, _, profile_id = header
            archive_blob = blob[header_len:]
            archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
        else:
            material = basefwx.MediaCipher._derive_media_material(password)
            archive_key = basefwx._hkdf_sha256(material, info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
            archive_blob = blob
            archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
        return basefwx._aead_decrypt(archive_key, archive_blob, archive_info)

    @staticmethod
    def _decrypt_trailer_stream(path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output_path: 'basefwx.pathlib.Path', progress_cb: 'basefwx.typing.Optional[basefwx.typing.Callable[[float], None]]'=None) -> bool:
        header_seen = False
        try:
            magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
            footer_len = len(magic) + 4
            try:
                size = path.stat().st_size
            except Exception:
                return False
            if size < footer_len:
                return False
            with open(path, 'rb') as handle:
                handle.seek(size - footer_len)
                footer = handle.read(footer_len)
                if len(footer) != footer_len or footer[:len(magic)] != magic:
                    return False
                blob_len = int.from_bytes(footer[len(magic):], 'big')
                trailer_start = size - footer_len - blob_len - footer_len
                if trailer_start < 0:
                    return False
                handle.seek(trailer_start)
                header = handle.read(footer_len)
                if len(header) != footer_len or header[:len(magic)] != magic:
                    return False
                header_len = int.from_bytes(header[len(magic):], 'big')
                if header_len != blob_len:
                    return False
                blob_start = trailer_start + footer_len
                handle.seek(blob_start)
                header_min = len(basefwx.JMG_KEY_MAGIC) + 1 + 4
                prefix = handle.read(len(basefwx.JMG_KEY_MAGIC))
                if len(prefix) != len(basefwx.JMG_KEY_MAGIC):
                    return False
                archive_info = basefwx.IMAGECIPHER_ARCHIVE_INFO
                if prefix == basefwx.JMG_KEY_MAGIC:
                    header_seen = True
                    version = handle.read(1)
                    if len(version) != 1:
                        return False
                    if version[0] not in {basefwx.JMG_KEY_VERSION_LEGACY, basefwx.JMG_KEY_VERSION}:
                        raise ValueError('Unsupported JMG key header version')
                    payload_len_bytes = handle.read(4)
                    if len(payload_len_bytes) != 4:
                        return False
                    payload_len = int.from_bytes(payload_len_bytes, 'big')
                    header_len = header_min + payload_len
                    payload = handle.read(payload_len)
                    if len(payload) != payload_len:
                        return False
                    if version[0] == basefwx.JMG_KEY_VERSION_LEGACY:
                        profile_id = basefwx.JMG_SECURITY_PROFILE_LEGACY
                        key_payload = payload
                    else:
                        if not payload:
                            return False
                        profile_id = basefwx._jmg_security_profile_id(payload[0])
                        key_payload = payload[1:]
                    user_blob, master_blob = basefwx._unpack_length_prefixed(key_payload, 2)
                    mask_key = basefwx._recover_mask_key_from_blob(user_blob, master_blob, password, True, mask_info=basefwx.JMG_MASK_INFO, aad=basefwx.JMG_MASK_AAD)
                    archive_key = basefwx._hkdf_sha256(mask_key, info=basefwx._jmg_archive_info_for_profile(profile_id), length=32)
                    archive_info = basefwx._jmg_archive_info_for_profile(profile_id)
                    nonce = handle.read(basefwx.AEAD_NONCE_LEN)
                    if len(nonce) != basefwx.AEAD_NONCE_LEN:
                        return False
                    cipher_body_len = blob_len - header_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                else:
                    archive_key = basefwx._hkdf_sha256(basefwx.MediaCipher._derive_media_material(password), info=basefwx.IMAGECIPHER_ARCHIVE_INFO, length=32)
                    nonce = prefix + handle.read(basefwx.AEAD_NONCE_LEN - len(prefix))
                    if len(nonce) != basefwx.AEAD_NONCE_LEN:
                        return False
                    cipher_body_len = blob_len - basefwx.AEAD_NONCE_LEN - basefwx.AEAD_TAG_LEN
                if cipher_body_len < 0:
                    return False
                cipher = basefwx.Cipher(basefwx.algorithms.AES(archive_key), basefwx.modes.GCM(nonce))
                decryptor = cipher.decryptor()
                decryptor.authenticate_additional_data(archive_info)
                chunk_size = 1024 * 1024
                with open(output_path, 'wb') as out_handle:
                    remaining = cipher_body_len
                    processed = 0
                    while remaining > 0:
                        chunk = handle.read(min(chunk_size, remaining))
                        if not chunk:
                            return False
                        out_handle.write(decryptor.update(chunk))
                        remaining -= len(chunk)
                        processed += len(chunk)
                        if progress_cb and cipher_body_len:
                            progress_cb(min(1.0, processed / cipher_body_len))
                    tag = handle.read(basefwx.AEAD_TAG_LEN)
                    if len(tag) != basefwx.AEAD_TAG_LEN:
                        return False
                    decryptor.finalize_with_tag(tag)
            return True
        except Exception:
            if header_seen:
                raise
            return False

    @staticmethod
    def _run_ffmpeg(cmd: 'list[str]', fallback_cmd: 'basefwx.typing.Optional[list[str]]'=None) -> None:

        def _run_once(run_cmd: 'list[str]') -> 'tuple[int, str, str]':
            proc = basefwx.subprocess.Popen([str(part) for part in run_cmd], stdout=basefwx.subprocess.PIPE, stderr=basefwx.subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate()
                return (proc.returncode, stdout or '', stderr or '')
            except KeyboardInterrupt:
                with basefwx.contextlib.suppress(Exception):
                    proc.terminate()
                with basefwx.contextlib.suppress(Exception):
                    proc.wait(timeout=1.5)
                with basefwx.contextlib.suppress(Exception):
                    if proc.poll() is None:
                        proc.kill()
                with basefwx.contextlib.suppress(Exception):
                    proc.wait(timeout=1.0)
                raise
        code, _stdout, stderr = _run_once(cmd)
        if code != 0:
            if fallback_cmd and (not basefwx.MediaCipher._hwaccel_strict()):
                retry_code, _retry_stdout, retry_stderr = _run_once(fallback_cmd)
                if retry_code != 0:
                    raise RuntimeError(retry_stderr.strip() or 'ffmpeg failed')
                return
            raise RuntimeError(stderr.strip() or 'ffmpeg failed')

    @staticmethod
    def _scramble_video(path: 'basefwx.pathlib.Path', output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', keep_meta: bool, base_key: 'basefwx.typing.Optional[bytes]'=None, security_profile: int=0, lossless_carrier: bool=False, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, hw_plan: 'basefwx.typing.Optional[dict[str, basefwx.typing.Any]]'=None) -> None:
        display_path = display_path or path
        info = basefwx.MediaCipher._probe_streams(path)
        video = info.get('video')
        if not video:
            raise ValueError('No video stream found')
        width = int(video.get('width') or 0)
        height = int(video.get('height') or 0)
        fps = float(video.get('fps') or 0.0)
        audio = info.get('audio')
        video_bps, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
        if hw_plan is None:
            frame_bytes = max(0, width * height * 3)
            hw_plan = basefwx.MediaCipher._build_hw_execution_plan('jMGe', stream_type='video', frame_bytes=frame_bytes, allow_pixel_gpu=True, prefer_cpu_decode=True)
            basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
        if reporter:
            with basefwx.contextlib.suppress(Exception):
                reporter.set_hw_execution_plan(hw_plan)
        selected_accel = hw_plan.get('selected_accel')
        decode_device = hw_plan.get('decode_device', 'cpu')
        decode_video_args = basefwx.MediaCipher._ffmpeg_video_decode_args(selected_accel if decode_device != 'cpu' else None)
        if reporter:
            reporter.update(file_index, 0.05, 'probe', display_path)
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-media-')
        try:
            workspace = basefwx.pathlib.Path(temp_dir.name)
            basefwx.MediaCipher._ensure_workspace_free(workspace, basefwx.MediaCipher._estimate_audio_workspace_need(info), 'video audio-scratch preflight')
            raw_audio = None
            raw_audio_out = None
            sample_rate = 0
            channels = 0
            if audio:
                raw_audio = basefwx.pathlib.Path(temp_dir.name) / 'audio.raw'
                raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / 'audio.scr.raw'
                sample_rate = int(audio.get('sample_rate') or 0)
                channels = int(audio.get('channels') or 0)
                cmd_audio = ['ffmpeg', '-y', '-i', str(path), '-map', '0:a:0', '-f', 's16le', '-acodec', 'pcm_s16le', '-ar', str(sample_rate or 48000), '-ac', str(channels or 2), str(raw_audio)]
                if reporter:
                    reporter.update(file_index, 0.21, 'decode-audio', display_path)
                basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                sample_rate = sample_rate or 48000
                channels = channels or 2
                if reporter:
                    reporter.update(file_index, 0.3, 'decode-audio', display_path)
            if raw_audio:
                required_transform = int(raw_audio.stat().st_size) + basefwx.MediaCipher.WORKSPACE_RESERVE_BYTES
                basefwx.MediaCipher._ensure_workspace_free(workspace, required_transform, 'video audio transform scratch')
            if base_key is None:
                base_key = basefwx.MediaCipher._derive_base_key(password, security_profile=security_profile)
            video_phase = 'jmg-video-gpu' if hw_plan.get('pixel_backend') == 'cuda' else 'jmg-video-cpu'

            def video_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.3 + 0.4 * frac, video_phase, display_path)

            def audio_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.7 + 0.2 * frac, 'jmg-audio-cpu', display_path)
            if raw_audio and raw_audio_out:
                basefwx.MediaCipher._scramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key, security_profile=security_profile, progress_cb=audio_cb if reporter else None, workers=basefwx.MediaCipher._media_workers())
            cmd_base = ['ffmpeg', '-loglevel', 'error', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-s', f'{width}x{height}', '-r', str(fps or 30), '-i', 'pipe:0']
            if raw_audio_out:
                cmd_base += ['-f', 's16le', '-ar', str(sample_rate), '-ac', str(channels), '-i', str(raw_audio_out), '-shortest']
            if keep_meta:
                tags = basefwx.MediaCipher._probe_metadata(path)
                for meta in basefwx.MediaCipher._encrypt_metadata(tags, password):
                    cmd_base += ['-metadata', meta]
            else:
                cmd_base += ['-map_metadata', '-1']
            video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, selected_accel, lossless=lossless_carrier)
            cpu_video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, None, lossless=lossless_carrier)
            cmd = cmd_base + video_args
            if raw_audio_out:
                cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps, lossless=lossless_carrier)
            cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            cmd.append(str(output_path))
            decode_cmd = ['ffmpeg', '-loglevel', 'error', '-y'] + decode_video_args + ['-i', str(path), '-map', '0:v:0']
            if decode_device != 'cpu' and selected_accel == 'nvenc':
                decode_cmd += ['-vf', 'hwdownload,format=nv12,format=rgb24']
            decode_cmd += ['-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1']
            decode_cmd_cpu = ['ffmpeg', '-loglevel', 'error', '-y', '-i', str(path), '-map', '0:v:0', '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1']
            if reporter:
                reporter.update(file_index, 0.06, 'decode-video', display_path)
            total_frames_hint = max(1, int(round(float(info.get('duration') or 0.0) * (fps or 30.0))))
            fallback_cmd = cmd_base + cpu_video_args
            if raw_audio_out:
                fallback_cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps, lossless=lossless_carrier)
            fallback_cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            fallback_cmd.append(str(output_path))

            def _run_stream(decode_use: 'list[str]', encode_use: 'list[str]') -> None:
                basefwx.MediaCipher._scramble_video_stream(decode_use, encode_use, width, height, fps, base_key, security_profile=security_profile, progress_cb=video_cb if reporter else None, workers=int(hw_plan.get('pixel_workers') or basefwx.MediaCipher._media_workers()), use_gpu_pixels=bool(hw_plan.get('pixel_backend') == 'cuda'), gpu_pixels_strict=bool(hw_plan.get('gpu_pixels_strict', False)), total_frames_hint=total_frames_hint)
            should_try_fallback = bool(selected_accel and video_args != cpu_video_args and (not basefwx.MediaCipher._hwaccel_strict()))
            try:
                _run_stream(decode_cmd if decode_video_args else decode_cmd_cpu, cmd)
            except RuntimeError as exc:
                if should_try_fallback and 'No space left on device' not in str(exc):
                    _run_stream(decode_cmd_cpu, fallback_cmd)
                else:
                    raise
            if reporter:
                reporter.update(file_index, 0.95, 'encode', display_path)
        finally:
            try:
                temp_dir.cleanup()
            except KeyboardInterrupt:
                pass

    @staticmethod
    def _scramble_audio(path: 'basefwx.pathlib.Path', output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', keep_meta: bool, base_key: 'basefwx.typing.Optional[bytes]'=None, security_profile: int=0, lossless_carrier: bool=False, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> None:
        display_path = display_path or path
        info = basefwx.MediaCipher._probe_streams(path)
        audio = info.get('audio')
        if not audio:
            raise ValueError('No audio stream found')
        sample_rate = int(audio.get('sample_rate') or 0)
        channels = int(audio.get('channels') or 0)
        sample_rate = sample_rate or 48000
        channels = channels or 2
        _, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
        if reporter:
            reporter.update(file_index, 0.05, 'probe', display_path)
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-media-')
        try:
            raw_audio = basefwx.pathlib.Path(temp_dir.name) / 'audio.raw'
            raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / 'audio.scr.raw'
            cmd_audio = ['ffmpeg', '-y', '-i', str(path), '-map', '0:a:0', '-f', 's16le', '-acodec', 'pcm_s16le', '-ar', str(sample_rate), '-ac', str(channels), str(raw_audio)]
            basefwx.MediaCipher._run_ffmpeg(cmd_audio)
            if base_key is None:
                base_key = basefwx.MediaCipher._derive_base_key(password, security_profile=security_profile)
            if reporter:
                reporter.update(file_index, 0.2, 'decode-audio', display_path)

            def audio_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.2 + 0.65 * frac, 'jmg-audio', display_path)
            basefwx.MediaCipher._scramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key, security_profile=security_profile, progress_cb=audio_cb if reporter else None, workers=basefwx.MediaCipher._media_workers())
            cmd = ['ffmpeg', '-y', '-f', 's16le', '-ar', str(sample_rate), '-ac', str(channels), '-i', str(raw_audio_out)]
            if keep_meta:
                tags = basefwx.MediaCipher._probe_metadata(path)
                for meta in basefwx.MediaCipher._encrypt_metadata(tags, password):
                    cmd += ['-metadata', meta]
            else:
                cmd += ['-map_metadata', '-1']
            cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps, lossless=lossless_carrier)
            cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            cmd.append(str(output_path))
            basefwx.MediaCipher._run_ffmpeg(cmd)
            if reporter:
                reporter.update(file_index, 0.95, 'encode', display_path)
        finally:
            try:
                temp_dir.cleanup()
            except KeyboardInterrupt:
                pass

    @staticmethod
    def _unscramble_video(path: 'basefwx.pathlib.Path', output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', base_key: 'basefwx.typing.Optional[bytes]'=None, security_profile: int=0, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None, hw_plan: 'basefwx.typing.Optional[dict[str, basefwx.typing.Any]]'=None) -> None:
        display_path = display_path or path
        info = basefwx.MediaCipher._probe_streams(path)
        video = info.get('video')
        if not video:
            raise ValueError('No video stream found')
        width = int(video.get('width') or 0)
        height = int(video.get('height') or 0)
        fps = float(video.get('fps') or 0.0)
        audio = info.get('audio')
        video_bps, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
        if hw_plan is None:
            frame_bytes = max(0, width * height * 3)
            hw_plan = basefwx.MediaCipher._build_hw_execution_plan('jMGd', stream_type='video', frame_bytes=frame_bytes, allow_pixel_gpu=True, prefer_cpu_decode=True)
            basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
        if reporter:
            with basefwx.contextlib.suppress(Exception):
                reporter.set_hw_execution_plan(hw_plan)
        selected_accel = hw_plan.get('selected_accel')
        decode_device = hw_plan.get('decode_device', 'cpu')
        decode_video_args = basefwx.MediaCipher._ffmpeg_video_decode_args(selected_accel if decode_device != 'cpu' else None)
        if reporter:
            reporter.update(file_index, 0.05, 'probe', display_path)
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-media-')
        try:
            workspace = basefwx.pathlib.Path(temp_dir.name)
            basefwx.MediaCipher._ensure_workspace_free(workspace, basefwx.MediaCipher._estimate_audio_workspace_need(info), 'video audio-scratch preflight')
            raw_audio = None
            raw_audio_out = None
            sample_rate = 0
            channels = 0
            if audio:
                raw_audio = basefwx.pathlib.Path(temp_dir.name) / 'audio.raw'
                raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / 'audio.unscr.raw'
                sample_rate = int(audio.get('sample_rate') or 0)
                channels = int(audio.get('channels') or 0)
                cmd_audio = ['ffmpeg', '-y', '-i', str(path), '-map', '0:a:0', '-f', 's16le', '-acodec', 'pcm_s16le', '-ar', str(sample_rate or 48000), '-ac', str(channels or 2), str(raw_audio)]
                if reporter:
                    reporter.update(file_index, 0.21, 'decode-audio', display_path)
                basefwx.MediaCipher._run_ffmpeg(cmd_audio)
                sample_rate = sample_rate or 48000
                channels = channels or 2
                if reporter:
                    reporter.update(file_index, 0.3, 'decode-audio', display_path)
            if raw_audio:
                required_transform = int(raw_audio.stat().st_size) + basefwx.MediaCipher.WORKSPACE_RESERVE_BYTES
                basefwx.MediaCipher._ensure_workspace_free(workspace, required_transform, 'video audio transform scratch')
            if base_key is None:
                base_key = basefwx.MediaCipher._derive_base_key(password, security_profile=security_profile)
            video_phase = 'unjmg-video-gpu' if hw_plan.get('pixel_backend') == 'cuda' else 'unjmg-video-cpu'

            def video_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.3 + 0.4 * frac, video_phase, display_path)

            def audio_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.7 + 0.2 * frac, 'unjmg-audio-cpu', display_path)
            if raw_audio and raw_audio_out:
                basefwx.MediaCipher._unscramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key, security_profile=security_profile, progress_cb=audio_cb if reporter else None, workers=basefwx.MediaCipher._media_workers())
            cmd_base = ['ffmpeg', '-loglevel', 'error', '-y', '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-s', f'{width}x{height}', '-r', str(fps or 30), '-i', 'pipe:0']
            if raw_audio_out:
                cmd_base += ['-f', 's16le', '-ar', str(sample_rate), '-ac', str(channels), '-i', str(raw_audio_out), '-shortest']
            tags = basefwx.MediaCipher._probe_metadata(path)
            decoded = basefwx.MediaCipher._decrypt_metadata(tags, password)
            if decoded:
                for meta in decoded:
                    cmd_base += ['-metadata', meta]
            else:
                cmd_base += ['-map_metadata', '-1']
            video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, selected_accel)
            cpu_video_args = basefwx.MediaCipher._ffmpeg_video_codec_args(output_path, video_bps, None)
            cmd = cmd_base + video_args
            if raw_audio_out:
                cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
            cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            cmd.append(str(output_path))
            decode_cmd = ['ffmpeg', '-loglevel', 'error', '-y'] + decode_video_args + ['-i', str(path), '-map', '0:v:0']
            if decode_device != 'cpu' and selected_accel == 'nvenc':
                decode_cmd += ['-vf', 'hwdownload,format=nv12,format=rgb24']
            decode_cmd += ['-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1']
            decode_cmd_cpu = ['ffmpeg', '-loglevel', 'error', '-y', '-i', str(path), '-map', '0:v:0', '-f', 'rawvideo', '-pix_fmt', 'rgb24', 'pipe:1']
            if reporter:
                reporter.update(file_index, 0.06, 'decode-video', display_path)
            total_frames_hint = max(1, int(round(float(info.get('duration') or 0.0) * (fps or 30.0))))
            fallback_cmd = cmd_base + cpu_video_args
            if raw_audio_out:
                fallback_cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
            fallback_cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            fallback_cmd.append(str(output_path))

            def _run_stream(decode_use: 'list[str]', encode_use: 'list[str]') -> None:
                basefwx.MediaCipher._unscramble_video_stream(decode_use, encode_use, width, height, fps, base_key, security_profile=security_profile, progress_cb=video_cb if reporter else None, workers=int(hw_plan.get('pixel_workers') or basefwx.MediaCipher._media_workers()), use_gpu_pixels=bool(hw_plan.get('pixel_backend') == 'cuda'), gpu_pixels_strict=bool(hw_plan.get('gpu_pixels_strict', False)), total_frames_hint=total_frames_hint)
            should_try_fallback = bool(selected_accel and video_args != cpu_video_args and (not basefwx.MediaCipher._hwaccel_strict()))
            try:
                _run_stream(decode_cmd if decode_video_args else decode_cmd_cpu, cmd)
            except RuntimeError as exc:
                if should_try_fallback and 'No space left on device' not in str(exc):
                    _run_stream(decode_cmd_cpu, fallback_cmd)
                else:
                    raise
            if reporter:
                reporter.update(file_index, 0.95, 'encode', display_path)
        finally:
            try:
                temp_dir.cleanup()
            except KeyboardInterrupt:
                pass

    @staticmethod
    def _unscramble_audio(path: 'basefwx.pathlib.Path', output_path: 'basefwx.pathlib.Path', password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', base_key: 'basefwx.typing.Optional[bytes]'=None, security_profile: int=0, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> None:
        display_path = display_path or path
        info = basefwx.MediaCipher._probe_streams(path)
        audio = info.get('audio')
        if not audio:
            raise ValueError('No audio stream found')
        _, audio_bps = basefwx.MediaCipher._estimate_bitrates(path, info)
        sample_rate = int(audio.get('sample_rate') or 0)
        channels = int(audio.get('channels') or 0)
        sample_rate = sample_rate or 48000
        channels = channels or 2
        if reporter:
            reporter.update(file_index, 0.05, 'probe', display_path)
        temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-media-')
        try:
            raw_audio = basefwx.pathlib.Path(temp_dir.name) / 'audio.raw'
            raw_audio_out = basefwx.pathlib.Path(temp_dir.name) / 'audio.unscr.raw'
            cmd_audio = ['ffmpeg', '-y', '-i', str(path), '-map', '0:a:0', '-f', 's16le', '-acodec', 'pcm_s16le', '-ar', str(sample_rate), '-ac', str(channels), str(raw_audio)]
            basefwx.MediaCipher._run_ffmpeg(cmd_audio)
            if reporter:
                reporter.update(file_index, 0.2, 'decode-audio', display_path)
            if base_key is None:
                base_key = basefwx.MediaCipher._derive_base_key(password, security_profile=security_profile)

            def audio_cb(frac: float) -> None:
                if reporter:
                    reporter.update(file_index, 0.2 + 0.65 * frac, 'unjmg-audio', display_path)
            basefwx.MediaCipher._unscramble_audio_raw(raw_audio, raw_audio_out, sample_rate, channels, base_key, security_profile=security_profile, progress_cb=audio_cb if reporter else None, workers=basefwx.MediaCipher._media_workers())
            cmd = ['ffmpeg', '-y', '-f', 's16le', '-ar', str(sample_rate), '-ac', str(channels), '-i', str(raw_audio_out)]
            tags = basefwx.MediaCipher._probe_metadata(path)
            decoded = basefwx.MediaCipher._decrypt_metadata(tags, password)
            if decoded:
                for meta in decoded:
                    cmd += ['-metadata', meta]
            else:
                cmd += ['-map_metadata', '-1']
            cmd += basefwx.MediaCipher._ffmpeg_audio_codec_args(output_path, audio_bps)
            cmd += basefwx.MediaCipher._ffmpeg_container_args(output_path)
            cmd.append(str(output_path))
            basefwx.MediaCipher._run_ffmpeg(cmd)
            if reporter:
                reporter.update(file_index, 0.95, 'encode', display_path)
        finally:
            try:
                temp_dir.cleanup()
            except KeyboardInterrupt:
                pass

    @staticmethod
    def encrypt_media(path: str, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output: str | None=None, *, keep_meta: bool=False, archive_original: bool=False, keep_input: bool=False, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> str:
        password = basefwx._resolve_password(password, use_master=True)
        path_obj = basefwx._normalize_path(path)
        basefwx._ensure_existing_file(path_obj)
        display_path = display_path or path_obj
        output_path = basefwx.pathlib.Path(output) if output else path_obj
        temp_output = output_path
        if basefwx._normalize_path(output_path) == basefwx._normalize_path(path_obj):
            temp_output = output_path.with_name(f'{output_path.stem}._jmg{output_path.suffix}')
        suffix = path_obj.suffix.lower()
        local_reporter = reporter
        created_reporter = False
        if local_reporter is None and (not basefwx._SILENT_MODE):
            local_reporter = basefwx._ProgressReporter(1)
            created_reporter = True
        if not archive_original:
            _warnings_module.warn('jMG archive_original=False omits embedded original payload; decrypted output may not be byte-identical to the input.', UserWarning)
        try:
            hw_plan: 'basefwx.typing.Optional[dict[str, basefwx.typing.Any]]' = None

            def _ensure_hw_plan(stream_type: str, *, frame_bytes: int=0, allow_pixel_gpu: bool=False, prefer_cpu_decode: bool=True) -> 'dict[str, basefwx.typing.Any]':
                nonlocal hw_plan
                if hw_plan is None:
                    hw_plan = basefwx.MediaCipher._build_hw_execution_plan('jMGe', stream_type=stream_type, frame_bytes=frame_bytes, allow_pixel_gpu=allow_pixel_gpu, prefer_cpu_decode=prefer_cpu_decode)
                    basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
                if local_reporter:
                    with basefwx.contextlib.suppress(Exception):
                        local_reporter.set_hw_execution_plan(hw_plan)
                return hw_plan
            append_archive_trailer = False
            append_key_trailer = False
            lossless_no_archive = not archive_original and basefwx.MediaCipher._jmg_lossless_no_archive()
            if suffix in basefwx.MediaCipher.IMAGE_EXTS:
                _ensure_hw_plan('image')
                result = basefwx.ImageCipher.encrypt_image_inv(str(path_obj), password, output=str(temp_output), include_trailer=True, archive_original=archive_original)
            else:
                try:
                    info = basefwx.MediaCipher._probe_streams(path_obj)
                except Exception:
                    info = {}
                if info.get('video'):
                    if not basefwx._jmg_video_enabled():
                        raise RuntimeError(f'jMG video mode is temporarily disabled. Use fwxAES for video, or set {basefwx.JMG_VIDEO_ENABLE_ENV}=1 to re-enable.')
                    frame_bytes = int((info.get('video') or {}).get('width') or 0) * int((info.get('video') or {}).get('height') or 0) * 3
                    plan = _ensure_hw_plan('video', frame_bytes=frame_bytes, allow_pixel_gpu=True, prefer_cpu_decode=True)
                    base_key, archive_key, _, trailer_header = basefwx._jmg_prepare_keys(password, use_master=True, security_profile=basefwx.JMG_SECURITY_PROFILE_MAX)
                    basefwx.MediaCipher._scramble_video(path_obj, temp_output, password, keep_meta, base_key=base_key, security_profile=basefwx.JMG_SECURITY_PROFILE_MAX, reporter=local_reporter, file_index=file_index, display_path=display_path, hw_plan=plan, lossless_carrier=lossless_no_archive)
                    result = str(temp_output)
                    if archive_original:
                        append_archive_trailer = True
                    else:
                        append_key_trailer = True
                elif info.get('audio'):
                    _ensure_hw_plan('audio')
                    base_key, archive_key, _, trailer_header = basefwx._jmg_prepare_keys(password, use_master=True, security_profile=basefwx.JMG_SECURITY_PROFILE_MAX)
                    basefwx.MediaCipher._scramble_audio(path_obj, temp_output, password, keep_meta, base_key=base_key, security_profile=basefwx.JMG_SECURITY_PROFILE_MAX, reporter=local_reporter, file_index=file_index, display_path=display_path, lossless_carrier=lossless_no_archive)
                    result = str(temp_output)
                    if archive_original:
                        append_archive_trailer = True
                    else:
                        append_key_trailer = True
                else:
                    _ensure_hw_plan('bytes')
                    fallback_out = output_path if output else path_obj.with_suffix('.fwx')
                    return basefwx.fwxAES_file(str(path_obj), password, use_master=True, output=str(fallback_out), ignore_media=True, keep_input=keep_input)
            out_path = basefwx._normalize_path(result)
            if out_path != temp_output:
                temp_output = out_path
            if append_archive_trailer:

                def trailer_cb(frac: float) -> None:
                    if local_reporter:
                        local_reporter.update(file_index, 0.95 + 0.04 * frac, 'archive', display_path)
                basefwx.MediaCipher._append_trailer_stream(temp_output, password, path_obj, progress_cb=trailer_cb if local_reporter else None, archive_key=archive_key, key_header=trailer_header)
            elif append_key_trailer:
                basefwx.MediaCipher._append_key_trailer(temp_output, trailer_header)
            if basefwx._normalize_path(output_path) != basefwx._normalize_path(temp_output):
                basefwx.os.replace(temp_output, output_path)
                temp_output = output_path
            basefwx._remove_input(path_obj, keep_input, output_path=temp_output)
            if local_reporter:
                local_reporter.update(file_index, 1.0, 'done', display_path)
            return str(temp_output)
        finally:
            if created_reporter and local_reporter:
                local_reporter.reset_terminal_state()

    @staticmethod
    def decrypt_media(path: str, password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', output: str | None=None, *, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, display_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> str:
        password = basefwx._resolve_password(password, use_master=True)
        path_obj = basefwx._normalize_path(path)
        basefwx._ensure_existing_file(path_obj)
        display_path = display_path or path_obj
        output_path = basefwx.pathlib.Path(output) if output else path_obj
        temp_output = output_path
        if basefwx._normalize_path(output_path) == basefwx._normalize_path(path_obj):
            temp_output = output_path.with_name(f'{output_path.stem}._jmgdec{output_path.suffix}')
        local_reporter = reporter
        created_reporter = False
        if local_reporter is None and (not basefwx._SILENT_MODE):
            local_reporter = basefwx._ProgressReporter(1)
            created_reporter = True
        try:
            hw_plan: 'basefwx.typing.Optional[dict[str, basefwx.typing.Any]]' = None

            def _ensure_hw_plan(stream_type: str, *, frame_bytes: int=0, allow_pixel_gpu: bool=False, prefer_cpu_decode: bool=True) -> 'dict[str, basefwx.typing.Any]':
                nonlocal hw_plan
                if hw_plan is None:
                    hw_plan = basefwx.MediaCipher._build_hw_execution_plan('jMGd', stream_type=stream_type, frame_bytes=frame_bytes, allow_pixel_gpu=allow_pixel_gpu, prefer_cpu_decode=prefer_cpu_decode)
                    basefwx.MediaCipher._log_hw_execution_plan(hw_plan)
                if local_reporter:
                    with basefwx.contextlib.suppress(Exception):
                        local_reporter.set_hw_execution_plan(hw_plan)
                return hw_plan
            suffix = path_obj.suffix.lower()
            if suffix in basefwx.MediaCipher.IMAGE_EXTS:
                _ensure_hw_plan('image')
                result = basefwx.ImageCipher.decrypt_image_inv(str(path_obj), password, output=str(temp_output))
            else:
                result = ''
                fallback_ok = False
                cached_bytes: 'basefwx.typing.Optional[bytes]' = None
                base_key_from_trailer: 'basefwx.typing.Optional[bytes]' = None
                trailer_profile = basefwx.JMG_SECURITY_PROFILE_LEGACY
                try:
                    fallback_ok = path_obj.stat().st_size <= basefwx.MediaCipher.TRAILER_FALLBACK_MAX
                except Exception:
                    fallback_ok = False

                def _load_cached_bytes() -> bytes:
                    nonlocal cached_bytes
                    if cached_bytes is None:
                        cached_bytes = path_obj.read_bytes()
                    return cached_bytes

                def trailer_cb(frac: float) -> None:
                    if local_reporter:
                        local_reporter.update(file_index, 0.05 + 0.9 * frac, 'archive', display_path)
                if basefwx.MediaCipher._decrypt_trailer_stream(path_obj, password, temp_output, progress_cb=trailer_cb if local_reporter else None):
                    result = str(temp_output)
                elif fallback_ok:
                    plain = basefwx.MediaCipher._decrypt_trailer(_load_cached_bytes(), password)
                    if plain is not None:
                        temp_output.write_bytes(plain)
                        result = str(temp_output)
                if not result:
                    trailer_key_info = basefwx.MediaCipher._load_base_key_from_key_trailer(path_obj, password)
                    if trailer_key_info is not None:
                        base_key_from_trailer, trailer_profile = trailer_key_info
                    if base_key_from_trailer is None and fallback_ok:
                        trailer_key_info = basefwx.MediaCipher._load_base_key_from_key_trailer_bytes(_load_cached_bytes(), password)
                        if trailer_key_info is not None:
                            base_key_from_trailer, trailer_profile = trailer_key_info
                    if base_key_from_trailer is not None:
                        _warnings_module.warn('jMG no-archive payload detected; restored media may not be byte-identical to the original input.', UserWarning)
                    try:
                        info = basefwx.MediaCipher._probe_streams(path_obj)
                    except Exception:
                        info = {}
                    if info.get('video'):
                        if not basefwx._jmg_video_enabled():
                            raise RuntimeError(f'jMG video mode is temporarily disabled. Use fwxAES for video, or set {basefwx.JMG_VIDEO_ENABLE_ENV}=1 to re-enable.')
                        frame_bytes = int((info.get('video') or {}).get('width') or 0) * int((info.get('video') or {}).get('height') or 0) * 3
                        plan = _ensure_hw_plan('video', frame_bytes=frame_bytes, allow_pixel_gpu=True, prefer_cpu_decode=True)
                        basefwx.MediaCipher._unscramble_video(path_obj, temp_output, password, base_key=base_key_from_trailer, security_profile=trailer_profile, reporter=local_reporter, file_index=file_index, display_path=display_path, hw_plan=plan)
                        result = str(temp_output)
                    elif info.get('audio'):
                        _ensure_hw_plan('audio')
                        basefwx.MediaCipher._unscramble_audio(path_obj, temp_output, password, base_key=base_key_from_trailer, security_profile=trailer_profile, reporter=local_reporter, file_index=file_index, display_path=display_path)
                        result = str(temp_output)
                    else:
                        _ensure_hw_plan('bytes')
                        fallback_out = output_path if output else path_obj.with_suffix('')
                        can_fwx = path_obj.suffix.lower() == '.fwx'
                        if not can_fwx:
                            try:
                                with open(path_obj, 'rb') as handle:
                                    can_fwx = handle.read(4) == basefwx.FWXAES_MAGIC
                            except Exception:
                                can_fwx = False
                        if can_fwx:
                            return basefwx.fwxAES_file(str(path_obj), password, use_master=True, output=str(fallback_out), ignore_media=True)
                        raise ValueError('Unsupported media format')
            if local_reporter:
                local_reporter.update(file_index, 1.0, 'done', display_path)
        finally:
            if created_reporter and local_reporter:
                local_reporter.reset_terminal_state()
        if basefwx._normalize_path(output_path) != basefwx._normalize_path(temp_output):
            basefwx.os.replace(temp_output, output_path)
            temp_output = output_path
        return str(temp_output)
