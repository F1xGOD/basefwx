# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.


from __future__ import annotations

from ._media_shared import basefwx


class _MediaSupportMixin:
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
        return f"CUDA_PATH={basefwx.os.getenv('CUDA_PATH', '')}|LD_LIBRARY_PATH={basefwx.os.getenv('LD_LIBRARY_PATH', '')}"

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
                return "aesni" if " aes " in f" {data.replace(chr(10), ' ')} " else "unknown"
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
        header = f"🎛️ [basefwx.hw] op={plan.get('op_name', 'unknown')} encode={encode} decode={decode} pixels={pixels} parallel={parallel_text} crypto={crypto} aes_accel={aes}"
        detail = f"   reason: {reason or 'n/a'}"
        if basefwx.MediaCipher._hw_log_color_enabled():
            header = (
                f"🎛️ {basefwx.MediaCipher._hw_color('[basefwx.hw]', '36;1')} "
                f"op={basefwx.MediaCipher._hw_color(str(plan.get('op_name', 'unknown')), '1')} "
                f"encode={basefwx.MediaCipher._hw_color(encode, '32;1')} "
                f"decode={basefwx.MediaCipher._hw_color(decode, '33;1')} "
                f"pixels={basefwx.MediaCipher._hw_color(pixels, '35;1')} "
                f"parallel={basefwx.MediaCipher._hw_color(parallel_text, '37;1')} "
                f"crypto={basefwx.MediaCipher._hw_color(crypto, '34;1')} "
                f"aes_accel={basefwx.MediaCipher._hw_color(aes, '36')}"
            )
            detail = f"   {basefwx.MediaCipher._hw_color('reason:', '2')} {reason or 'n/a'}"
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
            raise RuntimeError(f"ffprobe failed: {result.stderr.strip() or 'unknown error'}")
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
