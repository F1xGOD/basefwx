# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations

import warnings


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _ensure_cp(cls):
    if cls._cp_load_attempted:
        return cls.cp
    cls._cp_load_attempted = True
    try:
        import cupy as _cp
        cls.cp = _cp
    except Exception:
        cls.cp = None
    return cls.cp


def kFMe(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    payload = src.read_bytes()
    if basefwx._kfm_is_audio_ext(src_ext):
        flags = basefwx.KFM_FLAG_BW if bw_mode else 0
        container = basefwx._kfm_pack_container(basefwx.KFM_MODE_AUDIO_IMAGE, payload, src_ext, flags=flags)
        out_path = basefwx._kfm_resolve_output(src, output, '.png', 'kfme')
        basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
    else:
        container = basefwx._kfm_pack_container(basefwx.KFM_MODE_IMAGE_AUDIO, payload, src_ext)
        out_path = basefwx._kfm_resolve_output(src, output, '.wav', 'kfme')
        basefwx._kfm_bytes_to_wav(container, out_path)
    return str(out_path)


def kFMd(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    if bw_mode:
        basefwx._kfm_warn('kFMd --bw is deprecated and ignored in strict decode mode.')
    decoded = basefwx._kfm_decode_container(src, src_ext)
    ext = decoded['ext']
    out_path = basefwx._kfm_resolve_output(src, output, ext, 'kfmd')
    out_path.write_bytes(decoded['payload'])
    return str(out_path)


def _kfae_legacy_encode(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    src = basefwx.pathlib.Path(path)
    src_ext = basefwx._kfm_clean_ext(src.suffix)
    payload = src.read_bytes()
    flags = basefwx.KFM_FLAG_BW if bw_mode else 0
    container = basefwx._kfm_pack_container(basefwx.KFM_MODE_AUDIO_IMAGE, payload, src_ext, flags=flags)
    out_path = basefwx._kfm_resolve_output(src, output, '.png', 'kfae')
    basefwx._kfm_bytes_to_png(container, out_path, bw_mode=bw_mode)
    return str(out_path)


def kFAe(path: str, output: str | None=None, *, bw_mode: bool=False) -> str:
    basefwx._kfm_warn('kFAe is deprecated; using legacy PNG carrier mode. Prefer kFMe for auto mode.')
    return basefwx._kfae_legacy_encode(path, output, bw_mode=bw_mode)


def kFAd(path: str, output: str | None=None) -> str:
    basefwx._kfm_warn('kFAd is deprecated; use kFMd (auto-detect) instead.')
    return basefwx.kFMd(path, output)

def _kfm_clean_ext(ext: str) -> str:
    normalized = (ext or '').strip().lower()
    if not normalized:
        return '.bin'
    if not normalized.startswith('.'):
        normalized = f'.{normalized}'
    if len(normalized) > 24:
        return '.bin'
    allowed = set('._-abcdefghijklmnopqrstuvwxyz0123456789')
    if any((ch not in allowed for ch in normalized)):
        return '.bin'
    return normalized


def _kfm_is_audio_ext(ext: str) -> bool:
    return basefwx._kfm_clean_ext(ext) in basefwx.KFM_AUDIO_EXTENSIONS


def _kfm_is_image_ext(ext: str) -> bool:
    return basefwx._kfm_clean_ext(ext) in basefwx.KFM_IMAGE_EXTENSIONS


def _kfm_warn(message: str) -> None:
    warnings.warn(message, RuntimeWarning, stacklevel=3)


def _kfm_accel_mode() -> str:
    raw = basefwx.os.getenv(basefwx.KFM_ACCEL_ENV, 'auto').strip().lower()
    if raw in {'', 'auto'}:
        return 'auto'
    if raw in {'cuda', 'gpu', 'nvidia'}:
        return 'cuda'
    if raw in {'cpu', 'off', 'none'}:
        return 'cpu'
    return 'auto'


def _kfm_accel_min_bytes() -> int:
    raw = basefwx.os.getenv(basefwx.KFM_ACCEL_MIN_BYTES_ENV, '').strip()
    if raw:
        try:
            return max(1, int(raw))
        except Exception:
            return basefwx.KFM_ACCEL_DEFAULT_MIN_BYTES
    return basefwx.KFM_ACCEL_DEFAULT_MIN_BYTES


def _kfm_should_use_cuda(length: int) -> bool:
    mode = basefwx._kfm_accel_mode()
    if mode == 'cpu':
        return False
    if length <= 0:
        return False
    if mode == 'auto' and length < basefwx._kfm_accel_min_bytes():
        return False
    basefwx._ensure_cp()
    if basefwx.cp is None or basefwx.np is None:
        if mode == 'cuda':
            raise RuntimeError('kFM CUDA mode requested but CuPy/NumPy is unavailable. Install CuPy or set BASEFWX_KFM_ACCEL=cpu.')
        return False
    cuda_status_fn = None
    with basefwx.contextlib.suppress(Exception):
        cuda_status_fn = getattr(basefwx.MediaCipher, '_cuda_runtime_status', None)
    if cuda_status_fn is None:
        if mode == 'cuda':
            raise RuntimeError('kFM CUDA mode requested but CUDA runtime probes are unavailable.')
        return False
    ready, reason = cuda_status_fn()
    if not ready:
        if mode == 'cuda':
            raise RuntimeError(f'kFM CUDA mode requested but CUDA runtime is unavailable: {reason}')
        return False
    return True


def _kfm_paths_equal(a: 'basefwx.pathlib.Path', b: 'basefwx.pathlib.Path') -> bool:
    try:
        return a.resolve() == b.resolve()
    except Exception:
        return a.absolute() == b.absolute()


def _kfm_default_output(src: 'basefwx.pathlib.Path', ext: str, tag: str) -> 'basefwx.pathlib.Path':
    candidate = src.with_suffix(ext)
    if basefwx._kfm_paths_equal(candidate, src):
        candidate = src.with_name(f'{src.stem}.{tag}{ext}')
    return candidate


def _kfm_resolve_output(src: 'basefwx.pathlib.Path', output: str | None, ext: str, tag: str) -> 'basefwx.pathlib.Path':
    if output:
        out_path = basefwx.pathlib.Path(output)
        if basefwx._kfm_paths_equal(out_path, src):
            raise ValueError('Refusing to overwrite input file; choose a different output path')
        return out_path
    return basefwx._kfm_default_output(src, ext, tag)


def _kfm_keystream(seed: int, length: int, *, legacy_blake2s: bool=False) -> bytes:
    if length <= 0:
        return b''
    out = bytearray(length)
    seed_bytes = seed.to_bytes(8, 'big', signed=False)
    cursor = 0
    counter = 0
    digest_fn = basefwx.hashlib.blake2s if legacy_blake2s else basefwx.hashlib.sha256
    while cursor < length:
        block = digest_fn(seed_bytes + counter.to_bytes(8, 'big', signed=False)).digest()
        take = min(length - cursor, len(block))
        out[cursor:cursor + take] = block[:take]
        cursor += take
        counter += 1
    return bytes(out)


def _kfm_xor(data: bytes, mask: bytes) -> bytes:
    if len(data) != len(mask):
        raise ValueError('kFM mask length mismatch')
    if basefwx.np is not None:
        try:
            np_data = basefwx.np.frombuffer(data, dtype=basefwx.np.uint8)
            np_mask = basefwx.np.frombuffer(mask, dtype=basefwx.np.uint8)
            if basefwx._kfm_should_use_cuda(len(data)):
                gpu_data = basefwx.cp.asarray(np_data)
                gpu_mask = basefwx.cp.asarray(np_mask)
                gpu_out = basefwx.cp.bitwise_xor(gpu_data, gpu_mask)
                return basefwx.cp.asnumpy(gpu_out).tobytes()
            return basefwx.np.bitwise_xor(np_data, np_mask).tobytes()
        except Exception:
            pass
    out = bytearray(len(data))
    for idx in range(len(data)):
        out[idx] = data[idx] ^ mask[idx]
    return bytes(out)


def _kfm_pack_container(mode: int, payload: bytes, ext: str, *, flags: int=0) -> bytes:
    if mode not in (basefwx.KFM_MODE_IMAGE_AUDIO, basefwx.KFM_MODE_AUDIO_IMAGE):
        raise ValueError('kFM mode is invalid')
    if isinstance(payload, memoryview):
        raw = payload.tobytes()
    elif isinstance(payload, bytearray):
        raw = bytes(payload)
    elif isinstance(payload, bytes):
        raw = payload
    else:
        raise TypeError('kFM payload must be bytes-like')
    if len(raw) > basefwx.KFM_MAX_PAYLOAD:
        raise ValueError('kFM payload is too large')
    ext_clean = basefwx._kfm_clean_ext(ext)
    ext_bytes = ext_clean.encode('utf-8')
    if len(ext_bytes) > 255:
        ext_bytes = b'.bin'
    seed = int.from_bytes(basefwx.secrets.token_bytes(8), 'big', signed=False)
    body = ext_bytes + raw
    masked = basefwx._kfm_xor(body, basefwx._kfm_keystream(seed, len(body)))
    crc32 = basefwx.zlib.crc32(raw) & 4294967295
    header = basefwx.KFM_HEADER_STRUCT.pack(basefwx.KFM_MAGIC, basefwx.KFM_VERSION, mode, flags & 255, len(ext_bytes), len(raw), crc32, seed, 0)
    return header + masked


def _kfm_unpack_container(blob: bytes) -> 'basefwx.typing.Optional[dict]':
    if isinstance(blob, memoryview):
        data = blob.tobytes()
    elif isinstance(blob, bytearray):
        data = bytes(blob)
    elif isinstance(blob, bytes):
        data = blob
    else:
        return None
    if len(data) < basefwx.KFM_HEADER_LEN:
        return None
    try:
        magic, version, mode, flags, ext_len, payload_len, crc32, seed, _ = basefwx.KFM_HEADER_STRUCT.unpack(data[:basefwx.KFM_HEADER_LEN])
    except basefwx.struct.error:
        return None
    if magic != basefwx.KFM_MAGIC or version != basefwx.KFM_VERSION:
        return None
    if mode not in (basefwx.KFM_MODE_IMAGE_AUDIO, basefwx.KFM_MODE_AUDIO_IMAGE):
        return None
    body_len = ext_len + payload_len
    if body_len < ext_len:
        return None
    if body_len > len(data) - basefwx.KFM_HEADER_LEN:
        return None
    masked = data[basefwx.KFM_HEADER_LEN:basefwx.KFM_HEADER_LEN + body_len]
    body = basefwx._kfm_xor(masked, basefwx._kfm_keystream(seed, body_len))
    ext_bytes = body[:ext_len]
    payload = body[ext_len:]
    if basefwx.zlib.crc32(payload) & 4294967295 != crc32:
        legacy_body = basefwx._kfm_xor(masked, basefwx._kfm_keystream(seed, body_len, legacy_blake2s=True))
        legacy_payload = legacy_body[ext_len:]
        if basefwx.zlib.crc32(legacy_payload) & 4294967295 != crc32:
            return None
        body = legacy_body
        ext_bytes = body[:ext_len]
        payload = legacy_payload
    try:
        ext = ext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        ext = '.bin'
    return {'mode': mode, 'flags': flags, 'ext': basefwx._kfm_clean_ext(ext), 'payload': payload}


def _kfm_bytes_to_wav(data: bytes, output_path: 'basefwx.pathlib.Path') -> None:
    if isinstance(data, memoryview):
        raw = data.tobytes()
    elif isinstance(data, bytearray):
        raw = bytes(data)
    else:
        raw = data
    if len(raw) % 2:
        raw += b'\x00'
    pcm_bytes: bytes
    if basefwx.np is not None:
        try:
            np_u16 = basefwx.np.frombuffer(raw, dtype=basefwx.np.dtype('<u2'))
            if basefwx._kfm_should_use_cuda(len(raw)):
                gpu_u16 = basefwx.cp.asarray(np_u16, dtype=basefwx.cp.uint16)
                gpu_i16 = (gpu_u16.astype(basefwx.cp.int32) - 32768).astype(basefwx.cp.int16)
                pcm_bytes = basefwx.cp.asnumpy(gpu_i16).tobytes()
            else:
                np_i16 = (np_u16.astype(basefwx.np.int32) - 32768).astype(basefwx.np.int16)
                pcm_bytes = np_i16.tobytes()
        except Exception:
            pcm_bytes = b''
    else:
        pcm_bytes = b''
    if not pcm_bytes:
        pcm = bytearray(len(raw))
        for idx in range(0, len(raw), 2):
            value = raw[idx] | raw[idx + 1] << 8
            sample = value - 32768
            pcm[idx:idx + 2] = basefwx.struct.pack('<h', sample)
        pcm_bytes = bytes(pcm)
    with basefwx.wave.open(str(output_path), 'wb') as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(basefwx.KFM_AUDIO_RATE)
        wav_file.writeframes(pcm_bytes)


def _kfm_wav_to_bytes(path: 'basefwx.pathlib.Path') -> bytes:
    with basefwx.wave.open(str(path), 'rb') as wav_file:
        channels = wav_file.getnchannels()
        width = wav_file.getsampwidth()
        frames = wav_file.readframes(wav_file.getnframes())
    if channels != 1 or width != 2:
        return frames
    return basefwx._kfm_pcm16le_to_bytes(frames)


def _kfm_pcm16le_to_bytes(frames: bytes) -> bytes:
    if len(frames) % 2:
        frames += b'\x00'
    if basefwx.np is not None:
        try:
            np_i16 = basefwx.np.frombuffer(frames, dtype=basefwx.np.dtype('<i2'))
            if basefwx._kfm_should_use_cuda(len(frames)):
                gpu_i16 = basefwx.cp.asarray(np_i16, dtype=basefwx.cp.int16)
                gpu_u16 = (gpu_i16.astype(basefwx.cp.int32) + 32768 & basefwx.cp.asarray(65535, dtype=basefwx.cp.int32)).astype(basefwx.cp.uint16)
                return basefwx.cp.asnumpy(gpu_u16).tobytes()
            np_u16 = (np_i16.astype(basefwx.np.int32) + 32768 & 65535).astype(basefwx.np.uint16)
            return np_u16.tobytes()
        except Exception:
            pass
    out = bytearray(len(frames))
    for idx in range(0, len(frames), 2):
        sample = basefwx.struct.unpack('<h', frames[idx:idx + 2])[0]
        value = sample + 32768 & 65535
        out[idx:idx + 2] = basefwx.struct.pack('<H', value)
    return bytes(out)


def _kfm_ffmpeg_audio_to_bytes(path: 'basefwx.pathlib.Path') -> bytes:
    ffmpeg_bin = basefwx.os.environ.get('BASEFWX_FFMPEG_BIN', 'ffmpeg')
    cmd = [ffmpeg_bin, '-v', 'error', '-i', str(path), '-f', 's16le', '-ac', '1', '-ar', str(basefwx.KFM_AUDIO_RATE), '-']
    try:
        result = basefwx.subprocess.run(cmd, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError('ffmpeg is required to read non-WAV audio (mp3/m4a). Install ffmpeg or provide WAV input.') from exc
    if result.returncode != 0:
        stderr = (result.stderr or b'').decode('utf-8', errors='replace').strip()
        detail = f': {stderr}' if stderr else ''
        raise RuntimeError(f'ffmpeg failed to decode audio{detail}')
    if not result.stdout:
        raise RuntimeError('ffmpeg produced no PCM output')
    return basefwx._kfm_pcm16le_to_bytes(result.stdout)


def _kfm_audio_to_bytes(path: 'basefwx.pathlib.Path') -> bytes:
    wav_error = None
    try:
        return basefwx._kfm_wav_to_bytes(path)
    except Exception as exc:
        wav_error = exc
    try:
        return basefwx._kfm_ffmpeg_audio_to_bytes(path)
    except Exception as ffmpeg_error:
        raise RuntimeError(f'Failed to decode audio carrier from {path.name}. WAV parse error: {wav_error}; ffmpeg error: {ffmpeg_error}') from ffmpeg_error


def _kfm_bytes_to_png(data: bytes, output_path: 'basefwx.pathlib.Path', *, bw_mode: bool=False) -> None:
    if basefwx.Image is None:
        raise RuntimeError('Pillow is required for kFM PNG operations')
    if isinstance(data, memoryview):
        raw = data.tobytes()
    elif isinstance(data, bytearray):
        raw = bytes(data)
    else:
        raw = data
    channels = 1 if bw_mode else 3
    mode = 'L' if bw_mode else 'RGB'
    pixels = max(1, (len(raw) + channels - 1) // channels)
    width = max(1, int(basefwx.math.sqrt(pixels)))
    if width * width < pixels:
        width += 1
    height = (pixels + width - 1) // width
    capacity = width * height * channels
    carrier = bytearray(basefwx.secrets.token_bytes(capacity))
    carrier[:len(raw)] = raw
    image = basefwx.Image.frombytes(mode, (width, height), bytes(carrier))
    image.save(str(output_path), format='PNG')


def _kfm_png_to_bytes(path: 'basefwx.pathlib.Path') -> bytes:
    if basefwx.Image is None:
        raise RuntimeError('Pillow is required for kFM PNG operations')
    with basefwx.Image.open(str(path)) as image:
        if image.mode == 'L':
            return image.tobytes()
        if image.mode != 'RGB':
            image = image.convert('RGB')
        return image.tobytes()


def _kfm_detect_carrier_kinds(src: 'basefwx.pathlib.Path', src_ext: str) -> 'basefwx.typing.List[str]':
    if basefwx._kfm_is_audio_ext(src_ext):
        return ['audio']
    if basefwx._kfm_is_image_ext(src_ext):
        return ['image']
    head = b''
    try:
        with src.open('rb') as handle:
            head = handle.read(16)
    except Exception:
        head = b''
    kinds: list[str] = []
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        kinds.append('image')
    if len(head) >= 12 and head[:4] == b'RIFF' and (head[8:12] == b'WAVE'):
        kinds.append('audio')
    if not kinds:
        kinds = ['audio', 'image']
    else:
        if 'audio' not in kinds:
            kinds.append('audio')
        if 'image' not in kinds:
            kinds.append('image')
    return kinds


def _kfm_decode_container(src: 'basefwx.pathlib.Path', src_ext: str) -> dict:
    kinds = basefwx._kfm_detect_carrier_kinds(src, src_ext)
    attempt_errors: list[str] = []
    for kind in kinds:
        try:
            carrier = basefwx._kfm_audio_to_bytes(src) if kind == 'audio' else basefwx._kfm_png_to_bytes(src)
        except Exception as exc:
            if len(kinds) == 1:
                raise
            attempt_errors.append(f'{kind}: {exc}')
            continue
        decoded = basefwx._kfm_unpack_container(carrier)
        if decoded is not None:
            return decoded
        attempt_errors.append(f'{kind}: no BaseFWX header')
    detail = '; '.join(attempt_errors[:2])
    if detail:
        detail = f' ({detail})'
    raise ValueError(f'kFMd refused input: file is not a BaseFWX kFM carrier. Use kFMe to encode first{detail}.')
