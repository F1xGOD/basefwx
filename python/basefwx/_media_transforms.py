# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.


from __future__ import annotations

from ._media_shared import basefwx


class _MediaTransformMixin:
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
