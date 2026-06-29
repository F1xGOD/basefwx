# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.


from __future__ import annotations

import warnings

from ._media_shared import basefwx


class _MediaPipelineMixin:
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
            warnings.warn('jMG archive_original=False omits embedded original payload; decrypted output may not be byte-identical to the input.', UserWarning)
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
                        warnings.warn('jMG no-archive payload detected; restored media may not be byte-identical to the original input.', UserWarning)
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
