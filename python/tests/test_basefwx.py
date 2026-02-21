import collections
import io
import json
import math
import os
import random
import shutil
import site
import subprocess
import sys
import tempfile
import unittest
import warnings
import wave
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
try:
    from pqcrypto.kem import ml_kem_768
except Exception:  # pragma: no cover - optional dependency
    ml_kem_768 = None

try:
    from basefwx.main import basefwx
except ModuleNotFoundError as exc:  # pragma: no cover - dependency missing
    basefwx = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


MASTER_PQ_SECRET_B64 = (
    "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"
)


@unittest.skipIf(basefwx is None, f"dependency unavailable: {_IMPORT_ERROR}")
class BaseFWXUnitTests(unittest.TestCase):
    """Unit-style tests: reversible codecs, hash helpers, AES text blobs, metadata warnings, CLI smokes."""

    def setUp(self) -> None:
        self.tmpdir = TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)
        self.user_site = site.getusersitepackages()
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.tmp_path)
        (self.tmp_path / "master_pq.sk").write_text(MASTER_PQ_SECRET_B64, encoding="utf-8")
        self.repo_root = Path(__file__).resolve().parent.parent
        self._orig_master_override = basefwx._MASTER_PUBKEY_OVERRIDE
        self._orig_priv_loader = basefwx.__dict__['_load_master_pq_private']
        self._recording_reporter = None

    def tearDown(self) -> None:
        if self.old_home is not None:
            os.environ["HOME"] = self.old_home
        else:
            os.environ.pop("HOME", None)
        basefwx._set_master_pubkey_override(self._orig_master_override)
        basefwx._load_master_pq_private = self._orig_priv_loader
        self.tmpdir.cleanup()

    class _RecordingReporter:
        def __init__(self) -> None:
            self.phases: list[str] = []

        def update(self, file_index: int, fraction: float, phase: str, path: Path, *, size_hint=None) -> None:  # type: ignore[override]
            self.phases.append(phase)

        def finalize_file(self, file_index: int, path: Path, *, size_hint=None) -> None:  # type: ignore[override]
            pass

    def _read_metadata_from_file(self, path: Path) -> dict[str, object]:
        with open(path, 'rb') as handle:
            len_user_bytes = handle.read(4)
            if len(len_user_bytes) < 4:
                return {}
            len_user = int.from_bytes(len_user_bytes, 'big')
            handle.seek(len_user, os.SEEK_CUR)
            len_master_bytes = handle.read(4)
            if len(len_master_bytes) < 4:
                return {}
            len_master = int.from_bytes(len_master_bytes, 'big')
            handle.seek(len_master, os.SEEK_CUR)
            len_payload_bytes = handle.read(4)
            if len(len_payload_bytes) < 4:
                return {}
            len_payload = int.from_bytes(len_payload_bytes, 'big')
            if len_payload < 4:
                return {}
            meta_len_bytes = handle.read(4)
            if len(meta_len_bytes) < 4:
                return {}
            meta_len = int.from_bytes(meta_len_bytes, 'big')
            meta_bytes = handle.read(meta_len)
            if not meta_bytes:
                return {}
            try:
                blob = meta_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return {}
        return basefwx._decode_metadata(blob)

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [self.user_site, env.get("PYTHONPATH")])
        )
        return subprocess.run(
            [sys.executable, "-m", "basefwx", *args],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_generate_random_string_length(self):
        token = basefwx.generate_random_string(42)
        self.assertEqual(len(token), 42)

    def test_fwx256_roundtrip(self):
        original = "HelloQuantum"
        encoded = basefwx.fwx256bin(original)
        decoded = basefwx.fwx256unbin(encoded)
        self.assertEqual(decoded, original)

    def test_hash_functions(self):
        data = "basefwx"
        h512 = basefwx.hash512(data)
        self.assertEqual(len(h512), 128)  # SHA-512 hex digest is 128 chars
        uhash = basefwx.uhash513(data)
        self.assertEqual(len(uhash), 64)
        self.assertNotEqual(h512, uhash)

    def test_pb512_roundtrip_without_master(self):
        original = "PQ Ready"
        cipher = basefwx.pb512encode(original, "pw", use_master=False)
        plain = basefwx.pb512decode(cipher, "pw", use_master=False)
        self.assertEqual(plain, original)

    def test_b512_roundtrip_without_master(self):
        original = "Reversible" * 2
        cipher = basefwx.b512encode(original, "pw", use_master=False)
        plain = basefwx.b512decode(cipher, "pw", use_master=False)
        self.assertEqual(plain, original)

    def test_n10_roundtrip_text(self):
        original = "n10 unicode ✓ test"
        encoded = basefwx.n10encode(original)
        decoded = basefwx.n10decode(encoded)
        self.assertEqual(decoded, original)

    def test_n10_roundtrip_bytes(self):
        original = os.urandom(257)
        encoded = basefwx.n10encode_bytes(original)
        decoded = basefwx.n10decode_bytes(encoded)
        self.assertEqual(decoded, original)

    def test_kfm_image_audio_roundtrip(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        src = self.tmp_path / "noise.png"
        img = basefwx.Image.frombytes("RGB", (48, 48), os.urandom(48 * 48 * 3))
        img.save(src)
        original = src.read_bytes()

        wav_path = self.tmp_path / "carrier.wav"
        decoded_path = self.tmp_path / "decoded.png"
        basefwx.kFMe(str(src), str(wav_path))
        basefwx.kFMd(str(wav_path), str(decoded_path))

        self.assertTrue(wav_path.exists())
        self.assertTrue(decoded_path.exists())
        self.assertEqual(decoded_path.read_bytes(), original)

    def test_kfm_audio_image_roundtrip_auto(self):
        src = self.tmp_path / "tone.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(os.urandom(4096))
        original = src.read_bytes()

        png_path = self.tmp_path / "carrier.png"
        decoded_path = self.tmp_path / "decoded.wav"
        basefwx.kFMe(str(src), str(png_path), bw_mode=True)
        basefwx.kFMd(str(png_path), str(decoded_path))

        self.assertTrue(png_path.exists())
        self.assertTrue(decoded_path.exists())
        self.assertEqual(decoded_path.read_bytes(), original)

    def test_kfmd_refuses_plain_png(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        src = self.tmp_path / "plain.png"
        img = basefwx.Image.frombytes("RGB", (32, 32), os.urandom(32 * 32 * 3))
        img.save(src)

        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(src))

    def test_kfmd_refuses_plain_wav(self):
        src = self.tmp_path / "plain.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(22050)
            wav_file.writeframes(os.urandom(4096))

        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(src))

    def test_kfme_accepts_audio_input(self):
        src = self.tmp_path / "audio.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(os.urandom(4096))
        out = Path(basefwx.kFMe(str(src)))
        self.assertEqual(out.suffix.lower(), ".png")
        self.assertTrue(out.exists())

    def test_kfmd_refuses_non_carrier_image(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        src = self.tmp_path / "image.png"
        img = basefwx.Image.frombytes("RGB", (16, 16), os.urandom(16 * 16 * 3))
        img.save(src)
        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(src))

    def test_kfmd_refuses_non_carrier_audio(self):
        src = self.tmp_path / "audio.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(os.urandom(4096))
        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(src))

    def test_kfae_default_output_does_not_overwrite_png_input(self):
        src = self.tmp_path / "input.png"
        original = os.urandom(4096)
        src.write_bytes(original)
        out = Path(basefwx.kFAe(str(src), bw_mode=True))
        self.assertTrue(out.exists())
        self.assertNotEqual(out.resolve(), src.resolve())
        self.assertEqual(src.read_bytes(), original)

    def test_kfme_default_output_does_not_overwrite_wav_input(self):
        src = self.tmp_path / "input.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(os.urandom(4096))
        original = src.read_bytes()
        out = Path(basefwx.kFMe(str(src)))
        self.assertTrue(out.exists())
        self.assertNotEqual(out.resolve(), src.resolve())
        self.assertEqual(src.read_bytes(), original)

    def test_kfm_rejects_explicit_same_output_path(self):
        src = self.tmp_path / "input.bin"
        src.write_bytes(os.urandom(1024))
        with self.assertRaises(ValueError):
            basefwx.kFAe(str(src), str(src), bw_mode=True)

    def test_kfm_xor_auto_falls_back_without_cupy(self):
        left = os.urandom(4096)
        right = os.urandom(4096)
        expected = bytes(a ^ b for a, b in zip(left, right))
        with patch.object(basefwx, "cp", None), \
                patch.dict(os.environ, {"BASEFWX_KFM_ACCEL": "auto", "BASEFWX_KFM_ACCEL_MIN_BYTES": "1"}, clear=False):
            got = basefwx._kfm_xor(left, right)
        self.assertEqual(got, expected)

    def test_kfm_cuda_mode_requires_cupy(self):
        with patch.object(basefwx, "cp", None), \
                patch.dict(os.environ, {"BASEFWX_KFM_ACCEL": "cuda"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "kFM CUDA mode requested"):
                basefwx._kfm_should_use_cuda(4096)

    def test_kfmd_refuses_plain_mp3_input(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        if shutil.which("ffmpeg") is None:
            self.skipTest("ffmpeg unavailable")
        src = self.tmp_path / "plain.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(22050)
            wav_file.writeframes(os.urandom(4096))
        mp3_path = self.tmp_path / "plain.mp3"
        result = subprocess.run(
            ["ffmpeg", "-y", "-v", "error", "-i", str(src), str(mp3_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.skipTest(f"ffmpeg mp3 encode unavailable: {result.stderr.strip()}")
        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(mp3_path))

    def test_kfmd_refuses_plain_m4a_input(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        if shutil.which("ffmpeg") is None:
            self.skipTest("ffmpeg unavailable")
        src = self.tmp_path / "plain.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(22050)
            wav_file.writeframes(os.urandom(4096))
        m4a_path = self.tmp_path / "plain.m4a"
        result = subprocess.run(
            ["ffmpeg", "-y", "-v", "error", "-i", str(src), "-c:a", "aac", str(m4a_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.skipTest(f"ffmpeg m4a encode unavailable: {result.stderr.strip()}")
        with self.assertRaisesRegex(ValueError, "not a BaseFWX kFM carrier"):
            basefwx.kFMd(str(m4a_path))

    def _make_png_fixture(self, name: str = "fixture.png", size: tuple[int, int] = (48, 48)) -> Path:
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        path = self.tmp_path / name
        img = basefwx.Image.frombytes("RGB", size, os.urandom(size[0] * size[1] * 3))
        img.save(path)
        return path

    def _split_live_frames(self, blob: bytes) -> list[bytes]:
        frames: list[bytes] = []
        offset = 0
        header_len = basefwx.LIVE_FRAME_HEADER_STRUCT.size
        while offset < len(blob):
            self.assertGreaterEqual(len(blob) - offset, header_len)
            magic, version, _frame_type, _seq, body_len = basefwx.LIVE_FRAME_HEADER_STRUCT.unpack(
                blob[offset:offset + header_len]
            )
            self.assertEqual(magic, basefwx.LIVE_FRAME_MAGIC)
            self.assertEqual(version, basefwx.LIVE_FRAME_VERSION)
            frame_end = offset + header_len + body_len
            self.assertLessEqual(frame_end, len(blob))
            frames.append(blob[offset:frame_end])
            offset = frame_end
        self.assertEqual(offset, len(blob))
        return frames

    def test_jmg_default_no_archive_uses_key_trailer(self):
        src = self._make_png_fixture("jmg_default_no_archive.png")
        enc = self.tmp_path / "jmg_default_no_archive_enc.png"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            basefwx.MediaCipher.encrypt_media(
                str(src),
                "pw",
                output=str(enc),
                keep_input=True,
            )
        self.assertTrue(any("archive_original=False" in str(w.message) for w in caught))
        blob = enc.read_bytes()
        self.assertIn(basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, blob)
        archive = basefwx._extract_balanced_trailer_from_bytes(
            blob,
            basefwx.IMAGECIPHER_TRAILER_MAGIC,
        )
        self.assertIsNone(archive)

    def test_jmg_key_header_v2_profile_max(self):
        src = self._make_png_fixture("jmg_profile_v2.png")
        enc = self.tmp_path / "jmg_profile_v2_enc.png"
        basefwx.MediaCipher.encrypt_media(
            str(src),
            "pw",
            output=str(enc),
            keep_input=True,
            archive_original=False,
        )
        trailer = basefwx._extract_balanced_trailer_from_bytes(
            enc.read_bytes(),
            basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC,
        )
        self.assertIsNotNone(trailer)
        key_blob, _payload = trailer
        self.assertTrue(key_blob.startswith(basefwx.JMG_KEY_MAGIC))
        parsed = basefwx._jmg_parse_key_header(key_blob, "pw", use_master=True)
        self.assertIsNotNone(parsed)
        _header_len, _base_key, _archive_key, _material, profile_id = parsed
        self.assertEqual(profile_id, basefwx.JMG_SECURITY_PROFILE_MAX)

    def test_jmg_key_header_v1_legacy_compat(self):
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            "pw",
            True,
            mask_info=basefwx.JMG_MASK_INFO,
            require_password=False,
            aad=basefwx.JMG_MASK_AAD,
        )
        _ = mask_key
        payload = basefwx._pack_length_prefixed(user_blob, master_blob)
        header = (
            basefwx.JMG_KEY_MAGIC
            + bytes([basefwx.JMG_KEY_VERSION_LEGACY])
            + len(payload).to_bytes(4, "big")
            + payload
        )
        parsed = basefwx._jmg_parse_key_header(header, "pw", use_master=True)
        self.assertIsNotNone(parsed)
        _header_len, _base_key, _archive_key, _material, profile_id = parsed
        self.assertEqual(profile_id, basefwx.JMG_SECURITY_PROFILE_LEGACY)

    def test_hwaccel_auto_priority_prefers_nvidia(self):
        with patch.dict(os.environ, {"BASEFWX_HWACCEL": "auto"}, clear=False):
            basefwx.MediaCipher._HWACCEL_READY = False
            basefwx.MediaCipher._HWACCEL_CACHE = None
            with patch.object(basefwx.MediaCipher, "_ffmpeg_encoder_set", return_value={"h264_nvenc", "h264_qsv", "h264_vaapi"}), \
                    patch.object(basefwx.MediaCipher, "_ffmpeg_hwaccel_set", return_value={"cuda", "qsv", "vaapi"}), \
                    patch.object(basefwx.MediaCipher, "_has_nvidia_hint", return_value=True), \
                    patch.object(basefwx.MediaCipher, "_has_qsv_hint", return_value=True), \
                    patch.object(basefwx.MediaCipher, "_has_vaapi_hint", return_value=True):
                self.assertEqual(basefwx.MediaCipher._select_hwaccel(), "nvenc")

    def test_hwaccel_strict_rejects_unavailable_request(self):
        env = {
            "BASEFWX_HWACCEL": "nvenc",
            "BASEFWX_HWACCEL_STRICT": "1",
        }
        with patch.dict(os.environ, env, clear=False):
            basefwx.MediaCipher._HWACCEL_READY = False
            basefwx.MediaCipher._HWACCEL_CACHE = None
            with patch.object(basefwx.MediaCipher, "_ffmpeg_encoder_set", return_value=set()), \
                    patch.object(basefwx.MediaCipher, "_ffmpeg_hwaccel_set", return_value=set()), \
                    patch.object(basefwx.MediaCipher, "_has_nvidia_hint", return_value=False):
                with self.assertRaises(RuntimeError):
                    basefwx.MediaCipher._select_hwaccel()

    def test_jmg_logs_hw_plan_line(self):
        src = self._make_png_fixture("jmg_hwlog_src.png")
        enc = self.tmp_path / "jmg_hwlog_enc.png"
        dec = self.tmp_path / "jmg_hwlog_dec.png"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            basefwx.MediaCipher.encrypt_media(
                str(src),
                "pw",
                output=str(enc),
                keep_input=True,
                archive_original=False,
            )
            basefwx.MediaCipher.decrypt_media(str(enc), "pw", output=str(dec))
        logs = stderr.getvalue()
        self.assertIn("[basefwx.hw] op=jMGe", logs)
        self.assertIn("[basefwx.hw] op=jMGd", logs)

    def test_hwaccel_stage_split_video_decode_cpu_encode_gpu(self):
        src = self.tmp_path / "video_stage_split.mp4"
        src.write_bytes(b"stub")
        out = self.tmp_path / "video_stage_split_out.mp4"
        info = {
            "bit_rate": 1_000_000,
            "duration": 1.0,
            "video": {"width": 2, "height": 2, "fps": 30.0, "bit_rate": 900_000},
            "audio": None,
        }
        recorded_cmds: list[list[str]] = []

        def fake_ffmpeg(cmd, fallback_cmd=None):
            _ = fallback_cmd
            recorded_cmds.append(list(cmd))
            target = Path(cmd[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.suffix == ".raw":
                if "video" in target.name:
                    target.write_bytes(os.urandom(2 * 2 * 3))
                else:
                    target.write_bytes(b"")
            else:
                target.write_bytes(b"ok")

        def fake_scramble_video_raw(raw_in, raw_out, *_args, **_kwargs):
            raw_out.write_bytes(raw_in.read_bytes())

        plan = {
            "selected_accel": "nvenc",
            "encode_device": "nvenc",
            "decode_device": "cpu",
            "pixel_backend": "cpu",
            "gpu_pixels_strict": False,
        }

        with patch.object(basefwx.MediaCipher, "_probe_streams", return_value=info), \
                patch.object(basefwx.MediaCipher, "_run_ffmpeg", side_effect=fake_ffmpeg), \
                patch.object(basefwx.MediaCipher, "_probe_metadata", return_value={}), \
                patch.object(basefwx.MediaCipher, "_encrypt_metadata", return_value=[]), \
                patch.object(basefwx.MediaCipher, "_scramble_video_raw", side_effect=fake_scramble_video_raw):
            basefwx.MediaCipher._scramble_video(
                src,
                out,
                "pw",
                keep_meta=False,
                base_key=b"\x22" * 32,
                hw_plan=plan,
            )

        decode_cmd = next(
            cmd for cmd in recorded_cmds if "-map" in cmd and "0:v:0" in cmd and "-f" in cmd and "rawvideo" in cmd
        )
        self.assertNotIn("-hwaccel", decode_cmd)
        encode_cmd = next(cmd for cmd in recorded_cmds if cmd and cmd[-1] == str(out))
        self.assertIn("h264_nvenc", encode_cmd)

    def test_gpu_pixels_auto_falls_back_without_cupy(self):
        env = {
            "BASEFWX_HWACCEL": "auto",
            "BASEFWX_GPU_PIXELS": "auto",
            "BASEFWX_GPU_PIXELS_MIN_BYTES": "1",
        }
        with patch.dict(os.environ, env, clear=False):
            basefwx.MediaCipher._HWACCEL_READY = False
            basefwx.MediaCipher._HWACCEL_CACHE = None
            with patch.object(basefwx.MediaCipher, "_select_hwaccel", return_value="nvenc"), \
                    patch.object(basefwx, "cp", None):
                plan = basefwx.MediaCipher._build_hw_execution_plan(
                    "jMGe",
                    stream_type="video",
                    frame_bytes=16 * 1024 * 1024,
                    allow_pixel_gpu=True,
                    prefer_cpu_decode=True,
                )
        self.assertEqual(plan["pixel_backend"], "cpu")
        self.assertTrue(any("CuPy is unavailable" in reason for reason in plan["reasons"]))

    def test_live_stream_default_chunk_size_uses_live_constant(self):
        class ReadIntoBytesIO(io.BytesIO):
            def __init__(self, data: bytes):
                super().__init__(data)
                self.request_sizes: list[int] = []

            def readinto(self, b):  # type: ignore[override]
                self.request_sizes.append(len(b))
                return super().readinto(b)

        payload = os.urandom(200_000)
        source = ReadIntoBytesIO(payload)
        encrypted = io.BytesIO()
        basefwx.fwxAES_live_encrypt_stream(source, encrypted, "pw", use_master=False)
        self.assertTrue(source.request_sizes)
        self.assertEqual(source.request_sizes[0], basefwx.LIVE_STREAM_CHUNK_SIZE)

        encrypted_source = ReadIntoBytesIO(encrypted.getvalue())
        recovered = io.BytesIO()
        basefwx.fwxAES_live_decrypt_stream(encrypted_source, recovered, "pw", use_master=False)
        self.assertTrue(encrypted_source.request_sizes)
        self.assertEqual(encrypted_source.request_sizes[0], basefwx.LIVE_STREAM_CHUNK_SIZE)
        self.assertEqual(recovered.getvalue(), payload)

    def test_jmg_image_archive_roundtrip_exact(self):
        src = self._make_png_fixture("jmg_src.png")
        original = src.read_bytes()
        enc = self.tmp_path / "jmg_enc.png"
        dec = self.tmp_path / "jmg_dec.png"
        basefwx.MediaCipher.encrypt_media(
            str(src),
            "pw",
            output=str(enc),
            keep_input=True,
            archive_original=True,
        )
        basefwx.MediaCipher.decrypt_media(str(enc), "pw", output=str(dec))
        self.assertEqual(dec.read_bytes(), original)

    def test_jmg_image_no_archive_roundtrip_valid_image(self):
        src = self._make_png_fixture("jmg_src_no_archive.png")
        enc = self.tmp_path / "jmg_enc_no_archive.png"
        dec = self.tmp_path / "jmg_dec_no_archive.png"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            basefwx.MediaCipher.encrypt_media(
                str(src),
                "pw",
                output=str(enc),
                keep_input=True,
                archive_original=False,
            )
        self.assertTrue(any("archive_original=False" in str(w.message) for w in caught))
        self.assertIn(basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, enc.read_bytes())
        with warnings.catch_warnings(record=True) as caught_dec:
            warnings.simplefilter("always")
            basefwx.MediaCipher.decrypt_media(str(enc), "pw", output=str(dec))
        self.assertTrue(any("no-archive payload" in str(w.message) for w in caught_dec))
        self.assertTrue(dec.exists())
        opened = basefwx.Image.open(dec)
        self.assertGreater(opened.size[0], 0)
        self.assertGreater(opened.size[1], 0)
        opened.close()

    def test_jmg_image_no_archive_master_only_roundtrip(self):
        if ml_kem_768 is None:
            self.skipTest("pqcrypto unavailable")
        public_key, private_key = ml_kem_768.generate_keypair()
        basefwx._set_master_pubkey_override(public_key)
        basefwx._load_master_pq_private = staticmethod(lambda: private_key)
        src = self._make_png_fixture("jmg_master.png")
        enc = self.tmp_path / "jmg_master_enc.png"
        dec = self.tmp_path / "jmg_master_dec.png"
        basefwx.MediaCipher.encrypt_media(
            str(src),
            "",
            output=str(enc),
            keep_input=True,
            archive_original=False,
        )
        basefwx.MediaCipher.decrypt_media(str(enc), "", output=str(dec))
        self.assertTrue(dec.exists())
        self.assertGreater(dec.stat().st_size, 0)

    def test_jmg_video_disabled_by_default(self):
        if shutil.which("ffmpeg") is None:
            self.skipTest("ffmpeg unavailable")
        src = self.tmp_path / "jmg_video_disabled_src.mp4"
        make_src = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=128x72:rate=24",
            "-t",
            "1",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            str(src),
        ]
        subprocess.run(make_src, check=True, capture_output=True, text=True)
        with self.assertRaisesRegex(RuntimeError, "jMG video mode is temporarily disabled"):
            basefwx.MediaCipher.encrypt_media(
                str(src),
                "pw",
                output=str(self.tmp_path / "jmg_video_disabled_enc.mp4"),
                keep_input=True,
                archive_original=False,
            )

    def test_probe_streams_ignores_attached_pic_video(self):
        sample = {
            "streams": [
                {
                    "codec_type": "video",
                    "width": 600,
                    "height": 600,
                    "avg_frame_rate": "0/0",
                    "r_frame_rate": "0/0",
                    "bit_rate": "32000",
                    "disposition": {"attached_pic": 1},
                },
                {
                    "codec_type": "audio",
                    "sample_rate": "44100",
                    "channels": 2,
                    "bit_rate": "128000",
                    "disposition": {"attached_pic": 0},
                },
            ],
            "format": {"duration": "10.0", "bit_rate": "160000"},
        }

        class _FakeResult:
            def __init__(self):
                self.returncode = 0
                self.stdout = json.dumps(sample)
                self.stderr = ""

        with patch.object(basefwx.MediaCipher, "_ensure_ffmpeg", return_value=None), \
                patch.object(basefwx.subprocess, "run", return_value=_FakeResult()):
            info = basefwx.MediaCipher._probe_streams(self.tmp_path / "tagged.mp3")
        self.assertIsNone(info.get("video"))
        self.assertIsNotNone(info.get("audio"))

    def test_probe_streams_ignores_audio_cover_art_without_disposition(self):
        sample = {
            "streams": [
                {
                    "codec_type": "audio",
                    "sample_rate": "48000",
                    "channels": 2,
                    "r_frame_rate": "0/0",
                    "avg_frame_rate": "0/0",
                    "bit_rate": "256000",
                },
                {
                    "codec_type": "video",
                    "width": 1280,
                    "height": 720,
                    "r_frame_rate": "0/0",
                    "avg_frame_rate": "0/0",
                },
            ],
            "format": {"duration": "10.0", "bit_rate": "280000"},
        }

        class _FakeResult:
            def __init__(self):
                self.returncode = 0
                self.stdout = json.dumps(sample)
                self.stderr = ""

        with patch.object(basefwx.MediaCipher, "_ensure_ffmpeg", return_value=None), \
                patch.object(basefwx.subprocess, "run", return_value=_FakeResult()):
            info = basefwx.MediaCipher._probe_streams(self.tmp_path / "tagged-no-disposition.mp3")
        self.assertIsNone(info.get("video"))
        self.assertIsNotNone(info.get("audio"))

    def test_unscramble_video_bitrate_regression(self):
        src = self.tmp_path / "video_stub.mp4"
        src.write_bytes(b"stub")
        out = self.tmp_path / "video_stub_out.mp4"
        info = {
            "bit_rate": 1_000_000,
            "duration": 1.0,
            "video": {"width": 2, "height": 2, "fps": 30.0, "bit_rate": 900_000},
            "audio": None,
        }

        def fake_ffmpeg(cmd, fallback_cmd=None):
            target = Path(cmd[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.suffix == ".raw":
                if "video" in target.name:
                    target.write_bytes(os.urandom(2 * 2 * 3 * 2))
                else:
                    target.write_bytes(b"")
            else:
                target.write_bytes(b"ok")

        def fake_unscramble_stream(
            decode_cmd,
            encode_cmd,
            width,
            height,
            fps,
            base_key,
            *,
            security_profile=0,
            progress_cb=None,
            workers=None,
            use_gpu_pixels=False,
            gpu_pixels_strict=False,
            total_frames_hint=0,
        ):
            target = Path(encode_cmd[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"ok")
            if progress_cb:
                progress_cb(1.0)

        with patch.object(basefwx.MediaCipher, "_probe_streams", return_value=info), \
                patch.object(basefwx.MediaCipher, "_run_ffmpeg", side_effect=fake_ffmpeg), \
                patch.object(basefwx.MediaCipher, "_unscramble_video_stream", side_effect=fake_unscramble_stream), \
                patch.object(basefwx.MediaCipher, "_probe_metadata", return_value={}), \
                patch.object(basefwx.MediaCipher, "_decrypt_metadata", return_value=[]), \
                patch.dict(os.environ, {"BASEFWX_ENABLE_JMG_VIDEO": "1"}, clear=False):
            basefwx.MediaCipher._unscramble_video(
                src,
                out,
                "pw",
                base_key=b"\x11" * 32,
            )
        self.assertTrue(out.exists())

    def test_live_stream_roundtrip_chunked(self):
        payload = os.urandom(96 * 1024)
        chunks = [payload[i:i + 4096] for i in range(0, len(payload), 4096)]
        encrypted_frames = basefwx.fwxAES_live_encrypt_chunks(chunks, "pw", use_master=False)
        encrypted_stream = b"".join(encrypted_frames)
        random.seed(1337)
        parts: list[bytes] = []
        cursor = 0
        while cursor < len(encrypted_stream):
            span = random.randint(1, 307)
            parts.append(encrypted_stream[cursor:cursor + span])
            cursor += span
        recovered = b"".join(basefwx.fwxAES_live_decrypt_chunks(parts, "pw", use_master=False))
        self.assertEqual(recovered, payload)

    def test_ffmpeg_video_codec_args_clamps_huge_bitrate(self):
        args = basefwx.MediaCipher._ffmpeg_video_codec_args(
            Path("out.mp4"),
            target_bitrate=3_548_796_000,
            hwaccel=None,
        )
        self.assertIn("2000000k", args)
        self.assertIn("-bufsize", args)

    def test_live_stream_tamper_rejected(self):
        payload = os.urandom(12 * 1024)
        enc = basefwx.LiveEncryptor("pw", use_master=False)
        blob = enc.start() + enc.update(payload) + enc.finalize()
        frames = self._split_live_frames(blob)
        self.assertGreaterEqual(len(frames), 3)
        tampered_data_frame = bytearray(frames[1])
        tampered_data_frame[-1] ^= 0x01
        tampered_blob = frames[0] + bytes(tampered_data_frame) + frames[2]
        dec = basefwx.LiveDecryptor("pw", use_master=False)
        with self.assertRaises(ValueError):
            dec.update(tampered_blob)

    def test_live_stream_sequence_replay_rejected(self):
        enc = basefwx.LiveEncryptor("pw", use_master=False)
        blob = enc.start()
        blob += enc.update(b"A" * 1024)
        blob += enc.update(b"B" * 1024)
        blob += enc.finalize()
        frames = self._split_live_frames(blob)
        replay_blob = frames[0] + frames[1] + frames[1] + frames[2] + frames[3]
        dec = basefwx.LiveDecryptor("pw", use_master=False)
        with self.assertRaises(ValueError):
            dec.update(replay_blob)

    def test_live_stream_file_wrappers(self):
        payload = os.urandom(32 * 1024)
        source = io.BytesIO(payload)
        encrypted = io.BytesIO()
        basefwx.fwxAES_live_encrypt_stream(source, encrypted, "pw", use_master=False, chunk_size=1024)
        encrypted.seek(0)
        recovered = io.BytesIO()
        basefwx.fwxAES_live_decrypt_stream(encrypted, recovered, "pw", use_master=False, chunk_size=777)
        self.assertEqual(recovered.getvalue(), payload)

    def test_live_ffmpeg_helpers_roundtrip(self):
        if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
            self.skipTest("ffmpeg/ffprobe unavailable")
        src = self.tmp_path / "live_src.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(os.urandom(24000))
        enc = self.tmp_path / "live_stream.fwx"
        dec = self.tmp_path / "live_decoded.wav"
        source_cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(src),
            "-f",
            "matroska",
            "-c",
            "copy",
            "-",
        ]
        sink_cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "matroska",
            "-i",
            "-",
            "-c",
            "copy",
            str(dec),
        ]
        basefwx.fwxAES_live_encrypt_ffmpeg(source_cmd, enc, "pw", use_master=False)
        basefwx.fwxAES_live_decrypt_ffmpeg(enc, sink_cmd, "pw", use_master=False)
        self.assertTrue(enc.exists())
        self.assertTrue(dec.exists())
        self.assertGreater(dec.stat().st_size, 44)
        with wave.open(str(dec), "rb") as wav_file:
            self.assertGreater(wav_file.getnframes(), 0)

    def test_aes_roundtrip_without_master(self):
        original = "Symmetric data"
        blob = basefwx.encryptAES(original, "pw", use_master=False)
        recovered = basefwx.decryptAES(blob, "pw", use_master=False)
        self.assertEqual(recovered, original)

    def test_aes_roundtrip_with_master(self):
        if ml_kem_768 is None:
            self.skipTest("pqcrypto unavailable")
        original = "QuantumGuardian"
        public_key, private_key = ml_kem_768.generate_keypair()
        basefwx._set_master_pubkey_override(public_key)
        basefwx._load_master_pq_private = staticmethod(lambda: private_key)
        blob = basefwx.encryptAES(original, "", use_master=True, master_public_key=public_key)
        recovered = basefwx.decryptAES(blob, "", use_master=True)
        self.assertEqual(recovered, original)

    def test_b512file_cycle(self):
        src = self.tmp_path / "note.txt"
        src.write_text("classified", encoding="utf-8")
        result = basefwx.b512file(str(src), "pw", strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")
        encoded = src.with_suffix('.fwx')
        self.assertTrue(encoded.exists())
        result = basefwx.b512file(str(encoded), "pw", strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")
        restored = src
        self.assertTrue(restored.exists())
        self.assertEqual(restored.read_text(encoding="utf-8"), "classified")

    def test_aesfile_cycle_light(self):
        src = self.tmp_path / "data.bin"
        src.write_bytes(b"FWX\x00PQ")
        result = basefwx.AESfile(str(src), "pw", light=True, strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")
        encoded = src.with_suffix('.fwx')
        self.assertTrue(encoded.exists())
        result = basefwx.AESfile(str(encoded), "pw", light=True, strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")
        restored = src
        self.assertEqual(restored.read_bytes(), b"FWX\x00PQ")

    def test_metadata_hint_message(self):
        meta = {"ENC-METHOD": "FWX512R", "ENC-VERSION": "2.9.0"}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            basefwx._warn_on_metadata(meta, "AES-LIGHT")
        out = buffer.getvalue().strip()
        self.assertIn("Did you mean", out)
        self.assertIn("FWX512R", out)
        self.assertIn("2.9.0", out)

    def test_cli_aes_master(self):
        src = self.tmp_path / "cli.txt"
        src.write_text("cli-power", encoding="utf-8")
        result = self._run_cli("cryptin", "aes", str(src), "-p", "pw", "--no-master")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        encoded = src.with_suffix('.fwx')
        self.assertTrue(encoded.exists())
        result = self._run_cli("cryptin", "aes", str(encoded), "-p", "pw", "--no-master")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(src.read_text(encoding="utf-8"), "cli-power")

    def test_cli_b512_strip(self):
        src = self.tmp_path / "reversible.md"
        src.write_text("### reversible", encoding="utf-8")
        result = self._run_cli("cryptin", "512", str(src), "-p", "pw", "--strip")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        encoded = src.with_suffix('.fwx')
        self.assertTrue(encoded.exists())
        result = self._run_cli("cryptin", "512", str(encoded), "-p", "pw", "--strip")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(src.read_text(encoding="utf-8"), "### reversible")

    def test_cli_n10_file_roundtrip(self):
        src = self.tmp_path / "blob.bin"
        src.write_bytes(os.urandom(513))
        encoded = self.tmp_path / "blob.n10"
        restored = self.tmp_path / "blob.out"
        result = self._run_cli("n10file-enc", str(src), str(encoded))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        result = self._run_cli("n10file-dec", str(encoded), str(restored))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_cli_kfm_roundtrip(self):
        if basefwx.Image is None:
            self.skipTest("Pillow unavailable")
        src = self.tmp_path / "cli-noise.png"
        img = basefwx.Image.frombytes("RGB", (24, 24), os.urandom(24 * 24 * 3))
        img.save(src)
        original = src.read_bytes()

        wav_path = self.tmp_path / "cli-noise.wav"
        restored = self.tmp_path / "cli-noise-restored.png"
        result = self._run_cli("kFMe", str(src), "-o", str(wav_path))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        result = self._run_cli("kFMd", str(wav_path), "-o", str(restored))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(restored.read_bytes(), original)

    def test_cli_kfa_roundtrip(self):
        src = self.tmp_path / "cli-tone.wav"
        with wave.open(str(src), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(16000)
            wav_file.writeframes(os.urandom(3072))
        original = src.read_bytes()

        png_path = self.tmp_path / "cli-tone.png"
        restored = self.tmp_path / "cli-tone-restored.wav"
        result = self._run_cli("kFAe", str(src), "-o", str(png_path), "--bw")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        result = self._run_cli("kFAd", str(png_path), "-o", str(restored))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(restored.read_bytes(), original)

    def test_aes_heavy_small_legacy_mode(self):
        src = self.tmp_path / "legacy.bin"
        payload = b"legacy-data" * 64  # well below streaming threshold
        src.write_bytes(payload)
        reporter = self._RecordingReporter()
        encoded_path, approx = basefwx._aes_heavy_encode_path(
            src,
            "pw",
            reporter,
            file_index=0,
            strip_metadata=False,
            use_master=False,
            master_pubkey=None
        )
        self.assertTrue(encoded_path.exists())
        self.assertFalse(src.exists())  # original removed after encode
        meta = self._read_metadata_from_file(encoded_path)
        self.assertNotEqual(approx, 0)
        self.assertNotIn("ENC-MODE", meta)
        self.assertIn("pb512", reporter.phases)
        self.assertNotIn("pb512-stream", reporter.phases)

        decode_reporter = self._RecordingReporter()
        decoded_path, restored_len = basefwx._aes_heavy_decode_path(
            encoded_path,
            "pw",
            decode_reporter,
            file_index=0,
            strip_metadata=False,
            use_master=False
        )
        self.assertEqual(restored_len, len(payload))
        self.assertEqual(decoded_path.read_bytes(), payload)
        self.assertEqual(decoded_path, self.tmp_path / "legacy.bin")

    def test_aes_heavy_streaming_roundtrip(self):
        src = self.tmp_path / "stream.bin"
        data = os.urandom(512 * 1024)
        src.write_bytes(data)
        created_dirs: list[str] = []
        real_tempdir = tempfile.TemporaryDirectory

        class RecordingTemporaryDirectory:
            def __init__(self, *args, **kwargs):
                self._real = real_tempdir(*args, **kwargs)
                created_dirs.append(self._real.name)

            def cleanup(self) -> None:
                self._real.cleanup()

            @property
            def name(self) -> str:
                return self._real.name

        with patch.object(basefwx.tempfile, "TemporaryDirectory", RecordingTemporaryDirectory):
            reporter = self._RecordingReporter()
            encoded_path, approx = basefwx._aes_heavy_encode_path(
                src,
                "pw",
                reporter,
                file_index=0,
                strip_metadata=False,
                use_master=False,
                master_pubkey=None
            )
            self.assertGreater(approx, 0)
            meta = self._read_metadata_from_file(encoded_path)
            self.assertEqual(meta.get("ENC-MODE"), "STREAM")
            self.assertIn("pb512-stream", reporter.phases)

            decode_reporter = self._RecordingReporter()
            decoded_path, restored_len = basefwx._aes_heavy_decode_path(
                encoded_path,
                "pw",
                decode_reporter,
                file_index=0,
                strip_metadata=False,
                use_master=False
            )
            self.assertEqual(restored_len, len(data))
            self.assertEqual(decoded_path.read_bytes(), data)
            self.assertIn("deobfuscate", decode_reporter.phases)

        for temp_path in created_dirs:
            self.assertFalse(os.path.exists(temp_path))

    def test_aes_light_large_no_obfuscation(self):
        src = self.tmp_path / "large.bin"
        data = os.urandom(400 * 1024)
        src.write_bytes(data)
        encoded_path, approx = basefwx._aes_light_encode_path(
            src,
            "pw",
            None,
            0,
            strip_metadata=False,
            use_master=False,
            master_pubkey=None
        )
        self.assertGreater(approx, 0)
        compressed_bytes = encoded_path.read_bytes()
        blob = basefwx.zlib.decompress(compressed_bytes)
        offset = 0
        len_user = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4 + len_user
        len_master = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4 + len_master
        len_payload = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4
        metadata_len = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4
        metadata_bytes = blob[offset:offset + metadata_len]
        meta_blob = metadata_bytes.decode('utf-8') if metadata_bytes else ""
        meta = basefwx._decode_metadata(meta_blob)
        self.assertEqual(meta.get("ENC-OBF"), "no")

        decoded_path, restored_len = basefwx._aes_light_decode_path(
            encoded_path,
            "pw",
            None,
            0,
            strip_metadata=False,
            use_master=False
        )
        self.assertEqual(restored_len, len(data))
        self.assertEqual(decoded_path.read_bytes(), data)

    def test_b512_streaming_roundtrip(self):
        src = self.tmp_path / "stream512.bin"
        data = os.urandom(512 * 1024)
        src.write_bytes(data)
        reporter = self._RecordingReporter()
        encoded_path, approx = basefwx._b512_encode_path(
            src,
            "pw",
            reporter,
            file_index=0,
            total_files=1,
            strip_metadata=False,
            use_master=False,
            master_pubkey=None
        )
        self.assertGreater(approx, 0)
        meta = self._read_metadata_from_file(encoded_path)
        self.assertEqual(meta.get("ENC-MODE"), "STREAM")
        self.assertIn("pb512-stream", reporter.phases)

        decode_reporter = self._RecordingReporter()
        decoded_path, restored_len = basefwx._b512_decode_path(
            encoded_path,
            "pw",
            decode_reporter,
            file_index=0,
            strip_metadata=False,
            use_master=False
        )
        self.assertEqual(restored_len, len(data))
        self.assertEqual(decoded_path.read_bytes(), data)
        self.assertIn("deobfuscate", decode_reporter.phases)


@unittest.skipIf(basefwx is None, f"dependency unavailable: {_IMPORT_ERROR}")
class CryptographyIntegrationTests(unittest.TestCase):
    """Integration-style tests: AEAD metadata/AAD, master handling, AEAD b512file, obfuscation, fast paths, nonce uniqueness."""

    def setUp(self) -> None:
        self._orig_master_override = basefwx._MASTER_PUBKEY_OVERRIDE
        self._orig_priv_loader = basefwx.__dict__['_load_master_pq_private']
        self._orig_obf_flag = basefwx.ENABLE_OBFUSCATION

    def tearDown(self) -> None:
        basefwx._set_master_pubkey_override(self._orig_master_override)
        basefwx._load_master_pq_private = self._orig_priv_loader
        basefwx.ENABLE_OBFUSCATION = self._orig_obf_flag

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = collections.Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    def test_encrypt_decrypt_aes_light_password_only(self):
        plain_text = "hello aes-light"
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir, "example.txt")
            src.write_text(plain_text, encoding="utf-8")
            result = basefwx.AESfile(src, "p@ssw0rd", light=True, strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            enc_path = src.with_suffix('.fwx')
            self.assertTrue(enc_path.exists())
            result = basefwx.AESfile(enc_path, "p@ssw0rd", light=True, strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            restored = Path(tmpdir, "example.txt")
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_text(encoding="utf-8"), plain_text)

    def test_encrypt_decrypt_aes_heavy_password_only(self):
        payload = os.urandom(2048)
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir, "blob.bin")
            src.write_bytes(payload)
            result = basefwx.AESfile(src, "p@ssw0rd", light=False, strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            enc_path = src.with_suffix('.fwx')
            self.assertTrue(enc_path.exists())
            result = basefwx.AESfile(enc_path, "p@ssw0rd", light=False, strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            restored = Path(tmpdir, "blob.bin")
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_bytes(), payload)

    def test_metadata_tamper_triggers_auth_failure(self):
        metadata = basefwx._build_metadata("UNIT", False, False)
        self.assertTrue(metadata)
        plaintext = f"{metadata}{basefwx.META_DELIM}payload"
        blob = basefwx.encryptAES(plaintext, "secret", use_master=False, metadata_blob=metadata)
        offset = 0
        user_len = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4 + user_len
        master_len = int.from_bytes(blob[offset:offset + 4], 'big')
        offset += 4 + master_len
        payload_len = int.from_bytes(blob[offset:offset + 4], 'big')
        payload = bytearray(blob[offset + 4:offset + 4 + payload_len])
        meta_len = int.from_bytes(payload[:4], 'big')
        self.assertGreater(meta_len, 0)
        payload[4] ^= 0x01
        tampered_blob = blob[:offset + 4] + bytes(payload) + blob[offset + 4 + payload_len:]
        with self.assertRaises(ValueError):
            basefwx.decryptAES(tampered_blob, "secret", use_master=False)

    def test_master_only_roundtrip(self):
        if ml_kem_768 is None:
            self.skipTest("pqcrypto unavailable")
        public_key, private_key = ml_kem_768.generate_keypair()
        basefwx._set_master_pubkey_override(public_key)
        basefwx._load_master_pq_private = staticmethod(lambda: private_key)
        metadata = basefwx._build_metadata("UNIT-MASTER", False, True, kdf="argon2id")
        plaintext = f"{metadata}{basefwx.META_DELIM}sensitive"
        blob = basefwx.encryptAES(plaintext, "", use_master=True, metadata_blob=metadata, master_public_key=public_key)
        recovered = basefwx.decryptAES(blob, "", use_master=True)
        self.assertEqual(recovered, plaintext)
        with self.assertRaises(ValueError):
            basefwx.decryptAES(blob, "", use_master=False)

    def test_no_master_cipher_requires_password(self):
        metadata = basefwx._build_metadata("UNIT", False, False)
        plaintext = f"{metadata}{basefwx.META_DELIM}sensitive"
        blob = basefwx.encryptAES(plaintext, "pw", use_master=False, metadata_blob=metadata)
        with self.assertRaises(ValueError):
            basefwx.decryptAES(blob, "", use_master=True)

    def test_b512_file_aead_roundtrip(self):
        if not getattr(basefwx, "ENABLE_B512_AEAD", True):
            self.skipTest("b512 AEAD disabled")
        basefwx.ENABLE_OBFUSCATION = True
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir, "note.bin")
            original = os.urandom(512)
            src.write_bytes(original)
            result = basefwx.b512file(src, "s3cret!", strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            enc_path = src.with_suffix('.fwx')
            self.assertTrue(enc_path.exists())
            result = basefwx.b512file(enc_path, "s3cret!", strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            restored = Path(tmpdir, "note.bin")
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_bytes(), original)
            result = basefwx.b512file(restored, "s3cret!", strip_metadata=False, use_master=False)
            self.assertEqual(result, "SUCCESS!")
            enc_path = restored.with_suffix('.fwx')
            blob = enc_path.read_bytes()
            user_blob, master_blob, ct_blob = basefwx._unpack_length_prefixed(blob, 3)
            tampered_ct = bytearray(ct_blob)
            tampered_ct[-1] ^= 0x01
            enc_path.write_bytes(basefwx._pack_length_prefixed(user_blob, master_blob, bytes(tampered_ct)))
            result = basefwx.b512file(enc_path, "s3cret!", strip_metadata=False, use_master=False)
            self.assertEqual(result, "FAIL!")

    def test_nonce_uniqueness_smoke(self):
        iterations = 2000
        nonces = set()
        password = "nonce-pass"
        basefwx.ENABLE_OBFUSCATION = True
        # Avoid heavy KDF costs in a tight loop; this test only checks nonce uniqueness.
        fast_kdf = "pbkdf2"
        fast_iters = 1024
        for i in range(iterations):
            metadata = basefwx._build_metadata("NONCE", False, False)
            plaintext = f"{metadata}{basefwx.META_DELIM}nonce-{i}"
            blob = basefwx.encryptAES(
                plaintext,
                password,
                use_master=False,
                metadata_blob=metadata,
                kdf=fast_kdf,
                kdf_iterations=fast_iters,
            )
            offset = 0
            user_len = int.from_bytes(blob[offset:offset + 4], 'big')
            offset += 4 + user_len
            master_len = int.from_bytes(blob[offset:offset + 4], 'big')
            offset += 4 + master_len
            payload_len = int.from_bytes(blob[offset:offset + 4], 'big')
            offset += 4
            payload = blob[offset:offset + payload_len]
            meta_len = int.from_bytes(payload[:4], 'big')
            nonce = payload[4 + meta_len:4 + meta_len + 12]
            self.assertEqual(len(nonce), 12)
            nonces.add(bytes(nonce))
        self.assertEqual(len(nonces), iterations)

    def test_obf_aead_roundtrip_text(self):
        basefwx.ENABLE_OBFUSCATION = True
        vectors = [0, 1, 2, 31, 32, 33, 1024, 65536]
        for length in vectors:
            text = "A" * length
            metadata = basefwx._build_metadata("OBF", False, False)
            payload = f"{metadata}{basefwx.META_DELIM}{text}"
            blob = basefwx.encryptAES(payload, "passphrase", use_master=False, metadata_blob=metadata)
            restored = basefwx.decryptAES(blob, "passphrase", use_master=False)
            self.assertEqual(restored, payload)

    def test_obf_disable(self):
        basefwx.ENABLE_OBFUSCATION = False
        for length in [0, 5, 128, 2048]:
            text = "B" * length
            metadata = basefwx._build_metadata("OBF-OFF", False, False)
            payload = f"{metadata}{basefwx.META_DELIM}{text}"
            blob = basefwx.encryptAES(payload, "passphrase", use_master=False, metadata_blob=metadata)
            restored = basefwx.decryptAES(blob, "passphrase", use_master=False)
            self.assertEqual(restored, payload)

    def test_obf_invertibility_raw(self):
        basefwx.ENABLE_OBFUSCATION = True
        ephemeral_key = os.urandom(32)
        data = os.urandom(4096)
        obf = basefwx._obfuscate_bytes(data, ephemeral_key)
        self.assertEqual(len(obf), len(data))
        clear = basefwx._deobfuscate_bytes(obf, ephemeral_key)
        self.assertEqual(clear, data)

    def test_obf_fast_path_roundtrip(self):
        basefwx.ENABLE_OBFUSCATION = True
        ephemeral_key = os.urandom(32)
        large = os.urandom(256 * 1024)
        obf = basefwx._obfuscate_bytes(large, ephemeral_key)
        self.assertEqual(len(obf), len(large))
        restored = basefwx._deobfuscate_bytes(obf, ephemeral_key)
        self.assertEqual(restored, large)
        vector = np.frombuffer(obf, dtype=np.uint8)
        self.assertGreater(vector.std(), 0.0)
        metadata = basefwx._build_metadata("OBF-FAST", False, False)
        text = "Z" * (256 * 1024)
        payload = f"{metadata}{basefwx.META_DELIM}{text}"
        blob = basefwx.encryptAES(payload, "fastpass", use_master=False, metadata_blob=metadata)
        result = basefwx.decryptAES(blob, "fastpass", use_master=False)
        self.assertEqual(result, payload)

    def test_obf_entropy(self):
        basefwx.ENABLE_OBFUSCATION = True
        plain = b"\x00" * 4096
        ephemeral_key = os.urandom(32)
        obf = basefwx._obfuscate_bytes(plain, ephemeral_key)
        vector = np.frombuffer(obf, dtype=np.uint8)
        self.assertGreater(vector.std(), 0.0)
        self.assertGreater(self._entropy(obf), 4.0)
        ct = basefwx._aead_encrypt(ephemeral_key, obf, b'entropy')
        cipher_entropy = self._entropy(ct[12:])  # skip nonce
        self.assertGreater(cipher_entropy, 4.0)


if __name__ == "__main__":
    unittest.main()
