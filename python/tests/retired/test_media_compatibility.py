# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Compatibility tests for the retired jMG, kFM, and kFA media codecs."""

import io
import json
import os
import shutil
import site
import subprocess
import sys
import unittest
import warnings
import wave
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

TESTS_ROOT = Path(__file__).resolve().parent.parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from test_basefwx import (  # noqa: E402
    MASTER_PQ_SECRET_B64,
    TEST_PASSWORD,
    _IMPORT_ERROR,
    basefwx,
    ml_kem_768,
)


@unittest.skipIf(basefwx is None, f"dependency unavailable: {_IMPORT_ERROR}")
@unittest.skipUnless(
    basefwx is not None and hasattr(basefwx, "MediaCipher"),
    "retired media compatibility is disabled",
)
class RetiredMediaCompatibilityTests(unittest.TestCase):
    """Existing-data and failure-behavior coverage for retired media codecs."""

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
                patch.object(basefwx, "_cp_load_attempted", True), \
                patch.dict(os.environ, {"BASEFWX_KFM_ACCEL": "auto", "BASEFWX_KFM_ACCEL_MIN_BYTES": "1"}, clear=False):
            got = basefwx._kfm_xor(left, right)
        self.assertEqual(got, expected)

    def test_kfm_cuda_mode_requires_cupy(self):
        with patch.object(basefwx, "cp", None), \
                patch.object(basefwx, "_cp_load_attempted", True), \
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

    def test_jmg_default_no_archive_uses_key_trailer(self):
        src = self._make_png_fixture("jmg_default_no_archive.png")
        enc = self.tmp_path / "jmg_default_no_archive_enc.png"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            basefwx.MediaCipher.encrypt_media(
                str(src),
                TEST_PASSWORD,
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
            TEST_PASSWORD,
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
        parsed = basefwx._jmg_parse_key_header(key_blob, TEST_PASSWORD, use_master=True)
        self.assertIsNotNone(parsed)
        _header_len, _base_key, _archive_key, _material, profile_id = parsed
        self.assertEqual(profile_id, basefwx.JMG_SECURITY_PROFILE_MAX)

    def test_jmg_key_header_v1_legacy_compat(self):
        # Build the blobs the way _jmg_prepare_keys does: resolve the master
        # key once and pass the effective decision on. Asking the primitive
        # for a master key that is not configured is a hard error, so an
        # unconditional True made this test depend on the host having one.
        master_selection = basefwx._select_master_key(True)
        mask_key, user_blob, master_blob, _ = basefwx._prepare_mask_key(
            TEST_PASSWORD,
            master_selection.used_master,
            mask_info=basefwx.JMG_MASK_INFO,
            require_password=False,
            aad=basefwx.JMG_MASK_AAD,
            master_selection=master_selection,
        )
        _ = mask_key
        payload = basefwx._pack_length_prefixed(user_blob, master_blob)
        header = (
            basefwx.JMG_KEY_MAGIC
            + bytes([basefwx.JMG_KEY_VERSION_LEGACY])
            + len(payload).to_bytes(4, "big")
            + payload
        )
        parsed = basefwx._jmg_parse_key_header(header, TEST_PASSWORD, use_master=True)
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
                TEST_PASSWORD,
                output=str(enc),
                keep_input=True,
                archive_original=False,
            )
            basefwx.MediaCipher.decrypt_media(str(enc), TEST_PASSWORD, output=str(dec))
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

        def fake_scramble_video_stream(
            decode_cmd, encode_cmd, *_args, **_kwargs
        ):
            recorded_cmds.append(list(decode_cmd))
            recorded_cmds.append(list(encode_cmd))
            target = Path(encode_cmd[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"ok")

        plan = {
            "selected_accel": "nvenc",
            "encode_device": "nvenc",
            "decode_device": "cpu",
            "pixel_backend": "cpu",
            "gpu_pixels_strict": False,
        }

        with patch.object(basefwx.MediaCipher, "_probe_streams", return_value=info), \
                patch.object(basefwx.MediaCipher, "_probe_metadata", return_value={}), \
                patch.object(basefwx.MediaCipher, "_encrypt_metadata", return_value=[]), \
                patch.object(
                    basefwx.MediaCipher,
                    "_scramble_video_stream",
                    side_effect=fake_scramble_video_stream,
                ):
            basefwx.MediaCipher._scramble_video(
                src,
                out,
                TEST_PASSWORD,
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
                    patch.object(basefwx, "cp", None), \
                    patch.object(basefwx, "_cp_load_attempted", True):
                plan = basefwx.MediaCipher._build_hw_execution_plan(
                    "jMGe",
                    stream_type="video",
                    frame_bytes=16 * 1024 * 1024,
                    allow_pixel_gpu=True,
                    prefer_cpu_decode=True,
                )
        self.assertEqual(plan["pixel_backend"], "cpu")
        self.assertTrue(any("CuPy is unavailable" in reason for reason in plan["reasons"]))

    def test_jmg_image_archive_roundtrip_exact(self):
        src = self._make_png_fixture("jmg_src.png")
        original = src.read_bytes()
        enc = self.tmp_path / "jmg_enc.png"
        dec = self.tmp_path / "jmg_dec.png"
        basefwx.MediaCipher.encrypt_media(
            str(src),
            TEST_PASSWORD,
            output=str(enc),
            keep_input=True,
            archive_original=True,
        )
        basefwx.MediaCipher.decrypt_media(str(enc), TEST_PASSWORD, output=str(dec))
        self.assertEqual(dec.read_bytes(), original)

    def test_jmg_image_no_archive_roundtrip_valid_image(self):
        src = self._make_png_fixture("jmg_src_no_archive.png")
        enc = self.tmp_path / "jmg_enc_no_archive.png"
        dec = self.tmp_path / "jmg_dec_no_archive.png"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            basefwx.MediaCipher.encrypt_media(
                str(src),
                TEST_PASSWORD,
                output=str(enc),
                keep_input=True,
                archive_original=False,
            )
        self.assertTrue(any("archive_original=False" in str(w.message) for w in caught))
        self.assertIn(basefwx.IMAGECIPHER_KEY_TRAILER_MAGIC, enc.read_bytes())
        with warnings.catch_warnings(record=True) as caught_dec:
            warnings.simplefilter("always")
            basefwx.MediaCipher.decrypt_media(str(enc), TEST_PASSWORD, output=str(dec))
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
                TEST_PASSWORD,
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
                TEST_PASSWORD,
                base_key=b"\x11" * 32,
            )
        self.assertTrue(out.exists())

    def test_ffmpeg_video_codec_args_clamps_huge_bitrate(self):
        args = basefwx.MediaCipher._ffmpeg_video_codec_args(
            Path("out.mp4"),
            target_bitrate=3_548_796_000,
            hwaccel=None,
        )
        self.assertIn("2000000k", args)
        self.assertIn("-bufsize", args)

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
