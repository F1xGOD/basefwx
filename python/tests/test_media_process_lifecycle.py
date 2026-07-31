# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused regressions for streaming media subprocess ownership."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from basefwx.main import basefwx
from basefwx.media._process_pipeline import _VideoProcessPipeline


class MediaProcessLifecycleTests(unittest.TestCase):
    def test_stderr_is_drained_concurrently_and_bounded(self):
        decoder_cmd = [
            sys.executable,
            "-c",
            "import sys; sys.stderr.buffer.write(b'x' * (2 << 20))",
        ]
        encoder_cmd = [
            sys.executable,
            "-c",
            "import sys; sys.stdin.buffer.read(); sys.stderr.write('encoder-tail')",
        ]
        pipeline = _VideoProcessPipeline(decoder_cmd, encoder_cmd)
        try:
            pipeline.encoder.stdin.close()
            decoder_code, encoder_code = pipeline.wait()
            self.assertEqual(decoder_code, 0)
            self.assertEqual(encoder_code, 0)
            self.assertEqual(len(pipeline.decoder_error), 1 << 20)
            self.assertEqual(pipeline.encoder_error, "encoder-tail")
        finally:
            pipeline.close()

    def test_decoder_is_reaped_when_encoder_spawn_fails(self):
        decoder_cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
        real_popen = subprocess.Popen
        started = []

        def fail_second_spawn(*args, **kwargs):
            if not started:
                process = real_popen(*args, **kwargs)
                started.append(process)
                return process
            raise FileNotFoundError("encoder unavailable")

        with patch.object(
            basefwx.subprocess,
            "Popen",
            side_effect=fail_second_spawn,
        ):
            with self.assertRaisesRegex(FileNotFoundError, "encoder unavailable"):
                _VideoProcessPipeline(decoder_cmd, ["missing-encoder"])

        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())

    def test_raw_video_rejects_a_truncated_final_frame(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "truncated.rgb"
            output = Path(temp_dir) / "output.rgb"
            source.write_bytes(b"\x00\x01")
            with self.assertRaisesRegex(ValueError, "truncated frame"):
                basefwx.MediaCipher._scramble_video_raw(
                    source,
                    output,
                    1,
                    1,
                    30.0,
                    b"\x00" * 32,
                    workers=1,
                )


if __name__ == "__main__":
    unittest.main()
