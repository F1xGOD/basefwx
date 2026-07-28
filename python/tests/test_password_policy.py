# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused regressions for public Python encryption password gates."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from basefwx.main import basefwx


class PasswordPolicyTests(unittest.TestCase):
    def policy_environment(self, **updates):
        values = {
            "BASEFWX_ALLOW_WEAK_PASSWORD": "",
            "BASEFWX_MIN_PASSWORD_LEN": "",
        }
        values.update(updates)
        return patch.dict(os.environ, values, clear=False)

    def test_negative_minimum_does_not_disable_default(self):
        with self.policy_environment(BASEFWX_MIN_PASSWORD_LEN="-1"):
            with self.assertRaisesRegex(ValueError, "at least 10 UTF-8 bytes"):
                basefwx._require_strong_password_for_encryption(b"short")

    def test_stream_and_live_entry_points_reject_weak_passwords(self):
        with self.policy_environment():
            with self.assertRaisesRegex(ValueError, "fwxAES stream"):
                basefwx.fwxAES_encrypt_stream(
                    io.BytesIO(b"payload"), io.BytesIO(), "short"
                )
            with self.assertRaisesRegex(ValueError, "fwxAES live"):
                basefwx.LiveEncryptor("short")

    def test_mask_wrapped_codecs_reject_weak_passwords(self):
        with self.policy_environment():
            with self.assertRaisesRegex(ValueError, "at least 10 UTF-8 bytes"):
                basefwx.b512encode("payload", "short", use_master=False)
            with self.assertRaisesRegex(ValueError, "at least 10 UTF-8 bytes"):
                basefwx.pb512encode("payload", "short", use_master=False)

    def test_file_entry_point_rejects_weak_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "payload.bin"
            source.write_bytes(b"payload")
            with self.policy_environment():
                with self.assertRaisesRegex(ValueError, "fwxAES file"):
                    basefwx.fwxAES_file(source, "short", keep_input=True)

    def test_explicit_nonnegative_minimum_is_honored(self):
        with self.policy_environment(BASEFWX_MIN_PASSWORD_LEN="5"):
            basefwx._require_strong_password_for_encryption(b"12345")

    def test_master_key_decode_caps_raw_and_compressed_material(self):
        oversized = b"x" * (4 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "too large"):
            basefwx._decode_pubkey_bytes(oversized)
        compressed = zlib.compress(oversized, level=1)
        with self.assertRaisesRegex(ValueError, "too large"):
            basefwx._decode_pubkey_bytes(compressed)


if __name__ == "__main__":
    unittest.main()
