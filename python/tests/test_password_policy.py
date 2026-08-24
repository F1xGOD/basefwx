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

    def test_short_password_stepup_constants_are_frozen(self):
        """These five values are wire-format constants that never reach the wire.

        The short-password step-up is applied at derivation time on BOTH
        encrypt and decrypt and is not recorded in metadata (an AES-LIGHT blob
        carries no ENC-ARGON2-* at all), so the two sides agree only because
        they compute the same numbers from the same password. Changing any of
        them makes every existing short-password blob undecryptable in every
        runtime, and the failure looks exactly like a wrong password.

        If this test fails, do not update the expected values: a profile change
        has to be negotiated on the wire instead. See SECURITY.md, "Short-password
        KDF step-up".
        """
        self.assertEqual(basefwx.SHORT_PASSWORD_MIN, 12)
        self.assertEqual(basefwx.SHORT_PBKDF2_ITERATIONS, 1_000_000)
        self.assertEqual(basefwx.SHORT_ARGON2_TIME_COST, 5)
        self.assertEqual(basefwx.SHORT_ARGON2_MEMORY_COST, 1 << 17)
        self.assertEqual(basefwx.SHORT_ARGON2_PARALLELISM, 4)

    @unittest.skipIf(
        basefwx.hash_secret_raw is None,
        "Argon2 backend is unavailable",
    )
    def test_short_password_blob_roundtrips_without_argon2_metadata(self):
        """Pins the mechanism the frozen constants above exist to protect."""
        password = "short1"
        self.assertLess(len(password), basefwx.SHORT_PASSWORD_MIN)
        metadata = basefwx._build_metadata(
            "AES-LIGHT", False, False, kdf="argon2id", key_separation="v1"
        )
        plaintext = f"{metadata}{basefwx.META_DELIM}payload"
        with self.policy_environment(BASEFWX_ALLOW_WEAK_PASSWORD="1"):
            blob = basefwx.encryptAES(
                plaintext,
                password,
                use_master=False,
                metadata_blob=metadata,
                kdf="argon2id",
            )
            # The step-up is invisible on the wire: nothing records the costs.
            self.assertNotIn("ENC-ARGON2", metadata)
            # ...yet decrypt still agrees, because it re-runs the same rule.
            self.assertEqual(
                basefwx.decryptAES(blob, password, use_master=False), plaintext
            )

    @unittest.skipIf(
        basefwx.hash_secret_raw is None,
        "Argon2 backend is unavailable",
    )
    def test_stepup_divergence_breaks_existing_blobs(self):
        """Demonstrates the failure mode, so the invariant cannot be argued away."""
        password = "short1"
        metadata = basefwx._build_metadata(
            "AES-LIGHT", False, False, kdf="argon2id", key_separation="v1"
        )
        plaintext = f"{metadata}{basefwx.META_DELIM}payload"
        with self.policy_environment(BASEFWX_ALLOW_WEAK_PASSWORD="1"):
            blob = basefwx.encryptAES(
                plaintext,
                password,
                use_master=False,
                metadata_blob=metadata,
                kdf="argon2id",
            )
            bumped = basefwx.SHORT_ARGON2_TIME_COST + 1
            with patch.object(basefwx, "SHORT_ARGON2_TIME_COST", bumped):
                with self.assertRaisesRegex(ValueError, "incorrect password"):
                    basefwx.decryptAES(blob, password, use_master=False)

    def test_stripped_streams_are_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "payload.bin"
            source.write_bytes(b"payload")
            b512_output = Path(temp_dir) / "b512.fwx"
            heavy_output = Path(temp_dir) / "heavy.fwx"

            with self.assertRaisesRegex(ValueError, "requires metadata"):
                basefwx._b512_encode_path_stream(
                    source,
                    "correct-password",
                    strip_metadata=True,
                    use_master=False,
                    output_path=b512_output,
                    keep_input=True,
                )
            with self.assertRaisesRegex(ValueError, "requires metadata"):
                basefwx._aes_heavy_encode_path_stream(
                    source,
                    "correct-password",
                    strip_metadata=True,
                    use_master=False,
                    output_path=heavy_output,
                    keep_input=True,
                )
            self.assertFalse(b512_output.exists())
            self.assertFalse(heavy_output.exists())

    def test_master_key_decode_caps_raw_and_compressed_material(self):
        oversized = b"x" * (4 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "too large"):
            basefwx._decode_pubkey_bytes(oversized)
        compressed = zlib.compress(oversized, level=1)
        with self.assertRaisesRegex(ValueError, "too large"):
            basefwx._decode_pubkey_bytes(compressed)


if __name__ == "__main__":
    unittest.main()
