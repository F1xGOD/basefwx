# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from basefwx.legacy import basefwx


class PayloadKeySeparationTests(unittest.TestCase):
    PASSWORD = "correct-password"

    @staticmethod
    def _metadata(version=None, obfuscation="yes"):
        info = {
            "ENC-KDF": "pbkdf2",
            "ENC-KDF-ITER": str(basefwx.USER_KDF_ITERATIONS),
            "ENC-OBF": obfuscation,
        }
        if version is not None:
            info["ENC-KSEP"] = version
        return base64.b64encode(
            json.dumps(info, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    def _roundtrip(self, version, obfuscation):
        metadata = self._metadata(version, obfuscation)
        plaintext = (
            metadata
            + basefwx.META_DELIM
            + "payload key separation regression"
        )
        blob = basefwx.encryptAES(
            plaintext,
            self.PASSWORD,
            use_master=False,
            metadata_blob=metadata,
            kdf="pbkdf2",
            kdf_iterations=basefwx.USER_KDF_ITERATIONS,
            obfuscate=obfuscation != "no",
        )
        self.assertEqual(
            plaintext,
            basefwx.decryptAES(
                blob,
                self.PASSWORD,
                use_master=False,
            ),
        )

    def test_v1_roundtrip_with_and_without_obfuscation(self):
        for obfuscation in ("yes", "no"):
            with self.subTest(obfuscation=obfuscation):
                self._roundtrip("v1", obfuscation)

    def test_decoder_follows_authenticated_obfuscation_mode(self):
        metadata = self._metadata("v1", "yes")
        plaintext = (
            metadata
            + basefwx.META_DELIM
            + "wire metadata controls decode"
        )
        with mock.patch.object(
            basefwx, "ENABLE_OBFUSCATION", True
        ):
            blob = basefwx.encryptAES(
                plaintext,
                self.PASSWORD,
                use_master=False,
                metadata_blob=metadata,
                kdf="pbkdf2",
                kdf_iterations=basefwx.USER_KDF_ITERATIONS,
                obfuscate=True,
            )
        with mock.patch.object(
            basefwx, "ENABLE_OBFUSCATION", False
        ):
            self.assertEqual(
                plaintext,
                basefwx.decryptAES(
                    blob,
                    self.PASSWORD,
                    use_master=False,
                ),
            )

    def test_unknown_obfuscation_mode_fails_closed(self):
        metadata = self._metadata("v1", "future")
        plaintext = metadata + basefwx.META_DELIM + "payload"
        blob = basefwx.encryptAES(
            plaintext,
            self.PASSWORD,
            use_master=False,
            metadata_blob=metadata,
            kdf="pbkdf2",
            kdf_iterations=basefwx.USER_KDF_ITERATIONS,
            obfuscate=True,
        )
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported payload obfuscation mode",
        ):
            basefwx.decryptAES(
                blob,
                self.PASSWORD,
                use_master=False,
            )

    def test_absent_marker_remains_legacy_compatible(self):
        self._roundtrip(None, "yes")

    def test_unknown_marker_rejected_before_key_transport(self):
        metadata = self._metadata("v2")
        plaintext = metadata + basefwx.META_DELIM + "payload"
        with mock.patch.object(
            basefwx,
            "_select_master_key",
            side_effect=AssertionError("key transport reached"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "Unsupported payload key-separation version",
            ):
                basefwx.encryptAES(
                    plaintext,
                    self.PASSWORD,
                    use_master=False,
                    metadata_blob=metadata,
                    kdf="pbkdf2",
                )

    def test_new_metadata_emits_v1_but_stripped_metadata_stays_absent(self):
        metadata = basefwx._build_metadata(
            "AES-HEAVY",
            False,
            False,
            master_kem="none",
            kdf="pbkdf2",
            key_separation="v1",
        )
        self.assertEqual(
            "v1",
            basefwx._decode_metadata(metadata)["ENC-KSEP"],
        )
        self.assertEqual(
            "",
            basefwx._build_metadata(
                "AES-HEAVY",
                True,
                False,
                master_kem="none",
                kdf="pbkdf2",
                key_separation="v1",
            ),
        )

    def test_streaming_obfuscation_off_emits_no_and_roundtrips(self):
        payload = bytes(
            (index * 31 + 7) & 0xFF
            for index in range(3 * 1024 * 1024 + 29)
        )
        with tempfile.TemporaryDirectory(
            prefix="basefwx-pb512-obf-off-"
        ) as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            encrypted = root / "encrypted.fwx"
            source.write_bytes(payload)
            with (
                mock.patch.object(
                    basefwx, "ENABLE_OBFUSCATION", False
                ),
                mock.patch.object(
                    basefwx, "HEAVY_PBKDF2_ITERATIONS", 1
                ),
                mock.patch.object(basefwx, "USER_KDF", "pbkdf2"),
                mock.patch.object(
                    basefwx, "USER_KDF_DEFAULT", "pbkdf2"
                ),
                mock.patch.object(basefwx, "hash_secret_raw", None),
                mock.patch.object(basefwx, "_SILENT_MODE", True),
            ):
                basefwx._aes_heavy_encode_path_stream(
                    source,
                    self.PASSWORD,
                    use_master=False,
                    output_path=encrypted,
                    keep_input=True,
                )

            with encrypted.open("rb") as handle:
                user_length = int.from_bytes(handle.read(4), "big")
                handle.seek(user_length, 1)
                master_length = int.from_bytes(handle.read(4), "big")
                handle.seek(master_length, 1)
                handle.seek(4, 1)
                metadata_length = int.from_bytes(
                    handle.read(4), "big"
                )
                metadata_blob = handle.read(
                    metadata_length
                ).decode("utf-8")
            metadata = basefwx._decode_metadata(metadata_blob)
            self.assertEqual("v1", metadata["ENC-KSEP"])
            self.assertEqual("no", metadata["ENC-OBF"])

            with (
                mock.patch.object(
                    basefwx, "ENABLE_OBFUSCATION", True
                ),
                mock.patch.object(basefwx, "hash_secret_raw", None),
                mock.patch.object(basefwx, "_SILENT_MODE", True),
            ):
                decoded, _ = basefwx._aes_heavy_decode_path(
                    encrypted,
                    self.PASSWORD,
                    use_master=False,
                )
            self.assertEqual(payload, decoded.read_bytes())


if __name__ == "__main__":
    unittest.main()
