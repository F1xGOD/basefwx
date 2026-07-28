# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Byte-identity KATs vs C++/liboqs vectors under testdata/protocol_kats/."""

from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import basefwx
from basefwx.crypto import _pq

VECTORS = Path(__file__).resolve().parents[2] / "testdata" / "protocol_kats" / "vectors.json"
KAT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "gen_protocol_kats.py"


def _load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


class ProtocolKatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load()

    def test_hkdf_salted(self):
        v = self.data["hkdf_sha256_salted"]
        out = basefwx.hkdf_sha256(
            bytes.fromhex(v["ikm_hex"]),
            length=v["length"],
            info=bytes.fromhex(v["info_hex"]),
            salt=bytes.fromhex(v["salt_hex"]),
        )
        self.assertEqual(out.hex(), v["okm_hex"])

    def test_hkdf_empty_salt(self):
        v = self.data["hkdf_sha256_empty_salt"]
        out = basefwx.hkdf_sha256(
            bytes.fromhex(v["ikm_hex"]),
            length=v["length"],
            info=v["info_utf8"].encode("ascii"),
            salt=b"",
        )
        self.assertEqual(out.hex(), v["okm_hex"])
        out2 = basefwx.hkdf_sha256(
            bytes.fromhex(v["ikm_hex"]),
            length=v["length"],
            info=v["info_utf8"].encode("ascii"),
        )
        self.assertEqual(out, out2)

    def test_x25519(self):
        v = self.data["x25519"]
        shared = basefwx.x25519.derive_shared_secret(
            bytes.fromhex(v["alice_private_hex"]),
            bytes.fromhex(v["bob_public_hex"]),
        )
        self.assertEqual(shared.hex(), v["shared_hex"])
        shared2 = basefwx.x25519.derive_shared_secret(
            bytes.fromhex(v["bob_private_hex"]),
            bytes.fromhex(v["alice_public_hex"]),
        )
        self.assertEqual(shared, shared2)
        with self.assertRaises(ValueError):
            basefwx.x25519.derive_shared_secret(b"\x00" * 32, b"\x00" * 32)

    def test_ml_kem_768(self):
        v = self.data["ml_kem_768"]
        shared = _pq.kem_decrypt(
            bytes.fromhex(v["private_key_hex"]),
            bytes.fromhex(v["ciphertext_hex"]),
        )
        self.assertEqual(shared.hex(), v["shared_hex"])

    def test_ml_kem_1024(self):
        v = self.data["ml_kem_1024"]
        shared = _pq.kem_decrypt(
            bytes.fromhex(v["private_key_hex"]),
            bytes.fromhex(v["ciphertext_hex"]),
        )
        self.assertEqual(shared.hex(), v["shared_hex"])

    def test_generate_keypair_roundtrip(self):
        for alg in ("ml-kem-768", "ml-kem-1024"):
            pub, priv = basefwx.generate_kem_keypair(alg)
            ct, shared = _pq.kem_encrypt(pub)
            shared2 = _pq.kem_decrypt(priv, ct)
            self.assertEqual(shared, shared2)

    def test_public_protocol_building_exports(self):
        expected = {
            "current_kem_algorithm",
            "generate_kem_keypair",
            "hkdf_sha256",
            "is_supported_kem_algorithm",
            "x25519",
        }
        self.assertTrue(expected.issubset(set(basefwx.__all__)))
        self.assertFalse(hasattr(basefwx, "_hkdf_sha256"))
        self.assertFalse(hasattr(basefwx, "_kem_encrypt"))
        self.assertFalse(hasattr(basefwx, "_kem_decrypt"))
        algorithm = basefwx.current_kem_algorithm()
        self.assertTrue(basefwx.is_supported_kem_algorithm(algorithm))

    def test_rejects_mismatched_kem_sizes(self):
        public_768, private_768 = _pq.generate_kem_keypair("ml-kem-768")
        public_1024, _ = _pq.generate_kem_keypair("ml-kem-1024")
        ciphertext_1024, _ = _pq.kem_encrypt(public_1024)
        self.assertEqual(len(public_768), _pq.ml_kem_768.PUBLIC_KEY_SIZE)
        with self.assertRaisesRegex(ValueError, "mismatched"):
            _pq.kem_decrypt(private_768, ciphertext_1024)


class KatGenerationSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("gen_protocol_kats", KAT_SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to import protocol KAT generator")
        cls.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.generator)

    @staticmethod
    def complete_data():
        return {
            "hkdf_sha256_salted": {"okm_hex": "00"},
            "hkdf_sha256_empty_salt": {"okm_hex": "00"},
            "x25519": {"shared_hex": "00"},
            "ml_kem_768": {"shared_hex": "00"},
            "ml_kem_1024": {"shared_hex": "00"},
            "ml_kem_1024_available": True,
        }

    def test_missing_oqs_is_rejected_before_fixture_mutation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = tuple(Path(temp_dir) / name for name in ("root.json", "java.json"))
            for output in outputs:
                output.write_text("original\n", encoding="utf-8")
            incomplete = self.complete_data()
            incomplete["ml_kem_768"] = None
            incomplete["ml_kem_1024"] = None
            incomplete["ml_kem_1024_available"] = False

            with self.assertRaisesRegex(ValueError, "ML-KEM"):
                self.generator.write_fixture_copies(incomplete, outputs)

            self.assertEqual(
                [output.read_text(encoding="utf-8") for output in outputs],
                ["original\n", "original\n"],
            )

    def test_staging_write_failure_preserves_all_existing_copies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = tuple(Path(temp_dir) / name for name in ("root.json", "java.json"))
            for output in outputs:
                output.write_text("original\n", encoding="utf-8")

            with patch.object(
                self.generator,
                "_stage_atomic_write",
                side_effect=OSError("simulated staging failure"),
            ):
                with self.assertRaisesRegex(OSError, "staging failure"):
                    self.generator.write_fixture_copies(self.complete_data(), outputs)

            self.assertEqual(
                [output.read_text(encoding="utf-8") for output in outputs],
                ["original\n", "original\n"],
            )

    def test_copy_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            outputs = tuple(Path(temp_dir) / name for name in ("root.json", "java.json"))
            outputs[0].write_text("one\n", encoding="utf-8")
            outputs[1].write_text("two\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "copies differ"):
                self.generator.check_fixture_copies(outputs)


if __name__ == "__main__":
    unittest.main()
