# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused regressions for strict-PQ and dual-wrap recovery policy."""

from __future__ import annotations

import os
import io
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from basefwx.crypto import _master_key, _pq, _primitives
from basefwx.main import basefwx


class MasterKeyPolicyTests(unittest.TestCase):
    PASSWORD = b"correct-password"
    MASK_INFO = b"basefwx.test.mask.v1"
    AAD = b"basefwx.test.aad.v1"

    def policy_environment(self, **updates):
        values = {
            "BASEFWX_MASTER_PQ_SK": "",
            "BASEFWX_PQ_STRICT": "",
            "BASEFWX_PQ_ONLY": "",
        }
        values.update(updates)
        return patch.dict(os.environ, values, clear=False)

    def password_wrapped_mask(self):
        with patch.object(basefwx, "USER_KDF", "pbkdf2"):
            return basefwx._prepare_mask_key(
                self.PASSWORD,
                False,
                mask_info=self.MASK_INFO,
                require_password=True,
                aad=self.AAD,
            )

    def test_boolean_spellings_match_cpp_contract(self):
        for value in ("1", "true", "TRUE", "yes", "YeS", "on", "ON"):
            self.assertTrue(_primitives._env_enabled_value(value), value)
        for value in (None, "", "0", "false", "off", "garbage"):
            self.assertFalse(_primitives._env_enabled_value(value), value)

    def test_mutable_secret_clear_zeros_storage(self):
        secret = bytearray(b"sensitive")
        self.assertIsNone(_primitives._clear_secret(secret))
        self.assertEqual(secret, bytearray(len(secret)))

    @unittest.skipIf(os.name == "nt", "POSIX mode assertion")
    def test_ec_keypair_is_published_with_safe_modes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public_path = root / "master.pub"
            private_path = root / "master.pem"
            old_umask = os.umask(0)
            try:
                _master_key._write_ec_keypair(public_path, private_path)
            finally:
                os.umask(old_umask)

            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o644)
            self.assertFalse(list(root.glob(".*.tmp")))

    def test_explicit_private_key_environment_path_wins(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_key = Path(temp_dir) / "env.sk"
            env_key.write_bytes(b"configured-private-key")
            with self.policy_environment(BASEFWX_MASTER_PQ_SK=str(env_key)):
                self.assertEqual(
                    _master_key._load_master_pq_private(),
                    b"configured-private-key",
                )

    def test_missing_explicit_private_key_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.sk"
            with self.policy_environment(BASEFWX_MASTER_PQ_SK=str(missing)):
                with self.assertRaisesRegex(FileNotFoundError, "not found"):
                    _master_key._load_master_pq_private()

    def test_strict_pq_refuses_ec_or_password_only_encrypt_fallback(self):
        with self.policy_environment(BASEFWX_PQ_STRICT="ON"), patch.object(
            basefwx, "_load_master_pq_public", return_value=None
        ), patch.object(basefwx, "_load_master_ec_public", return_value=object()):
            with self.assertRaisesRegex(ValueError, "strict"):
                basefwx._prepare_mask_key(
                    self.PASSWORD,
                    True,
                    mask_info=self.MASK_INFO,
                    require_password=False,
                    aad=self.AAD,
                )
            with self.assertRaisesRegex(ValueError, "strict"):
                basefwx.encryptAES(
                    "payload",
                    self.PASSWORD,
                    use_master=True,
                    kdf="pbkdf2",
                    kdf_iterations=1,
                )
            with self.assertRaisesRegex(ValueError, "strict"):
                basefwx.fwxAES_encrypt_raw(
                    b"payload", self.PASSWORD, use_master=True
                )
            with self.assertRaisesRegex(ValueError, "strict"):
                basefwx.fwxAES_encrypt_stream(
                    io.BytesIO(b"payload"),
                    io.BytesIO(),
                    self.PASSWORD,
                    use_master=True,
                )
            with self.assertRaisesRegex(ValueError, "strict"):
                basefwx.LiveEncryptor(
                    self.PASSWORD, use_master=True
                ).start()

    def test_wrong_master_key_falls_back_to_correct_password(self):
        mask_key, user_blob, _, _ = self.password_wrapped_mask()
        with patch.object(
            basefwx, "_load_master_pq_private", side_effect=ValueError("wrong key")
        ):
            recovered = basefwx._recover_mask_key_from_blob(
                user_blob,
                b"corrupt-pq-master-blob",
                self.PASSWORD,
                True,
                mask_info=self.MASK_INFO,
                aad=self.AAD,
            )
        self.assertEqual(recovered, mask_key)

    def test_disabled_master_still_uses_independent_password_wrap(self):
        mask_key, user_blob, _, _ = self.password_wrapped_mask()
        recovered = basefwx._recover_mask_key_from_blob(
            user_blob,
            b"unused-master-blob",
            self.PASSWORD,
            False,
            mask_info=self.MASK_INFO,
            aad=self.AAD,
        )
        self.assertEqual(recovered, mask_key)

    def test_strict_mode_rejects_ec_master_but_allows_password_wrap(self):
        mask_key, user_blob, _, _ = self.password_wrapped_mask()
        with self.policy_environment(BASEFWX_PQ_ONLY="TrUe"):
            recovered = basefwx._recover_mask_key_from_blob(
                user_blob,
                basefwx.MASTER_EC_MAGIC + b"corrupt",
                self.PASSWORD,
                True,
                mask_info=self.MASK_INFO,
                aad=self.AAD,
            )
        self.assertEqual(recovered, mask_key)

    def test_length_prefixed_codec_uses_password_when_master_recovery_fails(self):
        metadata = basefwx._build_metadata(
            "AES-TEST",
            False,
            False,
            kdf="pbkdf2",
            kdf_iters=1,
            obfuscation=False,
        )
        blob = basefwx.encryptAES(
            "payload",
            self.PASSWORD,
            use_master=False,
            metadata_blob=metadata,
            kdf="pbkdf2",
            kdf_iterations=1,
            obfuscate=False,
        )

        parts = []
        offset = 0
        for _ in range(3):
            length = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            parts.append(blob[offset : offset + length])
            offset += length
        parts[1] = b"corrupt-pq-master-blob"
        modified = b"".join(
            len(part).to_bytes(4, "big") + part for part in parts
        )

        with patch.object(
            basefwx, "_load_master_pq_private", side_effect=ValueError("wrong key")
        ):
            recovered = basefwx.decryptAES(
                modified, self.PASSWORD, use_master=True
            )
        self.assertEqual(recovered, "payload")

    def test_length_prefixed_codec_rejects_truncated_lengths(self):
        malformed = (8).to_bytes(4, "big") + b"short"
        with self.assertRaisesRegex(ValueError, "truncated chunk"):
            basefwx.decryptAES(malformed, self.PASSWORD)

    def test_supported_kem_aliases_and_selected_key_metadata(self):
        class Kem768:
            PUBLIC_KEY_SIZE = 1184

        class Kem1024:
            PUBLIC_KEY_SIZE = 1568

        with patch.object(_pq, "_ml_kem_768", Kem768), patch.object(
            _pq, "_ml_kem_1024", Kem1024
        ):
            for spelling in (
                "ml-kem-768",
                " ML-KEM-768 ",
                "kyber768",
                " Kyber-768 ",
                "ml-kem-1024",
                "kyber1024",
                " kyber-1024 ",
            ):
                self.assertTrue(
                    basefwx.is_supported_kem_algorithm(spelling),
                    spelling,
                )
            for spelling in (None, "", " ", "ml-kem-512"):
                self.assertFalse(
                    basefwx.is_supported_kem_algorithm(spelling)
                )

            selected_1024 = basefwx._select_master_key(
                True, b"x" * Kem1024.PUBLIC_KEY_SIZE
            )
            selected_768 = basefwx._select_master_key(
                True, b"x" * Kem768.PUBLIC_KEY_SIZE
            )
            self.assertEqual(selected_1024.kem_label, "ml-kem-1024")
            self.assertEqual(selected_768.kem_label, "ml-kem-768")

        ec_key = object()
        with patch.object(
            basefwx, "_load_master_pq_public", return_value=None
        ), patch.object(
            basefwx, "_load_master_ec_public", return_value=ec_key
        ):
            selected_ec = basefwx._select_master_key(True)
        self.assertEqual(selected_ec.kem_label, "EC")
        self.assertIs(selected_ec.ec_public, ec_key)
        self.assertEqual(
            basefwx._select_master_key(False).kem_label, "none"
        )

        for label in ("ml-kem-768", "ml-kem-1024", "EC"):
            metadata = basefwx._build_metadata(
                "TEST", False, True, master_kem=label
            )
            self.assertEqual(
                basefwx._decode_metadata(metadata)["ENC-KEM"], label
            )
        self.assertEqual(
            basefwx._decode_metadata(
                basefwx._build_metadata(
                    "TEST", False, False, master_kem="none"
                )
            )["ENC-KEM"],
            "none",
        )

    def test_java37_b512_user_wrap_aad_retry_is_auth_failure_only(self):
        legacy_aad = basefwx.B512_AEAD_INFO
        canonical_aad = b"b512file"
        with patch.object(basefwx, "USER_KDF", "pbkdf2"), patch.object(
            basefwx, "USER_KDF_ITERATIONS", 1
        ), patch.object(basefwx, "_TEST_KDF_ITERS", 1):
            mask_key, user_blob, _, _ = basefwx._prepare_mask_key(
                self.PASSWORD,
                False,
                mask_info=self.MASK_INFO,
                require_password=True,
                aad=legacy_aad,
            )
            recovered = basefwx._recover_mask_key_from_blob(
                user_blob,
                b"",
                self.PASSWORD,
                False,
                mask_info=self.MASK_INFO,
                aad=canonical_aad,
                legacy_user_aad=legacy_aad,
            )
            self.assertEqual(recovered, mask_key)

            with self.assertRaises(Exception):
                basefwx._recover_mask_key_from_blob(
                    user_blob,
                    b"",
                    b"wrong-password",
                    False,
                    mask_info=self.MASK_INFO,
                    aad=canonical_aad,
                    legacy_user_aad=legacy_aad,
                )

            with patch.object(basefwx, "_aead_decrypt") as decrypt:
                with self.assertRaisesRegex(ValueError, "truncated"):
                    basefwx._recover_mask_key_from_blob(
                        b"\xff",
                        b"",
                        self.PASSWORD,
                        False,
                        mask_info=self.MASK_INFO,
                        aad=canonical_aad,
                        legacy_user_aad=legacy_aad,
                    )
                decrypt.assert_not_called()

    def test_java37_b512_user_wrap_fixture_decodes_bytes_and_direct_stream(self):
        password = self.PASSWORD.decode("utf-8")

        def replace_user_wrap(blob: bytes) -> bytes:
            user_blob, master_blob, payload = (
                basefwx._unpack_length_prefixed(blob, 3)
            )
            mask_key = basefwx._recover_mask_key_from_blob(
                user_blob,
                master_blob,
                password,
                False,
                mask_info=basefwx.B512_FILE_MASK_INFO,
                aad=b"b512file",
            )
            label = b"pbkdf2"
            salt = b"\x5a" * basefwx.USER_KDF_SALT_SIZE
            user_key, _ = basefwx._derive_user_key(
                password,
                salt=salt,
                iterations=1,
                kdf="pbkdf2",
            )
            legacy_wrap = basefwx._aead_encrypt(
                user_key, mask_key, basefwx.B512_AEAD_INFO
            )
            legacy_user = (
                bytes([len(label)]) + label + salt + legacy_wrap
            )
            self.assertEqual(len(legacy_user), len(user_blob))
            return basefwx._pack_length_prefixed(
                legacy_user, master_blob, payload
            )

        with patch.object(basefwx, "USER_KDF", "pbkdf2"), patch.object(
            basefwx, "USER_KDF_ITERATIONS", 1
        ), patch.object(basefwx, "_TEST_KDF_ITERS", 1):
            canonical = basefwx.b512file_encode_bytes(
                b"fixture-bytes", ".txt", password, use_master=False
            )
            legacy = replace_user_wrap(canonical)
            decoded, extension = basefwx.b512file_decode_bytes(
                legacy, password, use_master=False
            )
            self.assertEqual(decoded, b"fixture-bytes")
            self.assertEqual(extension, ".txt")

            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                source = root / "source.txt"
                encoded = root / "legacy-stream.fwx"
                source.write_bytes(b"fixture-stream")
                basefwx._b512_encode_path_stream(
                    source,
                    password,
                    use_master=False,
                    output_path=encoded,
                    keep_input=True,
                )
                stream_blob = encoded.read_bytes()
                len_user = int.from_bytes(stream_blob[:4], "big")
                user_end = 4 + len_user
                len_master = int.from_bytes(
                    stream_blob[user_end:user_end + 4], "big"
                )
                master_start = user_end + 4
                master_end = master_start + len_master
                user_blob = stream_blob[4:user_end]
                master_blob = stream_blob[master_start:master_end]
                mask_key = basefwx._recover_mask_key_from_blob(
                    user_blob,
                    master_blob,
                    password,
                    False,
                    mask_info=basefwx.B512_FILE_MASK_INFO,
                    aad=b"b512file",
                )
                label = b"pbkdf2"
                salt = b"\x6b" * basefwx.USER_KDF_SALT_SIZE
                user_key, _ = basefwx._derive_user_key(
                    password,
                    salt=salt,
                    iterations=1,
                    kdf="pbkdf2",
                )
                legacy_wrap = basefwx._aead_encrypt(
                    user_key, mask_key, basefwx.B512_AEAD_INFO
                )
                legacy_user = (
                    bytes([len(label)]) + label + salt + legacy_wrap
                )
                self.assertEqual(len(legacy_user), len(user_blob))
                encoded.write_bytes(
                    len(legacy_user).to_bytes(4, "big")
                    + legacy_user
                    + stream_blob[user_end:]
                )
                decoded_path, _ = basefwx._b512_decode_path(
                    encoded,
                    password,
                    use_master=False,
                )
                self.assertEqual(
                    Path(decoded_path).read_bytes(), b"fixture-stream"
                )

    def test_explicit_ec_paths_are_authoritative_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing_pub = root / "missing-public.pem"
            missing_priv = root / "missing-private.pem"
            with patch.dict(
                os.environ,
                {
                    basefwx.MASTER_EC_PUBLIC_ENV: str(missing_pub),
                    basefwx.MASTER_EC_PRIVATE_ENV: str(missing_priv),
                },
                clear=False,
            ):
                with self.assertRaises(FileNotFoundError):
                    basefwx._load_master_ec_public()
                with self.assertRaises(FileNotFoundError):
                    basefwx._load_master_ec_private()

            oversized = root / "oversized.pem"
            with oversized.open("wb") as handle:
                handle.seek(4 * 1024 * 1024)
                handle.write(b"x")
            with patch.dict(
                os.environ,
                {basefwx.MASTER_EC_PUBLIC_ENV: str(oversized)},
                clear=False,
            ):
                with self.assertRaisesRegex(ValueError, "4 MiB"):
                    basefwx._load_master_ec_public()
            with patch.dict(
                os.environ,
                {basefwx.MASTER_EC_PRIVATE_ENV: str(oversized)},
                clear=False,
            ):
                with self.assertRaisesRegex(ValueError, "4 MiB"):
                    basefwx._load_master_ec_private()


if __name__ == "__main__":
    unittest.main()
