# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused regressions for strict-PQ and dual-wrap recovery policy."""

from __future__ import annotations

import os
import io
import inspect
import stat
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

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

    def test_public_writers_refuse_missing_or_failing_master(self):
        def writers():
            return (
                lambda: basefwx.b512file_encode_bytes(b"payload", ".bin", self.PASSWORD, use_master=True),
                lambda: basefwx.pb512file_encode_bytes(b"payload", ".bin", self.PASSWORD, use_master=True),
                lambda: basefwx.encryptAES("payload", self.PASSWORD, use_master=True),
                lambda: basefwx.fwxAES_encrypt_raw(b"payload", self.PASSWORD, use_master=True),
                lambda: basefwx.fwxAES_encrypt_stream(io.BytesIO(b"payload"), destination, self.PASSWORD, use_master=True),
                lambda: basefwx.LiveEncryptor(self.PASSWORD, use_master=True).start(),
            )
        for strict in ("", "1"):
            with self.subTest(strict=strict), self.policy_environment(BASEFWX_PQ_STRICT=strict), patch.object(
                basefwx, "_load_master_pq_public", return_value=None
            ), patch.object(basefwx, "_load_master_ec_public", return_value=None):
                for writer in writers():
                    destination = io.BytesIO()
                    with self.assertRaisesRegex(ValueError, "master public key"):
                        writer()
                    self.assertEqual(destination.getvalue(), b"")
        with self.policy_environment(), patch.object(
            basefwx, "_load_master_pq_public", return_value=None
        ), patch.object(basefwx, "_load_master_ec_public", return_value=object()), patch.object(
            basefwx, "_ec_kem_enc", side_effect=ValueError("injected master wrap failure")
        ):
            for writer in writers():
                destination = io.BytesIO()
                with self.assertRaisesRegex(ValueError, "injected master wrap failure"):
                    writer()
                self.assertEqual(destination.getvalue(), b"")

    def test_master_and_stripped_metadata_conflict(self):
        with self.assertRaisesRegex(ValueError, "conflicts"):
            basefwx.b512file_encode_bytes(
                b"payload", ".bin", self.PASSWORD, strip_metadata=True, use_master=True
            )

    def test_preselected_recipient_cannot_bypass_strict_policy(self):
        private_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
        selection = _master_key.MasterKeySelection(None, private_key.public_key(), "EC")
        writers = (basefwx.b512encode, basefwx.pb512encode, basefwx.encryptAES)
        with self.policy_environment(BASEFWX_PQ_STRICT="1"), patch.object(
            basefwx, "_ec_kem_enc", side_effect=AssertionError("strict policy reached EC encapsulation")
        ):
            for writer in writers:
                with self.subTest(writer=writer.__name__), self.assertRaisesRegex(ValueError, "PQ strict"):
                    writer("payload", self.PASSWORD, use_master=True, master_selection=selection)

        # Preselection also cannot silently erase an explicit recovery request.
        empty = _master_key.MasterKeySelection(None, None, "none")
        with self.policy_environment():
            for writer in writers:
                with self.subTest(writer=writer.__name__), self.assertRaisesRegex(ValueError, "master key requested"):
                    writer("payload", self.PASSWORD, use_master=True, master_selection=empty)

        # Explicitly disabling recovery keeps password-only authoring available.
        with self.recipient_test_environment(), patch.object(
            basefwx, "_ec_kem_enc", side_effect=AssertionError("disabled recovery reached EC encapsulation")
        ):
            for encode, decode in ((basefwx.b512encode, basefwx.b512decode),
                                   (basefwx.pb512encode, basefwx.pb512decode),
                                   (basefwx.encryptAES, basefwx.decryptAES)):
                with self.subTest(writer=encode.__name__):
                    blob = encode("payload", self.PASSWORD, use_master=False, master_selection=selection)
                    self.assertEqual(decode(blob, self.PASSWORD, use_master=False), "payload")

    def test_file_writer_refusal_preserves_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory, self.policy_environment(), patch.object(
            basefwx, "_load_master_pq_public", return_value=None
        ), patch.object(basefwx, "_load_master_ec_public", return_value=None):
            root = Path(directory)
            source = root / "input.bin"
            destination = root / "input.fwx"
            source.write_bytes(b"source")
            destination.write_bytes(b"existing")
            for writer in (basefwx._b512_encode_path, basefwx._b512_encode_path_stream,
                           basefwx._aes_heavy_encode_path_stream, basefwx._aes_heavy_encode_path):
                with self.subTest(writer=writer.__name__), self.assertRaisesRegex(ValueError, "master key requested"):
                    writer(source, self.PASSWORD, use_master=True)
                self.assertEqual(source.read_bytes(), b"source")
                self.assertEqual(destination.read_bytes(), b"existing")

    def test_public_file_wrappers_refuse_master_strip_conflict(self):
        writers = (
            lambda path: basefwx.b512file_encode(path, self.PASSWORD, strip_metadata=True),
            lambda path: basefwx.b512file(path, self.PASSWORD, strip_metadata=True, silent=True),
            lambda path: basefwx.AESfile(path, self.PASSWORD, strip_metadata=True, silent=True),
            lambda path: basefwx.AESfile(path, self.PASSWORD, light=False, strip_metadata=True, silent=True),
        )
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            source = Path(directory) / "input.bin"
            destination = source.with_suffix(".fwx")
            for index, writer in enumerate(writers):
                with self.subTest(writer=index):
                    source.write_bytes(b"source")
                    destination.write_bytes(b"existing")
                    self.assertEqual(writer(source), "FAIL!")
                    self.assertEqual(source.read_bytes(), b"source")
                    self.assertEqual(destination.read_bytes(), b"existing")

    def test_public_file_readers_do_not_select_writer_master_keys(self):
        operations = (
            lambda path, master: basefwx.b512file(path, self.PASSWORD, use_master=master, silent=True),
            lambda path, master: basefwx.AESfile(path, self.PASSWORD, use_master=master, silent=True),
            lambda path, master: basefwx.AESfile(path, self.PASSWORD, light=False, use_master=master, silent=True),
            lambda path, master: basefwx.fwxAES_file(path, self.PASSWORD, heavy=True, use_master=master),
        )
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), patch.object(
            basefwx, "_SILENT_MODE", True
        ):
            source = Path(directory) / "input.bin"
            for index, operation in enumerate(operations):
                with self.subTest(operation=index):
                    source.write_bytes(b"independent password recovery")
                    operation(source, False)
                    ciphertext = source.with_suffix(".fwx")
                    self.assertTrue(ciphertext.is_file())
                    self.assertFalse(source.exists())
                    with self.policy_environment(BASEFWX_PQ_STRICT="1"), patch.object(
                        basefwx, "_load_master_pq_public", side_effect=AssertionError("reader selected writer key")
                    ), patch.object(
                        basefwx, "_load_master_ec_public", side_effect=AssertionError("reader selected writer key")
                    ):
                        operation(ciphertext, True)
                    self.assertEqual(source.read_bytes(), b"independent password recovery")
                    self.assertFalse(ciphertext.exists())

    def recipient_test_environment(self):
        context = ExitStack()
        context.enter_context(self.policy_environment(BASEFWX_PQ_STRICT="1"))
        # These cases exercise real key wrapping and recovery, not KDF cost.
        for name, value in (("USER_KDF", "pbkdf2"), ("USER_KDF_ITERATIONS", 1),
                            ("HEAVY_PBKDF2_ITERATIONS", 1), ("_TEST_KDF_ITERS", 1)):
            context.enter_context(patch.object(basefwx, name, value))
        context.enter_context(patch.object(basefwx, "_load_master_ec_public", return_value=None))
        context.enter_context(patch.object(basefwx, "_load_master_ec_private", return_value=None))
        context.enter_context(redirect_stdout(io.StringIO()))
        return context

    def test_b512_stream_setup_failure_clears_keys_and_preserves_files(self):
        for failure in ("progress", "temporary-directory"):
            with self.subTest(failure=failure), self.recipient_test_environment(), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "input.bin"
                destination = source.with_suffix(".fwx")
                source.write_bytes(b"source")
                destination.write_bytes(b"existing")
                captured = {}

                def fail_after_keys(*args, **kwargs):
                    # Observe the actual owned buffers before unwinding, so this
                    # tests wiping after an I/O/callback failure, not helper calls.
                    frame = inspect.currentframe()
                    try:
                        while frame is not None and frame.f_code.co_name != "_b512_encode_path_stream":
                            frame = frame.f_back
                        self.assertIsNotNone(frame)
                        for name in ("mask_key", "aead_key", "obf_key"):
                            secret = frame.f_locals[name]
                            self.assertIsInstance(secret, bytearray)
                            self.assertTrue(any(secret), name)
                            captured[name] = secret
                    finally:
                        del frame
                    raise OSError("injected stream setup failure")

                reporter = Mock()
                reporter.update.side_effect = lambda *args, **kwargs: (
                    fail_after_keys() if args[2] == "stream-setup" else None
                )
                with ExitStack() as context:
                    if failure == "temporary-directory":
                        context.enter_context(patch.object(basefwx.tempfile, "TemporaryDirectory", side_effect=fail_after_keys))
                        reporter = None
                    with self.assertRaisesRegex(OSError, "injected stream setup failure"):
                        basefwx._b512_encode_path_stream(
                            source, self.PASSWORD, reporter=reporter,
                            use_master=False, output_path=destination)
                self.assertEqual(set(captured), {"mask_key", "aead_key", "obf_key"})
                for name, secret in captured.items():
                    self.assertFalse(any(secret), name)
                self.assertEqual(source.read_bytes(), b"source")
                self.assertEqual(destination.read_bytes(), b"existing")
                self.assertEqual(set(Path(directory).iterdir()), {source, destination})

    @unittest.skipIf(_pq._ml_kem_768 is None, "real ML-KEM backend required")
    def test_supplied_file_recipient_survives_every_layer_and_size_branch(self):
        public_key, private_key = basefwx.generate_kem_keypair("ml-kem-768")
        other_public, other_private = basefwx.generate_kem_keypair("ml-kem-768")
        operations = (
            lambda path, password, **options: basefwx.b512file(path, password, silent=True, **options),
            lambda path, password, **options: basefwx.AESfile(path, password, light=False, silent=True, **options),
        )
        payloads = (b"payload", b"x" * (basefwx.HKDF_MAX_LEN + 1))
        with self.recipient_test_environment(), tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.bin"
            ciphertext = source.with_suffix(".fwx")
            for index, operation in enumerate(operations):
                for host_key in (None, other_public):
                    for payload in payloads:
                        with self.subTest(operation=index, host_key=host_key is not None, size=len(payload)), patch.object(
                            basefwx, "_load_master_pq_public", return_value=host_key
                        ):
                            source.write_bytes(payload)
                            self.assertEqual(operation(source, self.PASSWORD, use_master=True,
                                                       master_pubkey=public_key), "SUCCESS!")
                            self.assertFalse(source.exists())
                            encoded = ciphertext.read_bytes()
                            # A competing host recipient must not recover the container.
                            with patch.object(basefwx, "_load_master_pq_private", return_value=other_private):
                                self.assertEqual(operation(ciphertext, b"wrong-password", use_master=True), "FAIL!")
                            self.assertFalse(source.exists())
                            self.assertEqual(ciphertext.read_bytes(), encoded)
                            # Only the caller's recipient key, with no correct password.
                            recovery_passwords = (b"", b"wrong-password") if index == 0 else (b"wrong-password",)
                            for recovery_password in recovery_passwords:
                                with patch.object(basefwx, "_load_master_pq_private", return_value=private_key):
                                    self.assertEqual(operation(ciphertext, recovery_password, use_master=True), "SUCCESS!")
                                self.assertEqual(source.read_bytes(), payload)
                                self.assertFalse(ciphertext.exists())
                                source.unlink()
                                ciphertext.write_bytes(encoded)
                            with patch.object(basefwx, "_load_master_pq_private",
                                              side_effect=AssertionError("password path loaded master key")):
                                self.assertEqual(operation(ciphertext, self.PASSWORD, use_master=False), "SUCCESS!")
                            self.assertEqual(source.read_bytes(), payload)
                            self.assertFalse(ciphertext.exists())

    @unittest.skipIf(_pq._ml_kem_768 is None, "real ML-KEM backend required")
    def test_bytes_container_keeps_one_recipient_when_host_key_changes(self):
        public_key, private_key = basefwx.generate_kem_keypair("ml-kem-768")
        other_public, _ = basefwx.generate_kem_keypair("ml-kem-768")
        codecs = (
            (basefwx.b512file_encode_bytes, basefwx.b512file_decode_bytes),
            (basefwx.pb512file_encode_bytes, basefwx.pb512file_decode_bytes),
        )
        with self.recipient_test_environment():
            for encode, decode in codecs:
                with self.subTest(codec=encode.__name__), patch.object(
                    basefwx, "_load_master_pq_public", side_effect=[public_key, other_public, other_public]
                ) as load_public:
                    encoded = encode(b"payload", ".bin", self.PASSWORD, use_master=True)
                self.assertEqual(load_public.call_count, 1)
                with patch.object(basefwx, "_load_master_pq_private", return_value=private_key):
                    self.assertEqual(decode(encoded, b"wrong-password", use_master=True), (b"payload", ".bin"))
                self.assertEqual(decode(encoded, self.PASSWORD, use_master=False), (b"payload", ".bin"))

    def test_legacy_b512_stream_requires_authenticated_password_before_publication(self):
        private_key = basefwx.ec.generate_private_key(basefwx.ec.SECP521R1())
        selection = _master_key.MasterKeySelection(None, private_key.public_key(), "EC")
        payload = b"legacy streaming data"
        with self.recipient_test_environment(), self.policy_environment(BASEFWX_PQ_STRICT=""), patch.object(
            basefwx, "_load_master_ec_private", return_value=private_key
        ), patch.object(basefwx, "_load_master_pq_private", return_value=None), tempfile.TemporaryDirectory() as directory:
            metadata = basefwx._build_metadata("FWX512R", False, True, master_kem="EC",
                                               aead="AESGCM", kdf="pbkdf2", mode="STREAM", obfuscation="fast").encode()
            mask, user, master, _ = basefwx._prepare_mask_key(
                self.PASSWORD, True, mask_info=basefwx.B512_FILE_MASK_INFO,
                require_password=True, aad=basefwx.MASK_AAD_B512FILE, master_selection=selection)
            salt = bytes(range(16))
            header = (basefwx.STREAM_MAGIC + (1024).to_bytes(4, "big") + len(payload).to_bytes(8, "big")
                      + salt + (4).to_bytes(2, "big") + b".bin")
            obfuscated = basefwx._StreamObfuscator.for_password(self.PASSWORD, salt, fast=True).encode_chunk(payload)
            plaintext = metadata + basefwx.META_DELIM.encode() + header + obfuscated
            aead_key = basefwx._hkdf_sha256(mask, info=basefwx.B512_AEAD_INFO)
            encrypted = basefwx._aead_encrypt(aead_key, plaintext, metadata)
            envelope = len(metadata).to_bytes(4, "big") + metadata + encrypted
            encoded = basefwx._pack_length_prefixed(user, master, envelope)
            ciphertext = Path(directory) / "legacy.fwx"
            destination = ciphertext.with_suffix(".bin")
            destination.write_bytes(b"prior output")
            for bad_password in (b"", b"wrong-password"):
                with self.subTest(password_present=bool(bad_password)):
                    ciphertext.write_bytes(encoded)
                    self.assertEqual(basefwx.b512file(ciphertext, bad_password, use_master=True, silent=True), "FAIL!")
                    self.assertEqual(ciphertext.read_bytes(), encoded)
                    self.assertEqual(destination.read_bytes(), b"prior output")
            # A valid but unrelated user wrap must not authenticate this stream's password.
            _, other_user, _, _ = basefwx._prepare_mask_key(
                b"wrong-password", False, mask_info=basefwx.B512_FILE_MASK_INFO,
                require_password=True, aad=basefwx.MASK_AAD_B512FILE)
            for invalid_user in (b"", other_user):
                ciphertext.write_bytes(basefwx._pack_length_prefixed(invalid_user, master, envelope))
                self.assertEqual(basefwx.b512file(ciphertext, b"wrong-password", use_master=True, silent=True), "FAIL!")
                self.assertEqual(destination.read_bytes(), b"prior output")
            for use_master in (False, True):
                ciphertext.write_bytes(encoded)
                self.assertEqual(basefwx.b512file(ciphertext, self.PASSWORD, use_master=use_master, silent=True), "SUCCESS!")
                self.assertEqual(destination.read_bytes(), payload)
                self.assertFalse(ciphertext.exists())

    def test_b512_stream_v2_key_domain_vector(self):
        key = basefwx._hkdf_sha256(bytes(range(32)), info=basefwx.B512_STREAM_OBF_INFO, length=32)
        self.assertEqual(key.hex(), "f53aec8167a000ca3ae3d2e001444946f141697a01f07526f2d476d6afd76f04")

    def test_public_file_writer_key_failure_preserves_files(self):
        status_writers = (
            lambda path: basefwx.b512file_encode(path, self.PASSWORD),
            lambda path: basefwx.b512file(path, self.PASSWORD, silent=True),
            lambda path: basefwx.AESfile(path, self.PASSWORD, silent=True),
            lambda path: basefwx.AESfile(path, self.PASSWORD, light=False, silent=True),
        )
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), patch.object(
            basefwx, "_SILENT_MODE", True
        ):
            source = Path(directory) / "input.bin"
            destination = source.with_suffix(".fwx")
            source.write_bytes(b"source")
            destination.write_bytes(b"existing")
            for strict, ec_key in (("", None), ("1", None), ("", object())):
                with self.subTest(strict=strict, wrapping=ec_key is not None), self.policy_environment(
                    BASEFWX_PQ_STRICT=strict
                ), patch.object(basefwx, "_load_master_pq_public", return_value=None), patch.object(
                    basefwx, "_load_master_ec_public", return_value=ec_key
                ), patch.object(basefwx, "_ec_kem_enc", side_effect=ValueError("injected master wrap failure")):
                    for index, writer in enumerate(status_writers):
                        with self.subTest(writer=index):
                            self.assertEqual(writer(source), "FAIL!")
                            self.assertEqual(source.read_bytes(), b"source")
                            self.assertEqual(destination.read_bytes(), b"existing")
                    for heavy in (False, True):
                        with self.subTest(fwxAES_heavy=heavy), self.assertRaisesRegex(ValueError, "master"):
                            basefwx.fwxAES_file(source, self.PASSWORD, use_master=True, heavy=heavy)
                        self.assertEqual(source.read_bytes(), b"source")
                        self.assertEqual(destination.read_bytes(), b"existing")

    def test_mixed_file_batches_keep_decode_independent_of_writer_policy(self):
        operations = (
            lambda paths, master, silent: basefwx.b512file(paths, self.PASSWORD, use_master=master, silent=silent),
            lambda paths, master, silent: basefwx.AESfile(paths, self.PASSWORD, use_master=master, silent=silent),
            lambda paths, master, silent: basefwx.AESfile(paths, self.PASSWORD, light=False, use_master=master, silent=silent),
        )
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()), patch.object(
            basefwx, "_CPU_COUNT", 2
        ):
            root = Path(directory)
            plaintext = root / "decode.bin"
            ciphertext = plaintext.with_suffix(".fwx")
            new_input = root / "encode.bin"
            prior_output = new_input.with_suffix(".fwx")
            new_input.write_bytes(b"new input")
            prior_output.write_bytes(b"prior output")
            for index, operation in enumerate(operations):
                for silent in (False, True):
                    with self.subTest(operation=index, silent=silent):
                        plaintext.write_bytes(b"independent password recovery")
                        self.assertEqual(operation(plaintext, False, True), "SUCCESS!")
                        with self.policy_environment(BASEFWX_PQ_STRICT="1"), patch.object(
                            basefwx, "_load_master_pq_public", return_value=None
                        ), patch.object(basefwx, "_load_master_ec_public", return_value=None):
                            result = operation([ciphertext, new_input], True, silent)
                        self.assertEqual(result, {str(ciphertext): "SUCCESS!", str(new_input): "FAIL!"})
                        self.assertEqual(plaintext.read_bytes(), b"independent password recovery")
                        self.assertFalse(ciphertext.exists())
                        self.assertEqual(new_input.read_bytes(), b"new input")
                        self.assertEqual(prior_output.read_bytes(), b"prior output")

    def test_master_key_loading_failure_falls_back_to_correct_password(self):
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
