import collections
import io
import math
import os
import site
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
from pqcrypto.kem import ml_kem_768

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
        self.assertEqual(len(h512), 64)
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

    def test_aes_roundtrip_without_master(self):
        original = "Symmetric data"
        blob = basefwx.encryptAES(original, "pw", use_master=False)
        recovered = basefwx.decryptAES(blob, "pw", use_master=False)
        self.assertEqual(recovered, original)

    def test_aes_roundtrip_with_master(self):
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
        for i in range(iterations):
            metadata = basefwx._build_metadata("NONCE", False, False)
            plaintext = f"{metadata}{basefwx.META_DELIM}nonce-{i}"
            blob = basefwx.encryptAES(plaintext, password, use_master=False, metadata_blob=metadata)
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
