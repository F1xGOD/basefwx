import io
import os
import site
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from basefwx.main import basefwx

MASTER_PQ_SECRET_B64 = (
    "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"
)


class BaseFWXTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)
        self.user_site = site.getusersitepackages()
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.tmp_path)
        (self.tmp_path / "master_pq.sk").write_text(MASTER_PQ_SECRET_B64, encoding="utf-8")
        self.repo_root = Path(__file__).resolve().parent

    def tearDown(self) -> None:
        if self.old_home is not None:
            os.environ["HOME"] = self.old_home
        else:
            os.environ.pop("HOME", None)
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
        blob = basefwx.encryptAES(original, "", use_master=True)
        recovered = basefwx.decryptAES(blob, "", use_master=True)
        self.assertEqual(recovered, original)

    def test_b512file_cycle(self):
        src = self.tmp_path / "note.txt"
        src.write_text("classified", encoding="utf-8")

        result = basefwx.b512file(str(src), "pw", strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")

        encoded = self.tmp_path / "note.fwx"
        self.assertTrue(encoded.exists())

        result = basefwx.b512file(str(encoded), "pw", strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")

        restored = self.tmp_path / "note.txt"
        self.assertTrue(restored.exists())
        self.assertEqual(restored.read_text(encoding="utf-8"), "classified")

    def test_aesfile_cycle_light(self):
        src = self.tmp_path / "data.bin"
        src.write_bytes(b"FWX\x00PQ")

        result = basefwx.AESfile(str(src), "pw", light=True, strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")

        encoded = self.tmp_path / "data.fwx"
        self.assertTrue(encoded.exists())

        result = basefwx.AESfile(str(encoded), "pw", light=True, strip_metadata=True, use_master=False)
        self.assertEqual(result, "SUCCESS!")

        restored = self.tmp_path / "data.bin"
        self.assertEqual(restored.read_bytes(), b"FWX\x00PQ")

    def test_metadata_hint_message(self):
        meta = {"ENC-METHOD": "FWX512R", "ENC-VERSION": "2.9.0"}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            basefwx._warn_on_metadata(meta, "AES-LIGHT")
        output = buffer.getvalue().strip()
        self.assertIn("Did you mean", output)
        self.assertIn("FWX512R", output)
        self.assertIn("2.9.0", output)

    def test_cli_aes_master(self):
        src = self.tmp_path / "cli.txt"
        src.write_text("cli-power", encoding="utf-8")

        result = self._run_cli("cryptin", "aes", str(src))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)

        encoded = self.tmp_path / "cli.fwx"
        self.assertTrue(encoded.exists())

        result = self._run_cli("cryptin", "aes", str(encoded))
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(src.read_text(encoding="utf-8"), "cli-power")

    def test_cli_b512_strip(self):
        src = self.tmp_path / "reversible.md"
        src.write_text("### reversible", encoding="utf-8")

        result = self._run_cli("cryptin", "512", str(src), "-p", "pw", "--strip")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)

        encoded = self.tmp_path / "reversible.fwx"
        self.assertTrue(encoded.exists())

        result = self._run_cli("cryptin", "512", str(encoded), "-p", "pw", "--strip")
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        self.assertEqual(src.read_text(encoding="utf-8"), "### reversible")


if __name__ == "__main__":
    unittest.main()
