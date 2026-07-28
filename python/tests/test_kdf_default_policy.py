# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Import-time regressions for fail-closed user-KDF selection."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class KdfDefaultPolicyTests(unittest.TestCase):
    def test_low_ram_probe_does_not_downgrade_argon2_default(self) -> None:
        python_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            shadow_root = Path(temp_dir)
            (shadow_root / "psutil.py").write_text(
                textwrap.dedent(
                    """\
                    class _Memory:
                        available = 1

                    def virtual_memory():
                        return _Memory()
                    """
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("BASEFWX_USER_KDF", None)
            env["PYTHONPATH"] = os.pathsep.join(
                (str(shadow_root), str(python_root))
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from basefwx.main import basefwx; "
                        "assert basefwx._check_ram_for_argon2() is False; "
                        "print(int(basefwx._ARGON2_AVAILABLE), "
                        "basefwx.USER_KDF_DEFAULT)"
                    ),
                ],
                cwd=str(python_root.parent),
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        available, default = result.stdout.strip().split()
        expected = "argon2id" if available == "1" else "pbkdf2"
        self.assertEqual(default, expected)

    def test_missing_argon_uses_full_pbkdf2_writer_cost(self) -> None:
        python_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            shadow_root = Path(temp_dir)
            argon_package = shadow_root / "argon2"
            argon_package.mkdir()
            (argon_package / "__init__.py").write_text(
                "",
                encoding="utf-8",
            )
            (argon_package / "low_level.py").write_text(
                "raise ImportError('simulated unavailable Argon2 backend')\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("BASEFWX_USER_KDF", None)
            env.pop("BASEFWX_USER_KDF_ITERS", None)
            env["PYTHONPATH"] = os.pathsep.join(
                (str(shadow_root), str(python_root))
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from basefwx.main import basefwx; "
                        "print(int(basefwx._ARGON2_AVAILABLE), "
                        "basefwx.USER_KDF_DEFAULT, "
                        "basefwx.USER_KDF_ITERATIONS)"
                    ),
                ],
                cwd=str(python_root.parent),
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

        available, default, iterations = result.stdout.strip().split()
        self.assertEqual("0", available)
        self.assertEqual("pbkdf2", default)
        self.assertEqual("600000", iterations)


if __name__ == "__main__":
    unittest.main()
