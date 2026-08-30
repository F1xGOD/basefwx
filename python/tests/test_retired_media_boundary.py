# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Structural checks for the default-off retired media boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


PYTHON_ROOT = Path(__file__).resolve().parent.parent
RETIRED_ENV = "BASEFWX_ENABLE_RETIRED_MEDIA"


def _probe(*, enabled: bool) -> dict[str, object]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(PYTHON_ROOT), env.get("PYTHONPATH")])
    )
    if enabled:
        env[RETIRED_ENV] = "1"
    else:
        env.pop(RETIRED_ENV, None)
    script = """
import json
import sys
import basefwx

print(json.dumps({
    "enabled": basefwx.HAS_RETIRED_MEDIA,
    "public_b256": hasattr(basefwx, "b256encode"),
    "public_kfme": hasattr(basefwx, "kFMe"),
    "engine_b256": hasattr(basefwx.basefwx, "b256encode"),
    "engine_kfme": hasattr(basefwx.basefwx, "kFMe"),
    "engine_media": hasattr(basefwx.basefwx, "MediaCipher"),
    "pillow_loaded": "PIL" in sys.modules,
    "retired_modules": sorted(
        name for name in sys.modules if name.startswith("basefwx.retired")
    ),
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PYTHON_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


class RetiredMediaBoundaryTests(unittest.TestCase):
    def test_default_import_excludes_retired_media(self) -> None:
        state = _probe(enabled=False)
        self.assertFalse(state["enabled"])
        self.assertFalse(state["public_b256"])
        self.assertFalse(state["public_kfme"])
        self.assertFalse(state["engine_b256"])
        self.assertFalse(state["engine_kfme"])
        self.assertFalse(state["engine_media"])
        self.assertFalse(state["pillow_loaded"])
        self.assertEqual(state["retired_modules"], [])

    def test_explicit_compatibility_import_installs_retired_media(self) -> None:
        state = _probe(enabled=True)
        self.assertTrue(state["enabled"])
        self.assertTrue(state["public_b256"])
        self.assertTrue(state["public_kfme"])
        self.assertTrue(state["engine_b256"])
        self.assertTrue(state["engine_kfme"])
        self.assertTrue(state["engine_media"])
        self.assertTrue(state["retired_modules"])

    def test_active_source_tree_has_no_retired_implementation_modules(self) -> None:
        package = PYTHON_ROOT / "basefwx"
        for relative in (
            "api_media.py",
            "crypto/_jmg.py",
            "crypto/_kfm.py",
            "media",
        ):
            self.assertFalse((package / relative).exists(), relative)
        self.assertTrue((package / "retired/media/_jmg.py").is_file())
        self.assertTrue((package / "retired/media/_kfm.py").is_file())
        self.assertTrue((package / "retired/codecs.py").is_file())
        self.assertNotIn(
            "def uhash513",
            (package / "crypto/_primitives.py").read_text(encoding="utf-8"),
        )
        active_codecs = (package / "crypto/_codecs_str.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("def b256encode", active_codecs)
        self.assertNotIn("def a512encode", active_codecs)
