# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Authentication-before-publication regressions for media trailers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from basefwx.main import basefwx


class MediaAuthenticationPublicationTests(unittest.TestCase):
    def test_inner_jmg_length_rejected_before_allocation_or_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            carrier = root / "hostile-jmg.bin"
            destination = root / "destination.bin"
            sentinel = b"existing authenticated destination"
            destination.write_bytes(sentinel)

            blob = (
                basefwx.JMG_KEY_MAGIC
                + bytes([basefwx.JMG_KEY_VERSION])
                + (0x7FFFFFFF).to_bytes(4, "big")
            )
            magic = basefwx.IMAGECIPHER_TRAILER_MAGIC
            length = len(blob).to_bytes(4, "big")
            carrier.write_bytes(
                b"carrier" + magic + length + blob + magic + length
            )
            before = sorted(path.name for path in root.iterdir())

            with self.assertRaisesRegex(
                ValueError,
                "Invalid JMG key header length",
            ):
                basefwx.MediaCipher._decrypt_trailer_stream(
                    carrier,
                    "media-trailer-test-password",
                    destination,
                )

            self.assertEqual(destination.read_bytes(), sentinel)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                before,
            )

    def test_bad_tag_preserves_destination_and_leaks_no_temp(self) -> None:
        password = "media-trailer-test-password"
        material = b"\x5a" * 32
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            carrier = root / "carrier.bin"
            original = root / "original.bin"
            destination = root / "destination.bin"
            carrier.write_bytes(b"carrier")
            original.write_bytes(
                bytes((i * 17 + 29) & 0xFF for i in range(
                    3 * 1024 * 1024 + 37
                ))
            )
            sentinel = b"existing authenticated destination"
            destination.write_bytes(sentinel)

            with patch.object(
                basefwx.MediaCipher,
                "_derive_media_material",
                return_value=material,
            ):
                basefwx.MediaCipher._append_trailer_stream(
                    carrier, password, original
                )
                footer_len = (
                    len(basefwx.IMAGECIPHER_TRAILER_MAGIC) + 4
                )
                with carrier.open("r+b") as handle:
                    handle.seek(-footer_len - 1, 2)
                    value = handle.read(1)
                    handle.seek(-1, 1)
                    handle.write(bytes([value[0] ^ 1]))
                before = sorted(path.name for path in root.iterdir())

                restored = (
                    basefwx.MediaCipher._decrypt_trailer_stream(
                        carrier, password, destination
                    )
                )

            self.assertFalse(restored)
            self.assertEqual(destination.read_bytes(), sentinel)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                before,
            )


if __name__ == "__main__":
    unittest.main()
