# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Authentication-before-publication regressions for fwxAES streams."""

from __future__ import annotations

import io
import unittest

from basefwx.main import basefwx


class FwxAesAuthenticationPublicationTests(unittest.TestCase):
    def test_bad_tag_writes_no_plaintext_to_destination(self) -> None:
        password = "stream-auth-test-password"
        plaintext = bytes(
            (i * 31 + 7) & 0xFF
            for i in range(3 * 1024 * 1024 + 29)
        )
        encrypted = io.BytesIO()
        basefwx.fwxAES_encrypt_stream(
            io.BytesIO(plaintext),
            encrypted,
            password,
            use_master=False,
        )
        tampered = bytearray(encrypted.getvalue())
        tampered[-1] ^= 1
        sentinel = b"existing authenticated stream destination"
        destination = io.BytesIO(sentinel)
        destination.seek(0, io.SEEK_END)

        with self.assertRaisesRegex(ValueError, "auth failed"):
            basefwx.fwxAES_decrypt_stream(
                io.BytesIO(tampered),
                destination,
                password,
                use_master=False,
            )

        self.assertEqual(destination.getvalue(), sentinel)


if __name__ == "__main__":
    unittest.main()
