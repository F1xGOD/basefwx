# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused primitive validation and fast-path parity regressions."""

from __future__ import annotations

import base64
import unittest
from unittest import mock

from basefwx.crypto import _primitives


class CryptoApiSafetyTests(unittest.TestCase):
    def test_argon2_ram_gate_uses_central_available_memory_probe(self):
        cases = ((None, True), (127.9, False), (128.0, True))
        for available_mib, expected in cases:
            with self.subTest(available_mib=available_mib), mock.patch.object(
                _primitives,
                "_get_available_ram_mib",
                return_value=available_mib,
            ):
                self.assertEqual(
                    _primitives._check_ram_for_argon2(),
                    expected,
                )

    def test_hkdf_sha256_enforces_rfc_output_limit(self):
        maximum = 255 * 32
        self.assertEqual(
            len(_primitives._hkdf_sha256(b"key", length=maximum)),
            maximum,
        )
        with self.assertRaisesRegex(ValueError, "RFC 5869"):
            _primitives._hkdf_sha256(b"key", length=maximum + 1)

    def test_aead_helpers_require_aes_256_and_complete_framing(self):
        with self.assertRaisesRegex(ValueError, "32-byte key"):
            _primitives._aead_encrypt(b"k" * 16, b"plaintext", b"aad")
        with self.assertRaisesRegex(ValueError, "32-byte key"):
            _primitives._aead_decrypt(b"k" * 24, b"x" * 28, b"aad")
        with self.assertRaisesRegex(ValueError, "too short"):
            _primitives._aead_decrypt(b"k" * 32, b"x" * 27, b"aad")

    @unittest.skipIf(_primitives.np is None, "NumPy fast path unavailable")
    def test_fast_base32hex_decoder_rejects_non_alphabet_input(self):
        encoded = base64.b32hexencode(b"A" * 1024)
        self.assertEqual(len(_primitives._B32HEX_DECODE_LUT), 256)
        for invalid in (b"]", b"`", b"W", b"w"):
            with self.subTest(invalid=invalid):
                malformed = invalid + encoded[1:]
                with self.assertRaises(ValueError):
                    _primitives._fast_b32hexdecode(malformed)

    @unittest.skipIf(_primitives.np is None, "NumPy fast path unavailable")
    def test_fast_base32hex_decoder_matches_stdlib(self):
        plaintext = bytes(range(256)) * 8
        encoded = base64.b32hexencode(plaintext)
        self.assertEqual(
            _primitives._fast_b32hexdecode(encoded),
            plaintext,
        )
        lowercase = encoded.lower()
        self.assertEqual(
            _primitives._fast_b32hexdecode(lowercase),
            base64.b32hexdecode(lowercase, casefold=True),
        )


if __name__ == "__main__":
    unittest.main()
