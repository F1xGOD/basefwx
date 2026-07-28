# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Focused regressions for peer-controlled PBKDF2 work-factor limits."""

from __future__ import annotations

import io
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from basefwx.main import basefwx
from basefwx.crypto import _aes_file
from basefwx.crypto import _fwxaes
from basefwx.file import _b512_obfuscation as length_format
from basefwx.file import _b512_stream


class PeerPbkdf2PolicyTests(unittest.TestCase):
    @staticmethod
    def metadata_with(field: str, value: str, mode: str | None = None) -> str:
        info = {
            "ENC-METHOD": "AES-HEAVY",
            "ENC-MASTER": "no",
            "ENC-KEM": "none",
            "ENC-AEAD": "AESGCM",
            "ENC-KDF": "argon2id",
            field: value,
        }
        if mode is not None:
            info["ENC-MODE"] = mode
        return base64.b64encode(
            json.dumps(info, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    @staticmethod
    def write_sparse_length_prefixed_container(
        path: Path, total_size: int, metadata: str
    ) -> None:
        metadata_bytes = metadata.encode("utf-8")
        payload_len = total_size - 12
        if payload_len < 4 + len(metadata_bytes):
            raise ValueError("test container is too small for metadata")
        with path.open("wb") as handle:
            handle.write((0).to_bytes(4, "big"))
            handle.write((0).to_bytes(4, "big"))
            handle.write(payload_len.to_bytes(4, "big"))
            handle.write(len(metadata_bytes).to_bytes(4, "big"))
            handle.write(metadata_bytes)
            handle.truncate(total_size)

    @staticmethod
    def write_stream_container(
        path: Path,
        user_len: int,
        master_len: int,
        metadata: str,
    ) -> None:
        metadata_bytes = metadata.encode("utf-8")
        payload = (
            len(metadata_bytes).to_bytes(4, "big")
            + metadata_bytes
            + b"\x00"
            * (basefwx.AEAD_NONCE_LEN + basefwx.AEAD_TAG_LEN)
        )
        path.write_bytes(
            user_len.to_bytes(4, "big")
            + b"\x11" * user_len
            + master_len.to_bytes(4, "big")
            + b"\x22" * master_len
            + len(payload).to_bytes(4, "big")
            + payload
        )

    def test_exact_maximum_is_accepted_and_metadata_is_strict(self):
        maximum = basefwx.PEER_PBKDF2_ITERATIONS_MAX
        basefwx._require_peer_pbkdf2_within_limits(maximum)
        self.assertEqual(
            maximum,
            basefwx._parse_peer_pbkdf2_iterations(
                str(maximum), basefwx.USER_KDF_ITERATIONS
            ),
        )

        for value in (
            "0",
            "01",
            "-1",
            "4000000x",
            "4000000 ",
            "4000001",
            "2147483648",
            "4294967296",
            "999999999999999999999999",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Peer"):
                    basefwx._parse_peer_pbkdf2_iterations(
                        value, basefwx.USER_KDF_ITERATIONS
                    )

    def test_wire_kdf_labels_and_ec_frames_are_exact(self):
        for label in ("pbkdf2", "argon2", "argon2id"):
            expected = "argon2id" if label == "argon2" else label
            self.assertEqual(
                expected, basefwx._resolve_kdf_label(label, peer=True)
            )
        for label in ("", "auto", "argon2evil", "PBKDF2", " pbkdf2"):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "peer KDF"):
                    basefwx._resolve_kdf_label(label, peer=True)

        valid = (
            basefwx.MASTER_EC_MAGIC
            + (133).to_bytes(2, "big")
            + b"\x04"
            + b"\x00" * 132
        )
        self.assertTrue(basefwx._is_ec_master_blob(valid))
        self.assertFalse(basefwx._is_ec_master_blob(valid + b"\x00"))
        collision = bytearray(1088)
        collision[:3] = basefwx.MASTER_EC_MAGIC
        self.assertFalse(basefwx._is_ec_master_blob(bytes(collision)))

    def test_unknown_producer_kdf_and_oversized_metadata_fail_before_crypto(self):
        with patch.object(basefwx, "USER_KDF", "argon2evil"), patch.object(
            basefwx, "_select_master_key"
        ) as select_master:
            with self.assertRaisesRegex(ValueError, "Unsupported KDF"):
                basefwx.encryptAES(
                    "payload", b"", use_master=True, kdf="argon2evil"
                )
            select_master.assert_not_called()

    def test_encrypt_requires_a_real_recovery_transport_before_crypto(self):
        no_master = Mock(
            pq_public=None,
            ec_public=None,
            used_master=False,
        )
        with patch.object(
            basefwx, "_select_master_key", return_value=no_master
        ) as select_master, patch.object(
            basefwx, "_kem_encrypt"
        ) as kem_encrypt, patch.object(
            basefwx, "_ec_kem_enc"
        ) as ec_encrypt, patch.object(
            basefwx.os, "urandom"
        ) as random_bytes, patch.object(
            basefwx, "Cipher"
        ) as cipher:
            with self.assertRaisesRegex(
                ValueError, "Password required.*master key"
            ):
                basefwx.encryptAES(
                    "payload", b"", use_master=True, kdf="pbkdf2"
                )
            select_master.assert_called_once()
            kem_encrypt.assert_not_called()
            ec_encrypt.assert_not_called()
            random_bytes.assert_not_called()
            cipher.assert_not_called()

    def test_encrypt_length_cap_rejects_early_and_checked_pack_is_exact(self):
        with patch.object(
            basefwx, "LENGTH_PREFIXED_MAX", 44
        ), patch.object(basefwx, "_select_master_key") as select_master:
            with self.assertRaisesRegex(ValueError, "64 MiB total cap"):
                basefwx.encryptAES(
                    "x", b"", use_master=True, kdf="pbkdf2"
                )
            select_master.assert_not_called()

        with patch.object(length_format, "LENGTH_PREFIXED_MAX", 16):
            self.assertEqual(
                16,
                len(basefwx._pack_length_prefixed(b"", b"", b"1234")),
            )
            with self.assertRaisesRegex(ValueError, "64 MiB total cap"):
                basefwx._pack_length_prefixed(b"", b"", b"12345")

        with patch.object(
            basefwx, "LENGTH_PREFIXED_MAX", 80
        ), patch.object(
            length_format, "LENGTH_PREFIXED_MAX", 80
        ), patch.object(
            basefwx,
            "_derive_user_key",
            return_value=(b"\x01" * 32, b"\x02" * 16),
        ):
            with self.assertRaisesRegex(ValueError, "64 MiB total cap"):
                basefwx.encryptAES(
                    "x",
                    "correct-password",
                    use_master=False,
                    kdf="pbkdf2",
                    kdf_iterations=1,
                    obfuscate=False,
                )

        with patch.object(basefwx, "_select_master_key") as select_master:
            with self.assertRaisesRegex(ValueError, "metadata exceeds"):
                basefwx.encryptAES(
                    "payload",
                    b"",
                    use_master=True,
                    metadata_blob="x" * (basefwx.METADATA_MAX + 1),
                    kdf="pbkdf2",
                )
            select_master.assert_not_called()

    def test_public_file_decoders_cap_before_read_and_keep_stream_dispatch(self):
        cap = 512
        nonstream_metadata = self.metadata_with(
            "ENC-KDF-ITER", "1"
        )
        stream_metadata = self.metadata_with(
            "ENC-KDF-ITER", "1", mode="STREAM"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            aes_nonstream = root / "aes-nonstream.fwx"
            b512_nonstream = root / "b512-nonstream.fwx"
            aes_stream = root / "aes-stream.fwx"
            b512_stream = root / "b512-stream.fwx"
            for candidate, metadata in (
                (aes_nonstream, nonstream_metadata),
                (b512_nonstream, nonstream_metadata),
                (aes_stream, stream_metadata),
                (b512_stream, stream_metadata),
            ):
                self.write_sparse_length_prefixed_container(
                    candidate, cap + 1, metadata
                )

            with patch.object(basefwx, "LENGTH_PREFIXED_MAX", cap), patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("oversized input was allocated"),
            ):
                with self.assertRaisesRegex(ValueError, "Non-stream"):
                    basefwx._aes_heavy_decode_path(
                        aes_nonstream, "correct-password", use_master=False
                    )
                with self.assertRaisesRegex(ValueError, "Non-stream"):
                    basefwx._b512_decode_path(
                        b512_nonstream, "correct-password", use_master=False
                    )

                with patch.object(
                    basefwx,
                    "_aes_heavy_decode_path_stream",
                    return_value=(aes_stream, 1),
                ) as aes_dispatch:
                    self.assertEqual(
                        (aes_stream, 1),
                        basefwx._aes_heavy_decode_path(
                            aes_stream,
                            "correct-password",
                            use_master=False,
                        ),
                    )
                    aes_dispatch.assert_called_once()

                with patch.object(
                    basefwx,
                    "_b512_decode_path_stream",
                    return_value=(b512_stream, 1),
                ) as b512_dispatch:
                    self.assertEqual(
                        (b512_stream, 1),
                        basefwx._b512_decode_path(
                            b512_stream,
                            "correct-password",
                            use_master=False,
                        ),
                    )
                    b512_dispatch.assert_called_once()

            encrypted_nonstream = root / "encrypted-nonstream.fwx"
            ct_blob = (
                (basefwx.METADATA_MAX + 1).to_bytes(4, "big")
                + b"\xa5" * 28
            )
            binary_blob = basefwx._pack_length_prefixed(
                b"", b"", ct_blob
            )
            encrypted_nonstream.write_bytes(binary_blob)
            self.assertEqual(
                ("", {}),
                _b512_stream._preview_b512_length_prefixed_container(
                    encrypted_nonstream, len(binary_blob)
                ),
            )
            decoded_payload = b"binary-preview-regression"
            content = (
                "extension-token"
                + basefwx.FWX_DELIM
                + "payload-token"
            ).encode("utf-8")
            with patch.object(
                basefwx,
                "_recover_mask_key_from_blob",
                return_value=b"\x01" * 32,
            ), patch.object(
                basefwx, "_hkdf_sha256", return_value=b"\x02" * 32
            ), patch.object(
                basefwx, "_aead_decrypt", return_value=content
            ) as aead_decrypt, patch.object(
                basefwx,
                "b512decode",
                side_effect=[
                    ".bin",
                    base64.b64encode(decoded_payload).decode("ascii"),
                ],
            ):
                decoded_path, decoded_len = basefwx._b512_decode_path(
                    encrypted_nonstream,
                    "correct-password",
                    use_master=False,
                )
            aead_decrypt.assert_called_once()
            self.assertEqual(len(decoded_payload), decoded_len)
            self.assertEqual(decoded_payload, decoded_path.read_bytes())

            legacy = root / "legacy.b512"
            legacy_bytes = b"ordinary legacy text"
            legacy.write_bytes(legacy_bytes)
            with patch.object(
                Path, "read_bytes", return_value=legacy_bytes
            ) as read_bytes:
                with self.assertRaises(ValueError):
                    basefwx._b512_decode_path(
                        legacy, "correct-password", use_master=False
                    )
                read_bytes.assert_called_once()

    def test_aes_light_zlib_input_and_output_are_bounded(self):
        cap = 64
        with patch.object(basefwx, "LENGTH_PREFIXED_MAX", cap):
            valid = basefwx.zlib.compress(b"x" * cap)
            self.assertEqual(
                b"x" * cap,
                _aes_file._decompress_aes_light_payload(valid, cap),
            )
            with self.assertRaisesRegex(ValueError, "exceeds 64 MiB"):
                _aes_file._decompress_aes_light_payload(
                    basefwx.zlib.compress(b"x" * (cap + 1)), cap
                )
            with self.assertRaisesRegex(ValueError, "truncated"):
                _aes_file._decompress_aes_light_payload(valid[:-1], cap)
            with self.assertRaisesRegex(ValueError, "trailing data"):
                _aes_file._decompress_aes_light_payload(
                    valid + b"trailing", cap
                )

            compressed_limit = _aes_file._zlib_compress_bound(cap)
            with tempfile.TemporaryDirectory() as temp_dir:
                sparse = Path(temp_dir) / "oversized-light.fwx"
                with sparse.open("wb") as handle:
                    handle.truncate(compressed_limit + 1)
                with patch.object(
                    Path,
                    "read_bytes",
                    side_effect=AssertionError(
                        "oversized compressed input was allocated"
                    ),
                ), patch.object(
                    basefwx.zlib, "decompressobj"
                ) as decompressobj:
                    with self.assertRaisesRegex(
                        ValueError, "maximum valid input size"
                    ):
                        basefwx._aes_light_decode_path(
                            sparse,
                            "correct-password",
                            use_master=False,
                        )
                    decompressobj.assert_not_called()

    def test_stream_header_aggregate_caps_precede_dispatch_and_crypto(self):
        stream_metadata = self.metadata_with(
            "ENC-KDF-ITER", "1", mode="STREAM"
        )
        metadata_len = len(stream_metadata.encode("utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            key_aggregate = root / "key-aggregate.fwx"
            metadata_aggregate = root / "metadata-aggregate.fwx"
            self.write_stream_container(
                key_aggregate, 9, 8, stream_metadata
            )
            self.write_stream_container(
                metadata_aggregate, 5, 4, stream_metadata
            )

            with patch.object(
                basefwx, "_aes_heavy_decode_path_stream"
            ) as aes_dispatch, patch.object(
                basefwx, "_b512_decode_path_stream"
            ) as b512_dispatch, patch.object(
                basefwx, "_recover_mask_key_from_blob"
            ) as recover_key, patch.object(
                basefwx, "Cipher"
            ) as cipher:
                with patch.object(
                    basefwx, "LENGTH_PREFIXED_MAX", 16
                ):
                    for decoder in (
                        basefwx._aes_heavy_decode_path,
                        basefwx._b512_decode_path,
                        _aes_file._aes_heavy_decode_path_stream,
                        _b512_stream._b512_decode_path_stream,
                    ):
                        with self.subTest(
                            decoder=decoder.__name__,
                            aggregate="key-transport",
                        ):
                            with self.assertRaisesRegex(
                                ValueError, "key transport header"
                            ):
                                decoder(
                                    key_aggregate,
                                    "correct-password",
                                    use_master=False,
                                )

                metadata_cap = metadata_len + 8
                with patch.object(
                    basefwx,
                    "LENGTH_PREFIXED_MAX",
                    metadata_cap,
                ):
                    for decoder in (
                        basefwx._aes_heavy_decode_path,
                        basefwx._b512_decode_path,
                        _aes_file._aes_heavy_decode_path_stream,
                        _b512_stream._b512_decode_path_stream,
                    ):
                        with self.subTest(
                            decoder=decoder.__name__,
                            aggregate="metadata",
                        ):
                            with self.assertRaisesRegex(
                                ValueError, "Ciphertext header"
                            ):
                                decoder(
                                    metadata_aggregate,
                                    "correct-password",
                                    use_master=False,
                                )

                aes_dispatch.assert_not_called()
                b512_dispatch.assert_not_called()
                recover_key.assert_not_called()
                cipher.assert_not_called()

    def test_fwxaes_wrap_header_cap_precedes_reads_and_crypto(self):
        maximum = basefwx.FWXAES_MAX_KEY_HEADER_LEN

        def wrap_header(header_len: int) -> bytes:
            return basefwx.struct.pack(
                ">4sBBBBII",
                basefwx.FWXAES_MAGIC,
                basefwx.FWXAES_ALGO,
                basefwx.FWXAES_KDF_WRAP,
                0,
                basefwx.FWXAES_IV_LEN,
                header_len,
                basefwx.AEAD_TAG_LEN,
            )

        class TrackingBytesIO(io.BytesIO):
            def __init__(self, initial: bytes):
                super().__init__(initial)
                self.read_sizes: list[int] = []

            def read(self, size: int = -1) -> bytes:
                self.read_sizes.append(size)
                return super().read(size)

        oversized = wrap_header(maximum + 1)
        source = TrackingBytesIO(oversized)
        with patch.object(
            basefwx, "_recover_mask_key_from_blob"
        ) as recover_key, patch.object(
            basefwx, "_hkdf_sha256"
        ) as hkdf:
            with self.assertRaisesRegex(
                ValueError, "fwxAES key header too large"
            ):
                basefwx.fwxAES_decrypt_stream(
                    source,
                    io.BytesIO(),
                    "correct-password",
                    use_master=True,
                )
            with self.assertRaisesRegex(
                ValueError, "fwxAES key header too large"
            ):
                basefwx.fwxAES_decrypt_raw(
                    oversized,
                    "correct-password",
                    use_master=True,
                )
            self.assertEqual([16], source.read_sizes)
            recover_key.assert_not_called()
            hkdf.assert_not_called()

        boundary = wrap_header(maximum)
        boundary_source = TrackingBytesIO(boundary)
        with self.assertRaisesRegex(ValueError, "truncated"):
            basefwx.fwxAES_decrypt_raw(
                boundary,
                "correct-password",
                use_master=True,
            )
        with self.assertRaisesRegex(ValueError, "truncated"):
            basefwx.fwxAES_decrypt_stream(
                boundary_source,
                io.BytesIO(),
                "correct-password",
                use_master=True,
            )
        self.assertEqual([16, maximum], boundary_source.read_sizes)

        oversized_key_header = b"x" * (maximum + 1)
        with patch.object(
            basefwx,
            "_prepare_mask_key",
            return_value=(b"\x03" * 32, b"user", b"master", True),
        ), patch.object(
            basefwx,
            "_pack_length_prefixed",
            return_value=oversized_key_header,
        ) as pack_header, patch.object(
            basefwx.os, "urandom"
        ) as random_bytes, patch.object(
            basefwx, "AESGCM"
        ) as aesgcm, patch.object(
            basefwx, "Cipher"
        ) as cipher:
            with self.assertRaisesRegex(
                ValueError, "fwxAES key header too large"
            ):
                basefwx.fwxAES_encrypt_raw(
                    b"payload",
                    "correct-password",
                    use_master=True,
                )
            with self.assertRaisesRegex(
                ValueError, "fwxAES key header too large"
            ):
                basefwx.fwxAES_encrypt_stream(
                    io.BytesIO(b"payload"),
                    io.BytesIO(),
                    "correct-password",
                    use_master=True,
                )
            self.assertEqual(2, pack_header.call_count)
            random_bytes.assert_not_called()
            aesgcm.assert_not_called()
            cipher.assert_not_called()

    def test_fwxaes_raw_and_stream_password_and_wrap_roundtrip(self):
        plaintext = b"fwxaes-wrap-header-roundtrip"
        password = "correct-password"
        with patch.dict(
            basefwx.os.environ,
            {
                "BASEFWX_TESTING": "1",
                "BASEFWX_TEST_KDF_ITERS": "2",
            },
            clear=False,
        ):
            raw = basefwx.fwxAES_encrypt_raw(
                plaintext, password, use_master=False
            )
            self.assertEqual(
                plaintext,
                basefwx.fwxAES_decrypt_raw(
                    raw, password, use_master=False
                ),
            )
            stream = io.BytesIO()
            basefwx.fwxAES_encrypt_stream(
                io.BytesIO(plaintext),
                stream,
                password,
                use_master=False,
            )
            stream.seek(0)
            recovered = io.BytesIO()
            basefwx.fwxAES_decrypt_stream(
                stream, recovered, password, use_master=False
            )
            self.assertEqual(plaintext, recovered.getvalue())

        mask_key = b"\x04" * 32
        with patch.object(
            basefwx,
            "_prepare_mask_key",
            return_value=(mask_key, b"user-wrap", b"master-wrap", True),
        ), patch.object(
            basefwx,
            "_recover_mask_key_from_blob",
            return_value=mask_key,
        ):
            raw = basefwx.fwxAES_encrypt_raw(
                plaintext, password, use_master=True
            )
            self.assertEqual(
                plaintext,
                basefwx.fwxAES_decrypt_raw(
                    raw, password, use_master=True
                ),
            )
            stream = io.BytesIO()
            basefwx.fwxAES_encrypt_stream(
                io.BytesIO(plaintext),
                stream,
                password,
                use_master=True,
            )
            stream.seek(0)
            recovered = io.BytesIO()
            basefwx.fwxAES_decrypt_stream(
                stream, recovered, password, use_master=True
            )
            self.assertEqual(plaintext, recovered.getvalue())

    @staticmethod
    def malicious_fwxaes_header(iterations: int) -> bytes:
        return basefwx.struct.pack(
            ">4sBBBBII",
            basefwx.FWXAES_MAGIC,
            basefwx.FWXAES_ALGO,
            basefwx.FWXAES_KDF_PBKDF2,
            0,
            0,
            iterations,
            basefwx.AEAD_TAG_LEN,
        )

    @staticmethod
    def malicious_live_header(iterations: int) -> bytes:
        body = basefwx.LIVE_HEADER_STRUCT.pack(
            basefwx.LIVE_KEYMODE_PBKDF2,
            1,
            basefwx.LIVE_NONCE_PREFIX_LEN,
            0,
            0,
            iterations,
        )
        body += b"\xa5"
        body += b"\x00" * basefwx.LIVE_NONCE_PREFIX_LEN
        return basefwx.LIVE_FRAME_HEADER_STRUCT.pack(
            basefwx.LIVE_FRAME_MAGIC,
            basefwx.LIVE_FRAME_VERSION,
            basefwx.LIVE_FRAME_TYPE_HEADER,
            0,
            len(body),
        ) + body

    def test_raw_stream_and_live_headers_reject_maximum_plus_one(self):
        iterations = basefwx.PEER_PBKDF2_ITERATIONS_MAX + 1
        header = self.malicious_fwxaes_header(iterations)
        with self.assertRaisesRegex(ValueError, "exceeds maximum"):
            basefwx.fwxAES_decrypt_raw(
                header, "correct-password", use_master=False
            )
        with self.assertRaisesRegex(ValueError, "exceeds maximum"):
            basefwx.fwxAES_decrypt_stream(
                io.BytesIO(header),
                io.BytesIO(),
                "correct-password",
                use_master=False,
            )
        with self.assertRaisesRegex(ValueError, "exceeds maximum"):
            basefwx.LiveDecryptor(
                "correct-password", use_master=False
            ).update(self.malicious_live_header(iterations))

    def test_live_rejects_oversized_key_header_from_outer_header_only(self):
        outer = basefwx.LIVE_FRAME_HEADER_STRUCT.pack(
            basefwx.LIVE_FRAME_MAGIC,
            basefwx.LIVE_FRAME_VERSION,
            basefwx.LIVE_FRAME_TYPE_HEADER,
            0,
            basefwx.LIVE_MAX_HEADER_BODY + 1,
        )
        with self.assertRaisesRegex(ValueError, "key header too large"):
            basefwx.LiveDecryptor(
                "correct-password", use_master=False
            ).update(outer)

    def test_simple_filecodec_rejects_metadata_maximum_plus_one(self):
        iterations = basefwx.PEER_PBKDF2_ITERATIONS_MAX + 1
        metadata = basefwx._build_metadata(
            "AES-HEAVY",
            False,
            False,
            kdf="pbkdf2",
            kdf_iters=iterations,
        )
        metadata_bytes = metadata.encode("utf-8")
        payload = len(metadata_bytes).to_bytes(4, "big") + metadata_bytes
        blob = basefwx._pack_length_prefixed(b"", b"", payload)
        with self.assertRaisesRegex(ValueError, "exceeds maximum"):
            basefwx.decryptAES(
                blob,
                "correct-password",
                use_master=False,
                allow_legacy=False,
            )

    def test_direct_stream_filecodec_rejects_metadata_maximum_plus_one(self):
        iterations = basefwx.PEER_PBKDF2_ITERATIONS_MAX + 1
        metadata = basefwx._build_metadata(
            "AES-HEAVY",
            False,
            False,
            kdf="pbkdf2",
            mode="STREAM",
            kdf_iters=iterations,
        )
        meta = basefwx._decode_metadata(metadata)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "peer-pbkdf2-over-max.fwx"
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "exceeds maximum"):
                basefwx._aes_heavy_decode_path_stream(
                    path,
                    "correct-password",
                    use_master=False,
                    meta_preview=meta,
                    metadata_blob_preview=metadata,
                )

    def test_all_argon_peer_fields_use_bounded_decimal_parser_before_kdf(self):
        maxima = {
            "ENC-ARGON2-TC": basefwx.ARGON2_TIME_COST_MAX,
            "ENC-ARGON2-MEM": basefwx.ARGON2_MEMORY_COST_MAX,
            "ENC-ARGON2-PAR": basefwx.ARGON2_PARALLELISM_MAX,
        }
        for field, maximum in maxima.items():
            self.assertEqual(
                maximum,
                basefwx._parse_peer_decimal(
                    str(maximum), field, maximum
                ),
            )
            for value in (
                " 1",
                "+1",
                "-1",
                "1 ",
                "1x",
                str(maximum + 1),
                "9" * 100_000,
            ):
                with self.subTest(field=field, value=value[:20]):
                    metadata = self.metadata_with(field, value)
                    metadata_bytes = metadata.encode("utf-8")
                    payload = (
                        len(metadata_bytes).to_bytes(4, "big")
                        + metadata_bytes
                    )
                    blob = basefwx._pack_length_prefixed(
                        b"x" * 32, b"", payload
                    )
                    with patch.object(
                        basefwx, "_derive_user_key"
                    ) as derive:
                        with self.assertRaisesRegex(ValueError, "Peer"):
                            basefwx.decryptAES(
                                blob,
                                "correct-password",
                                use_master=False,
                                allow_legacy=False,
                            )
                        derive.assert_not_called()

    def test_overlong_leading_zero_peer_decimal_rejects_before_kdf(self):
        value = "0" * 100_000 + "1"
        metadata = self.metadata_with("ENC-ARGON2-TC", value)
        metadata_bytes = metadata.encode("utf-8")
        payload = len(metadata_bytes).to_bytes(4, "big") + metadata_bytes
        blob = basefwx._pack_length_prefixed(b"x" * 32, b"", payload)
        with patch.object(basefwx, "_derive_user_key") as derive:
            with self.assertRaisesRegex(ValueError, "Peer.*exceeds maximum"):
                basefwx.decryptAES(
                    blob,
                    "correct-password",
                    use_master=False,
                    allow_legacy=False,
                )
            derive.assert_not_called()

    def test_length_prefix_and_stream_metadata_caps_reject_tiny_huge_declarations(self):
        with self.assertRaisesRegex(ValueError, "truncated|64 MiB"):
            basefwx._unpack_length_prefixed(
                (0xFFFFFFFF).to_bytes(4, "big"), 1
            )

        tiny = (
            (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (32).to_bytes(4, "big")
            + (0xFFFFFFFF).to_bytes(4, "big")
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            aes_path = Path(temp_dir) / "huge-meta-aes.fwx"
            aes_path.write_bytes(tiny)
            with patch.object(basefwx, "_derive_user_key") as derive:
                with self.assertRaisesRegex(ValueError, "metadata length"):
                    basefwx._aes_heavy_decode_path(
                        aes_path, "correct-password", use_master=False
                    )
                derive.assert_not_called()

            b512_path = Path(temp_dir) / "huge-meta-b512.fwx"
            b512_path.write_bytes(tiny)
            metadata = self.metadata_with(
                "ENC-ARGON2-TC", "1", mode="STREAM"
            )
            meta = basefwx._decode_metadata(metadata)
            with patch.object(basefwx, "_derive_user_key") as derive:
                with self.assertRaisesRegex(ValueError, "metadata length"):
                    basefwx._b512_decode_path_stream(
                        b512_path,
                        "correct-password",
                        use_master=False,
                        meta_preview=meta,
                        metadata_blob_preview=metadata,
                    )
                derive.assert_not_called()

    def test_argon_runtime_failure_never_switches_to_pbkdf2_or_writes_output(self):
        with patch.object(basefwx, "USER_KDF", "argon2id"), patch.object(
            basefwx, "hash_secret_raw", object()
        ), patch.object(
            basefwx,
            "_derive_user_key_argon2id",
            side_effect=MemoryError("simulated"),
        ), patch.object(basefwx, "_derive_user_key_pbkdf2") as pbkdf2:
            with self.assertRaises(MemoryError):
                basefwx._derive_user_key(
                    "correct-password", kdf="argon2id"
                )
            pbkdf2.assert_not_called()

            with self.assertRaises(MemoryError):
                basefwx._prepare_mask_key(
                    "correct-password",
                    False,
                    mask_info=b"test-mask",
                    require_password=True,
                    aad=b"test-aad",
                )
            pbkdf2.assert_not_called()

            with tempfile.TemporaryDirectory() as temp_dir:
                source = Path(temp_dir) / "input.bin"
                output = Path(temp_dir) / "output.fwx"
                source.write_bytes(b"payload")
                with self.assertRaises(MemoryError):
                    basefwx._aes_heavy_encode_path_stream(
                        source,
                        "correct-password",
                        use_master=False,
                        output_path=output,
                        keep_input=True,
                    )
                self.assertFalse(output.exists())
            pbkdf2.assert_not_called()

    def test_missing_argon_backend_never_switches_to_pbkdf2_or_writes_output(self):
        with patch.object(basefwx, "USER_KDF", "argon2id"), patch.object(
            basefwx, "hash_secret_raw", None
        ), patch.object(basefwx, "_derive_user_key_pbkdf2") as pbkdf2:
            with self.assertRaisesRegex(RuntimeError, "backend is unavailable"):
                basefwx._derive_user_key("correct-password")
            pbkdf2.assert_not_called()

            with tempfile.TemporaryDirectory() as temp_dir:
                source = Path(temp_dir) / "input.bin"
                output = Path(temp_dir) / "output.fwx"
                source.write_bytes(b"payload")
                with self.assertRaisesRegex(
                    RuntimeError, "backend is unavailable"
                ):
                    basefwx._aes_heavy_encode_path_stream(
                        source,
                        "correct-password",
                        use_master=False,
                        output_path=output,
                        keep_input=True,
                    )
                self.assertFalse(output.exists())
            pbkdf2.assert_not_called()

    def test_writer_pbkdf2_maximum_plus_one_fails_before_output(self):
        over_max = basefwx.PEER_PBKDF2_ITERATIONS_MAX + 1
        password = "correct-password"
        with patch.object(basefwx, "FWXAES_PBKDF2_ITERS", over_max):
            with self.assertRaisesRegex(ValueError, "exceeds maximum"):
                basefwx.fwxAES_encrypt_raw(
                    b"payload", password, use_master=False
                )

            destination = io.BytesIO()
            with self.assertRaisesRegex(ValueError, "exceeds maximum"):
                basefwx.fwxAES_encrypt_stream(
                    io.BytesIO(b"payload"),
                    destination,
                    password,
                    use_master=False,
                )
            self.assertEqual(b"", destination.getvalue())

            with self.assertRaisesRegex(ValueError, "exceeds maximum"):
                basefwx.LiveEncryptor(
                    password, use_master=False
                ).start()

        with patch.object(
            basefwx, "HEAVY_PBKDF2_ITERATIONS", over_max
        ), tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "input.bin"
            output = Path(temp_dir) / "output.fwx"
            source.write_bytes(b"payload")
            with self.assertRaisesRegex(ValueError, "exceeds maximum"):
                basefwx._aes_heavy_encode_path_stream(
                    source,
                    password,
                    use_master=False,
                    output_path=output,
                    keep_input=True,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
