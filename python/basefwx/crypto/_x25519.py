# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""X25519 building block mirroring ``basefwx::x25519`` / Java ``X25519``.

Raw 32-byte keys, wipe helpers, reject the all-zero shared secret.
Not wired into fwxAES / keywrap file formats.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


KEY_LEN = 32


class KeyPair:
    __slots__ = ("public_key", "private_key")

    def __init__(
        self, public_key: bytes, private_key: "bytes | bytearray"
    ) -> None:
        self.public_key = public_key
        self.private_key = bytearray(private_key)

    def wipe_private(self) -> None:
        self.private_key[:] = b"\x00" * len(self.private_key)

    def __del__(self) -> None:  # pragma: no cover - best-effort wipe
        try:
            self.wipe_private()
        except Exception:
            pass


def generate_keypair() -> KeyPair:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return KeyPair(
        public_key=public.public_bytes_raw(),
        private_key=private.private_bytes_raw(),
    )


def derive_shared_secret(
    private_key: "bytes | bytearray | memoryview",
    peer_public_key: "bytes | bytearray | memoryview",
) -> bytes:
    if len(private_key) != KEY_LEN:
        raise ValueError("X25519 private key must be 32 bytes")
    if len(peer_public_key) != KEY_LEN:
        raise ValueError("X25519 public key must be 32 bytes")
    local = X25519PrivateKey.from_private_bytes(bytes(private_key))
    peer = X25519PublicKey.from_public_bytes(bytes(peer_public_key))
    shared = local.exchange(peer)
    if len(shared) != KEY_LEN:
        raise RuntimeError("X25519 shared-secret size mismatch")
    if shared == b"\x00" * KEY_LEN:
        raise ValueError("X25519 peer produced the forbidden all-zero shared secret")
    return shared
