# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""ML-KEM algorithm selection + encaps/decaps (pqcrypto, OQS-compatible)."""

from __future__ import annotations

import os
from typing import Optional, Tuple

from ._primitives import _env_enabled

ALG_768 = "ml-kem-768"
ALG_1024 = "ml-kem-1024"

try:
    from pqcrypto.kem import ml_kem_768 as _raw_ml_kem_768
except Exception:  # pragma: no cover
    _raw_ml_kem_768 = None

try:
    from pqcrypto.kem import ml_kem_1024 as _raw_ml_kem_1024
except Exception:  # pragma: no cover
    _raw_ml_kem_1024 = None


class _PQUnavailable:
    CIPHERTEXT_SIZE = 0
    PUBLIC_KEY_SIZE = 0
    SECRET_KEY_SIZE = 0

    @staticmethod
    def generate_keypair():
        raise RuntimeError("pqcrypto is required for PQ operations (pip install pqcrypto)")

    @staticmethod
    def encrypt(_public_key):
        raise RuntimeError("pqcrypto is required for PQ operations (pip install pqcrypto)")

    @staticmethod
    def decrypt(_private_key, _ciphertext):
        raise RuntimeError("pqcrypto is required for PQ operations (pip install pqcrypto)")


class _PQModuleAdapter:
    """Normalize the two public pqcrypto KEM APIs used in the wild.

    pqcrypto historically exported generate_keypair/encrypt/decrypt. Newer
    releases expose the same operations as keygen/encaps/decaps. BaseFWX keeps
    its stable internal interface while accepting either installed backend.
    """

    def __init__(self, module):
        self._module = module
        self.CIPHERTEXT_SIZE = module.CIPHERTEXT_SIZE
        self.PUBLIC_KEY_SIZE = module.PUBLIC_KEY_SIZE
        self.SECRET_KEY_SIZE = module.SECRET_KEY_SIZE

    def generate_keypair(self):
        return self._module.keygen()

    def encrypt(self, public_key):
        return self._module.encaps(public_key)

    def decrypt(self, private_key, ciphertext):
        return self._module.decaps(private_key, ciphertext)

    def __getattr__(self, name):
        return getattr(self._module, name)


def _adapt_module(module):
    if module is None:
        return None
    legacy_api = ("generate_keypair", "encrypt", "decrypt")
    if all(callable(getattr(module, name, None)) for name in legacy_api):
        return module
    current_api = ("keygen", "encaps", "decaps")
    if all(callable(getattr(module, name, None)) for name in current_api):
        return _PQModuleAdapter(module)
    return None


_ml_kem_768 = _adapt_module(_raw_ml_kem_768)
_ml_kem_1024 = _adapt_module(_raw_ml_kem_1024)


def _normalize_alg(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    value = name.strip().lower()
    if not value:
        return None
    if value in ("kyber768", "kyber-768", ALG_768):
        return ALG_768
    if value in ("kyber1024", "kyber-1024", ALG_1024):
        return ALG_1024
    return value


def is_supported_kem_algorithm(algorithm: Optional[str]) -> bool:
    return _normalize_alg(algorithm) in (ALG_768, ALG_1024)


def current_kem_algorithm() -> str:
    configured = _normalize_alg(os.getenv("BASEFWX_MASTER_PQ_ALG"))
    if not configured:
        if _env_enabled("BASEFWX_PQ_MAX") or _env_enabled("BASEFWX_PQ_1024"):
            configured = ALG_1024
        else:
            configured = ALG_768
    if not is_supported_kem_algorithm(configured):
        raise RuntimeError(f"Unsupported ML-KEM algorithm: {configured}")
    if configured == ALG_1024 and _ml_kem_1024 is None:
        raise RuntimeError(
            "ml-kem-1024 requested but pqcrypto.ml_kem_1024 is unavailable "
            "(pip install pqcrypto)"
        )
    if configured == ALG_768 and _ml_kem_768 is None:
        raise RuntimeError(
            "ml-kem-768 requested but pqcrypto.ml_kem_768 is unavailable "
            "(pip install pqcrypto)"
        )
    return configured


def _module_for(algorithm: Optional[str] = None):
    alg = _normalize_alg(algorithm) or current_kem_algorithm()
    if alg == ALG_1024:
        if _ml_kem_1024 is None:
            raise RuntimeError("pqcrypto ml_kem_1024 is required for ML-KEM-1024")
        return _ml_kem_1024
    if alg == ALG_768:
        if _ml_kem_768 is None:
            raise RuntimeError("pqcrypto ml_kem_768 is required for ML-KEM-768")
        return _ml_kem_768
    raise RuntimeError(f"Unsupported ML-KEM algorithm: {alg}")


def generate_kem_keypair(algorithm: Optional[str] = None) -> Tuple[bytes, bytes]:
    mod = _module_for(algorithm)
    return mod.generate_keypair()


def kem_encrypt(public_key: bytes, algorithm: Optional[str] = None) -> Tuple[bytes, bytes]:
    mod = _module_for(algorithm) if algorithm is not None else _module_for_public_key(public_key)
    return mod.encrypt(public_key)


def kem_decrypt(private_key: bytes, ciphertext: bytes, algorithm: Optional[str] = None) -> bytes:
    mod = (
        _module_for(algorithm)
        if algorithm is not None
        else _module_for_decapsulation(private_key, ciphertext)
    )
    return mod.decrypt(private_key, ciphertext)


def _available_modules():
    return tuple(mod for mod in (_ml_kem_768, _ml_kem_1024) if mod is not None)


def _module_for_public_key(public_key: bytes):
    if not isinstance(public_key, bytes):
        raise TypeError("ML-KEM public key must be bytes")
    for mod in _available_modules():
        if len(public_key) == mod.PUBLIC_KEY_SIZE:
            return mod
    raise ValueError(
        "Invalid ML-KEM public key length; expected ML-KEM-768 or ML-KEM-1024"
    )


def kem_algorithm_for_public_key(public_key: bytes) -> str:
    """Return the canonical algorithm selected by an actual public key."""
    mod = _module_for_public_key(public_key)
    return ALG_1024 if mod is _ml_kem_1024 else ALG_768


def _module_for_decapsulation(private_key: bytes, ciphertext: bytes):
    if not isinstance(private_key, bytes) or not isinstance(ciphertext, bytes):
        raise TypeError("ML-KEM private key and ciphertext must be bytes")
    for mod in _available_modules():
        if (
            len(private_key) == mod.SECRET_KEY_SIZE
            and len(ciphertext) == mod.CIPHERTEXT_SIZE
        ):
            return mod
    raise ValueError("Invalid or mismatched ML-KEM private-key/ciphertext lengths")


# Back-compat module objects used by legacy attribute access.
ml_kem_768 = _ml_kem_768 if _ml_kem_768 is not None else _PQUnavailable()
ml_kem_1024 = _ml_kem_1024 if _ml_kem_1024 is not None else _PQUnavailable()
