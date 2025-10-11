"""
Optional YubiKey-backed storage for ML-KEM post-quantum secrets.

This module keeps the YubiKey dependency optional. When the `python-fido2`
package is not available or no compatible device is present, the helper raises
`YubiKeyUnavailableError`. Callers should surface the exception as a friendly
message so users know the optional feature needs extra setup.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

try:
    from fido2.client import (
        AssertionSelection,
        Fido2Client,
        RegistrationResponse,
    )
    from fido2.ctap2 import CtapError
    from fido2.hid import CtapHidDevice
    from fido2.webauthn import (
        AuthenticatorSelectionCriteria,
        AuthenticatorTransport,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    _HAVE_FIDO2 = True
except Exception:  # pragma: no cover - optional dependency branch
    _HAVE_FIDO2 = False


class YubiKeyUnavailableError(RuntimeError):
    """Raised when the YubiKey integration cannot be used."""


@dataclass(frozen=True)
class StoredPQKey:
    credential_id: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    public_key: bytes

    def to_record(self) -> Mapping[str, str]:
        return {
            "credential_id": base64.b64encode(self.credential_id).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
        }

    @classmethod
    def from_record(cls, record: Mapping[str, str]) -> "StoredPQKey":
        return cls(
            credential_id=base64.b64decode(record["credential_id"]),
            salt=base64.b64decode(record["salt"]),
            nonce=base64.b64decode(record["nonce"]),
            ciphertext=base64.b64decode(record["ciphertext"]),
            public_key=base64.b64decode(record["public_key"]),
        )


class YubiKeyPQKeyStore:
    """
    Wrap ML-KEM private keys with a secret derived from a resident YubiKey credential.

    The private key never touches disk in the clear. Instead it is sealed with AES-GCM
    using a key derived from the hmac-secret extension tied to a specific credential
    stored on the YubiKey. The encrypted blob plus public key metadata lives in the
    user's home directory so the dependency only surfaces when the credential needs to
    be accessed.
    """

    RP_ID = "basefwx.local"
    RP_NAME = "basefwx PQ Vault"
    ORIGIN = "https://basefwx.local"
    STATE_DIR = Path.home() / ".basefwx"
    STATE_PATH = STATE_DIR / "yubikey_pq_keys.json"
    WRAP_SALT_BYTES = 32
    AES_NONCE_BYTES = 12
    _PUB_KEY_PARAMS = (
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
    )

    def __init__(self) -> None:
        if not _HAVE_FIDO2:
            raise YubiKeyUnavailableError(
                "python-fido2 is not installed. Install it in order to use the "
                "optional YubiKey integration."
            )

    # ---------- Public API -------------------------------------------------

    def get_or_create(self, label: str) -> Tuple[bytes, bytes]:
        """
        Fetch the ML-KEM keypair associated with the label, registering a new one
        if needed. Touching the YubiKey is required whenever the key is accessed.
        """
        record_map = self._load_state()
        normalized = self._normalize_label(label)
        if normalized in record_map:
            stored = StoredPQKey.from_record(record_map[normalized])
        else:
            stored = self._enroll(normalized)
            record_map[normalized] = stored.to_record()
            self._store_state(record_map)
        wrap_key = self._derive_wrap_key(stored.credential_id, stored.salt)
        aesgcm = AESGCM(wrap_key)
        private_key = aesgcm.decrypt(stored.nonce, stored.ciphertext, None)
        return stored.public_key, private_key

    def derive_passphrase(self, label: str, *, digest: bool = True) -> str:
        """
        Produce a UTF-8 passphrase derived from the sealed ML-KEM private key.
        The digest flag controls whether the raw key material or a SHA-3 digest
        is returned. Hashing keeps the password ASCII friendly.
        """
        _, private_key = self.get_or_create(label)
        if digest:
            digestor = hashes.Hash(hashes.SHA3_512())
            digestor.update(private_key)
            reduced = digestor.finalize()
            return base64.urlsafe_b64encode(reduced).decode("ascii")
        return base64.urlsafe_b64encode(private_key).decode("ascii")

    def export_public_key(self, label: str) -> bytes:
        """Convenience helper to fetch the public key for the given label."""
        record_map = self._load_state()
        normalized = self._normalize_label(label)
        if normalized not in record_map:
            raise YubiKeyUnavailableError(
                f"No YubiKey record named '{label}' was found. Touch the key to "
                "provision it first."
            )
        stored = StoredPQKey.from_record(record_map[normalized])
        return stored.public_key

    # ---------- Internal helpers -------------------------------------------

    def _normalize_label(self, label: str) -> str:
        stripped = label.strip()
        if not stripped:
            raise ValueError("YubiKey label must not be empty")
        if len(stripped) > 64:
            raise ValueError("YubiKey label must be at most 64 characters")
        return stripped

    def _load_state(self) -> Dict[str, Mapping[str, str]]:
        if not self.STATE_PATH.exists():
            return {}
        try:
            with self.STATE_PATH.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:  # pragma: no cover - defensive guard
            raise RuntimeError(
                f"Failed to read YubiKey key store at {self.STATE_PATH}: {exc}"
            ) from exc

    def _store_state(self, state: Mapping[str, Mapping[str, str]]) -> None:
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp_path = self.STATE_PATH.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(self.STATE_PATH)
        try:
            os.chmod(self.STATE_PATH, 0o600)
        except PermissionError:
            # Best effort; on platforms without chmod (e.g. Windows) this can be ignored.
            pass

    def _enroll(self, label: str) -> StoredPQKey:
        credential_id, salt, secret = self._register_resident_credential(label)
        wrap_key = self._derive_wrap_key(credential_id, salt, secret=secret)
        nonce = secrets.token_bytes(self.AES_NONCE_BYTES)
        from pqcrypto.kem import ml_kem_768

        public_key, private_key = ml_kem_768.generate_keypair()
        aesgcm = AESGCM(wrap_key)
        ciphertext = aesgcm.encrypt(nonce, private_key, None)
        return StoredPQKey(
            credential_id=credential_id,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            public_key=public_key,
        )

    def _register_resident_credential(self, label: str) -> Tuple[bytes, bytes, bytes]:
        client, device = self._connect()
        try:
            rp = PublicKeyCredentialRpEntity(id=self.RP_ID, name=self.RP_NAME)
            user_id = hashes.Hash(hashes.SHA3_256())
            user_id.update(label.encode("utf-8"))
            user = PublicKeyCredentialUserEntity(
                id=user_id.finalize(),
                name=label,
                display_name=label,
            )
            challenge = secrets.token_bytes(32)
            selection = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.DISCOURAGED,
            )
            options = PublicKeyCredentialCreationOptions(
                rp=rp,
                user=user,
                challenge=challenge,
                pub_key_cred_params=self._PUB_KEY_PARAMS,
                timeout=60000,
                authenticator_selection=selection,
                extensions={"hmacSecret": True},
            )
            response: RegistrationResponse = client.make_credential(options)
            cred_id = response.raw_id
            salt = secrets.token_bytes(self.WRAP_SALT_BYTES)
            secret = self._obtain_hmac_secret(
                client=client,
                credential_id=cred_id,
                salt=salt,
            )
            if len(secret) < 32:
                raise RuntimeError("Authenticator hmac-secret extension returned too few bytes")
            return cred_id, salt, secret
        except CtapError as exc:
            raise YubiKeyUnavailableError(f"YubiKey refused registration: {exc}") from exc
        finally:
            device.close()

    def _derive_wrap_key(
        self,
        credential_id: bytes,
        salt: bytes,
        *,
        secret: Optional[bytes] = None,
    ) -> bytes:
        if secret is None:
            secret = self._obtain_hmac_secret(credential_id=credential_id, salt=salt)
        digestor = hashes.Hash(hashes.SHA3_256())
        digestor.update(secret)
        digestor.update(salt)
        digestor.update(credential_id)
        return digestor.finalize()

    def _obtain_hmac_secret(
        self,
        credential_id: bytes,
        salt: bytes,
        *,
        client: Optional[Fido2Client] = None,
    ) -> bytes:
        client_ctx: Optional[Fido2Client] = None
        device = None
        try:
            if client is None:
                client_ctx, device = self._connect()
            active_client = client or client_ctx
            if active_client is None:
                raise YubiKeyUnavailableError("Unable to initialise FIDO2 client")
            descriptors = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=credential_id,
                    transports=[AuthenticatorTransport.USB],
                )
            ]
            request_options = PublicKeyCredentialRequestOptions(
                challenge=secrets.token_bytes(32),
                timeout=60000,
                rp_id=self.RP_ID,
                allow_credentials=descriptors,
                user_verification=UserVerificationRequirement.DISCOURAGED,
                extensions={"hmacSecret": {"salt1": salt}},
            )
            assertion: AssertionSelection = active_client.get_assertion(request_options)
            response = assertion.get_response(0)
            results = response.client_extension_results
            secret = results.get("hmacSecret")
            if not secret:
                raise RuntimeError("Authenticator did not return an hmac-secret")
            # The extension may return a list of results; normalise to bytes.
            if isinstance(secret, list):
                secret = b"".join(secret)
            if not isinstance(secret, (bytes, bytearray)):
                raise RuntimeError("Unexpected hmac-secret type returned by authenticator")
            return bytes(secret)
        except CtapError as exc:
            raise YubiKeyUnavailableError(f"YubiKey assertion failed: {exc}") from exc
        finally:
            if device:
                device.close()

    def _connect(self) -> Tuple[Fido2Client, CtapHidDevice]:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise YubiKeyUnavailableError("No YubiKey detected over HID.")
        device = devices[0]
        client = Fido2Client(device, self.ORIGIN)
        return client, device
