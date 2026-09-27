"""Adversarial Keystore Container and Argon2id Security Tests.

Validates:
- Prevention of silent Argon2id parameter downgrade (memory, iterations, lanes).
- Fail-closed behavior on incorrect passphrase.
- Detection of tampered ciphertext, authentication tags, salt, or nonce.
- RFC 8785 canonical Authenticated Associated Data (AAD) integrity enforcement.
"""

from __future__ import annotations

import base64
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.types import KeyMetadata, KeyPurpose
from tracecrypt.errors import CryptographicError, SecurityError
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.utils.timestamps import utc_now_micros


class TestKeystoreSecurity:
    """Evaluate Argon2id + AES-256-GCM keystore against adversarial parameter and data attacks."""

    @pytest.fixture
    def keystore_fixture(self):
        pk, sk = generate_mldsa_keypair()
        metadata = KeyMetadata(
            key_id="key-sec-test-1",
            owner_id="usr-sec-test",
            algorithm="ML-DSA-65",
            parameter_set="ML-DSA-65",
            purpose=KeyPurpose.DIGITAL_SIGNATURE,
            fingerprint=pk.fingerprint,
            created_at=utc_now_micros(),
        )
        passphrase = "CorrectHorseBatteryStaple123!"
        container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)
        return container, passphrase, sk

    def test_wrong_passphrase_fails_closed(self, keystore_fixture) -> None:
        """Decrypting with incorrect passphrase must raise CryptographicError."""
        container, _, _ = keystore_fixture
        with pytest.raises(CryptographicError, match="Keystore decryption failed"):
            KeystoreManager.decrypt_private_key(container, "WrongPassword!")

    def test_argon2id_parameter_downgrade_prevention(self, keystore_fixture) -> None:
        """Attempting to decrypt a container with downgraded KDF parameters fails closed."""
        container, passphrase, _ = keystore_fixture

        # 1. Attempt downgrade: memory < 64 MB (65536 KB)
        low_mem_kdf = container.kdf_params.model_copy(update={"memory_cost_kb": 1024})
        c_low_mem = container.model_copy(update={"kdf_params": low_mem_kdf})
        with pytest.raises(SecurityError, match="downgraded Argon2id"):
            KeystoreManager.decrypt_private_key(c_low_mem, passphrase)

        # 2. Attempt downgrade: iterations < 3
        low_iter_kdf = container.kdf_params.model_copy(update={"iterations": 1})
        c_low_iter = container.model_copy(update={"kdf_params": low_iter_kdf})
        with pytest.raises(SecurityError, match="downgraded Argon2id"):
            KeystoreManager.decrypt_private_key(c_low_iter, passphrase)

        # 3. Attempt downgrade: lanes < 4
        low_lanes_kdf = container.kdf_params.model_copy(update={"parallelism": 1})
        c_low_lanes = container.model_copy(update={"kdf_params": low_lanes_kdf})
        with pytest.raises(SecurityError, match="downgraded Argon2id"):
            KeystoreManager.decrypt_private_key(c_low_lanes, passphrase)

    def test_ciphertext_tampering_rejected(self, keystore_fixture) -> None:
        """Bit-flipping in ciphertext_b64 must trigger authentication tag mismatch."""
        container, passphrase, _ = keystore_fixture
        raw_ct = bytearray(base64.b64decode(container.ciphertext_b64))
        raw_ct[0] ^= 0xFF  # Flip bits
        tampered_container = container.model_copy(
            update={"ciphertext_b64": base64.b64encode(raw_ct).decode("ascii")}
        )

        with pytest.raises(CryptographicError, match="Keystore decryption failed"):
            KeystoreManager.decrypt_private_key(tampered_container, passphrase)

    def test_auth_tag_tampering_rejected(self, keystore_fixture) -> None:
        """Bit-flipping in auth_tag_b64 must trigger authentication failure."""
        container, passphrase, _ = keystore_fixture
        raw_tag = bytearray(base64.b64decode(container.auth_tag_b64))
        raw_tag[0] ^= 0xFF
        tampered_container = container.model_copy(
            update={"auth_tag_b64": base64.b64encode(raw_tag).decode("ascii")}
        )

        with pytest.raises(CryptographicError, match="Keystore decryption failed"):
            KeystoreManager.decrypt_private_key(tampered_container, passphrase)

    def test_aad_metadata_tampering_rejected(self, keystore_fixture) -> None:
        """Modifying owner_id or algorithm in container metadata breaks AES-GCM AAD."""
        container, passphrase, _ = keystore_fixture
        tampered_container = container.model_copy(update={"owner_id": "usr-attacker"})

        with pytest.raises(CryptographicError, match="Keystore decryption failed"):
            KeystoreManager.decrypt_private_key(tampered_container, passphrase)
