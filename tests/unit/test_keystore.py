"""Unit and security tests for Argon2id and AES-256-GCM KeystoreManager."""

from __future__ import annotations

import base64
from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    KeyStatus,
)
from tracecrypt.errors import CryptographicError, SecurityError
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.utils.timestamps import utc_now_micros


def test_argon2id_aes_gcm_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    """Verify full encrypt and decrypt lifecycle of ML-DSA private key."""
    pk, sk = generate_mldsa_keypair()
    passphrase = "CorrectHorseBatteryStaple-OfflineRoot-2026!"
    metadata = KeyMetadata(
        key_id="key-usr-alice-dsa-1",
        owner_id="usr-alice",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=pk.fingerprint,
    )

    container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)
    assert container.format_version == "1.0.0"
    assert container.cipher_algorithm == "AES-256-GCM"
    assert container.kdf_params.algorithm == "Argon2id"
    assert container.kdf_params.memory_cost_kb == 65536  # 64 MB
    assert container.kdf_params.iterations == 3
    assert container.kdf_params.parallelism == 4

    key_file = tmp_path / "alice_sk.json"
    KeystoreManager.save_container(container, key_file)
    assert key_file.exists()

    loaded_container = KeystoreManager.load_container(key_file)
    decrypted_bytes = KeystoreManager.decrypt_private_key(loaded_container, passphrase)

    try:
        assert bytes(decrypted_bytes) == sk.raw_bytes
    finally:
        # Zeroize test buffer
        for i in range(len(decrypted_bytes)):
            decrypted_bytes[i] = 0


def test_keystore_wrong_password_fails_closed(tmp_path: Path) -> None:
    """Verify that decryption with an incorrect passphrase fails closed without leaking key."""
    _, sk = generate_mlkem_keypair()
    passphrase = "SecretMasterPassword123"
    metadata = KeyMetadata(
        key_id="key-kem-1",
        owner_id="rcp-bob",
        purpose=KeyPurpose.KEY_ENCAPSULATION,
        algorithm="ML-KEM-768",
        parameter_set="ML-KEM-768",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mlkem768:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)
    key_file = tmp_path / "bob_kem.json"
    KeystoreManager.save_container(container, key_file)

    with pytest.raises(CryptographicError, match="Keystore decryption failed"):
        KeystoreManager.decrypt_private_key(container, "WrongPassword!")


def test_keystore_tampered_ciphertext_rejection(tmp_path: Path) -> None:
    """Verify that AES-256-GCM authentication tag catches corrupted ciphertext."""
    _, sk = generate_mldsa_keypair()
    passphrase = "StrongPassword456!"
    metadata = KeyMetadata(
        key_id="key-tamper-1",
        owner_id="usr-carol",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)

    # Modify raw ciphertext bytes
    ct_bytes = bytearray(base64.b64decode(container.ciphertext_b64))
    ct_bytes[10] ^= 0x55
    tampered_container = container.model_copy(
        update={"ciphertext_b64": base64.b64encode(bytes(ct_bytes)).decode("ascii")}
    )

    with pytest.raises(CryptographicError, match="Keystore decryption failed"):
        KeystoreManager.decrypt_private_key(tampered_container, passphrase)


def test_keystore_tampered_aad_metadata_rejection() -> None:
    """Verify that altering metadata in AAD causes AES-GCM verification to fail."""
    _, sk = generate_mldsa_keypair()
    passphrase = "StrongPassword789!"
    metadata = KeyMetadata(
        key_id="key-aad-1",
        owner_id="usr-dave",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)

    # Modify metadata in container (e.g. change owner_id)
    tampered_container = container.model_copy(update={"owner_id": "usr-attacker"})

    with pytest.raises(CryptographicError, match="Keystore decryption failed"):
        KeystoreManager.decrypt_private_key(tampered_container, passphrase)


def test_keystore_unsupported_version_rejection() -> None:
    """Verify that unsupported container versions are rejected."""
    _, sk = generate_mldsa_keypair()
    passphrase = "TestPassword"
    metadata = KeyMetadata(
        key_id="key-ver-1",
        owner_id="usr-eve",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, passphrase, metadata)
    tampered_container = container.model_copy(update={"format_version": "99.0.0"})

    with pytest.raises(SecurityError, match="Unsupported keystore format version"):
        KeystoreManager.decrypt_private_key(tampered_container, passphrase)
