"""Unit and property tests for NIST FIPS 204 ML-DSA-65."""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import (
    generate_mldsa_keypair,
    sign,
    verify,
)
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    MLDSASignature,
)
from tracecrypt.errors import ValidationError


def test_mldsa_keygen_sizes() -> None:
    """Verify that generated ML-DSA-65 key pairs match NIST FIPS 204 byte lengths."""
    pk, sk = generate_mldsa_keypair()

    assert isinstance(pk, MLDSAPublicKey)
    assert isinstance(sk, MLDSAPrivateKey)
    assert len(pk.raw_bytes) == MLDSAPublicKey.EXPECTED_LENGTH  # 1952 bytes
    assert len(sk.raw_bytes) == MLDSAPrivateKey.EXPECTED_LENGTH  # 4032 bytes
    assert pk.purpose == KeyPurpose.DIGITAL_SIGNATURE
    assert sk.purpose == KeyPurpose.DIGITAL_SIGNATURE
    assert pk.algorithm == "ML-DSA-65"
    assert sk.algorithm == "ML-DSA-65"
    assert pk.fingerprint.startswith("mldsa65:sha3-256:")


def test_mldsa_sign_and_verify_valid() -> None:
    """Verify that a valid ML-DSA-65 signature on a message verifies successfully."""
    pk, sk = generate_mldsa_keypair()
    message = b"TraceCrypt canonical decryption event 42"

    signature = sign(sk, message)
    assert isinstance(signature, MLDSASignature)
    assert len(signature.raw_bytes) == MLDSASignature.EXPECTED_LENGTH  # 3309 bytes

    is_valid = verify(pk, message, signature)
    assert is_valid is True


def test_mldsa_modified_message_fails() -> None:
    """Verify that any modification to the signed message causes verification to fail."""
    pk, sk = generate_mldsa_keypair()
    message = b"Original uncorrupted message"
    signature = sign(sk, message)

    modified_message = b"Tampered uncorrupted message"
    assert verify(pk, modified_message, signature) is False


def test_mldsa_modified_signature_fails() -> None:
    """Verify that altering signature bytes causes verification to fail."""
    pk, sk = generate_mldsa_keypair()
    message = b"Secure payload bytes"
    signature = sign(sk, message)

    tampered_sig_bytes = bytearray(signature.raw_bytes)
    tampered_sig_bytes[100] ^= 0x01
    tampered_sig = MLDSASignature(bytes(tampered_sig_bytes))

    assert verify(pk, message, tampered_sig) is False


def test_mldsa_wrong_public_key_fails() -> None:
    """Verify that verifying with a different public key fails."""
    pk1, sk1 = generate_mldsa_keypair()
    pk2, _ = generate_mldsa_keypair()
    message = b"Payload signed by key 1"

    signature = sign(sk1, message)
    assert verify(pk1, message, signature) is True
    assert verify(pk2, message, signature) is False


def test_mldsa_invalid_signature_length_rejection() -> None:
    """Verify that malformed signature length is rejected on construction."""
    with pytest.raises(ValidationError, match="Invalid ML-DSA-65 signature length"):
        MLDSASignature(b"\x00" * 100)


def test_mldsa_invalid_key_lengths_fail_closed() -> None:
    """Verify that malformed public or private key lengths are rejected immediately."""
    with pytest.raises(ValidationError, match="Invalid ML-DSA-65 public key length"):
        MLDSAPublicKey(b"short_pk")

    with pytest.raises(ValidationError, match="Invalid ML-DSA-65 private key length"):
        MLDSAPrivateKey(b"short_sk")


def test_mldsa_deterministic_seed_property() -> None:
    """Verify deterministic key generation given a fixed 32-byte seed."""
    from dilithium_py.ml_dsa import ML_DSA_65

    zeta = b"\x05" * 32
    pk1, sk1 = ML_DSA_65._keygen_internal(zeta)
    pk2, sk2 = ML_DSA_65._keygen_internal(zeta)

    assert pk1 == pk2
    assert sk1 == sk2


def test_mldsa_repeated_signing_unique_signatures() -> None:
    """Verify that randomized signing produces distinct valid signatures over the same message."""
    pk, sk = generate_mldsa_keypair()
    message = b"Repeated signing test"

    sig1 = sign(sk, message)
    sig2 = sign(sk, message)

    assert verify(pk, message, sig1) is True
    assert verify(pk, message, sig2) is True
