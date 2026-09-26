"""Unit and property tests for NIST FIPS 203 ML-KEM-768."""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_kem import (
    decapsulate,
    encapsulate,
    generate_mlkem_keypair,
)
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLKEMCiphertext,
    MLKEMPrivateKey,
    MLKEMPublicKey,
)
from tracecrypt.errors import ValidationError


def test_mlkem_keygen_sizes() -> None:
    """Verify that generated ML-KEM-768 key pairs match NIST FIPS 203 byte lengths."""
    pk, sk = generate_mlkem_keypair()

    assert isinstance(pk, MLKEMPublicKey)
    assert isinstance(sk, MLKEMPrivateKey)
    assert len(pk.raw_bytes) == MLKEMPublicKey.EXPECTED_LENGTH  # 1184 bytes
    assert len(sk.raw_bytes) == MLKEMPrivateKey.EXPECTED_LENGTH  # 2400 bytes
    assert pk.purpose == KeyPurpose.KEY_ENCAPSULATION
    assert sk.purpose == KeyPurpose.KEY_ENCAPSULATION
    assert pk.algorithm == "ML-KEM-768"
    assert sk.algorithm == "ML-KEM-768"
    assert pk.fingerprint.startswith("mlkem768:sha3-256:")


def test_mlkem_encapsulate_decapsulate_agreement() -> None:
    """Verify standard encapsulation and decapsulation shared-secret equality."""
    pk, sk = generate_mlkem_keypair()

    ss_sender, ciphertext = encapsulate(pk)
    assert len(ss_sender) == 32
    assert isinstance(ciphertext, MLKEMCiphertext)
    assert len(ciphertext.raw_bytes) == MLKEMCiphertext.EXPECTED_LENGTH  # 1088 bytes

    ss_recipient = decapsulate(sk, ciphertext)
    assert len(ss_recipient) == 32
    assert ss_sender == ss_recipient


def test_mlkem_wrong_private_key_rejection() -> None:
    """Verify that decapsulating with a mismatched private key fails (implicit rejection).

    Per NIST FIPS 203, decapsulation on invalid ciphertext or key does not raise an exception,
    but produces a deterministic pseudo-random key that differs from the sender's shared secret.
    """
    pk1, _ = generate_mlkem_keypair()
    _, sk2 = generate_mlkem_keypair()

    ss_sender, ciphertext = encapsulate(pk1)
    ss_wrong = decapsulate(sk2, ciphertext)

    assert ss_wrong != ss_sender


def test_mlkem_corrupted_ciphertext_implicit_rejection() -> None:
    """Verify that corrupted ciphertext decapsulation yields a different pseudo-random secret."""
    pk, sk = generate_mlkem_keypair()

    ss_sender, ciphertext = encapsulate(pk)

    # Tamper with the ciphertext bytes
    tampered_bytes = bytearray(ciphertext.raw_bytes)
    tampered_bytes[42] ^= 0xFF
    tampered_ciphertext = MLKEMCiphertext(bytes(tampered_bytes))

    ss_tampered = decapsulate(sk, tampered_ciphertext)
    assert ss_tampered != ss_sender


def test_mlkem_invalid_ciphertext_length_rejection() -> None:
    """Verify that malformed ciphertext lengths fail closed with ValidationError."""
    _, sk = generate_mlkem_keypair()

    with pytest.raises(ValidationError, match="Invalid ML-KEM-768 ciphertext length"):
        MLKEMCiphertext(b"\x00" * 500)

    with pytest.raises(ValidationError, match="Invalid ML-KEM-768 ciphertext length"):
        MLKEMCiphertext(b"\x00" * 2000)


def test_mlkem_invalid_key_lengths_fail_closed() -> None:
    """Verify that malformed public or private key lengths are rejected immediately."""
    with pytest.raises(ValidationError, match="Invalid ML-KEM-768 public key length"):
        MLKEMPublicKey(b"invalid_pk_bytes")

    with pytest.raises(ValidationError, match="Invalid ML-KEM-768 private key length"):
        MLKEMPrivateKey(b"invalid_sk_bytes")


def test_mlkem_deterministic_seed_property() -> None:
    """Verify deterministic KAT behavior when using internal fixed seeds."""
    from mlkem.ml_kem import ML_KEM
    from mlkem.parameter_set import ML_KEM_768

    engine = ML_KEM(ML_KEM_768)
    d = b"\x01" * 32
    z = b"\x02" * 32

    pk_bytes_1, sk_bytes_1 = engine._key_gen(d, z)
    pk_bytes_2, sk_bytes_2 = engine._key_gen(d, z)

    assert pk_bytes_1 == pk_bytes_2
    assert sk_bytes_1 == sk_bytes_2

    m = b"\x03" * 32
    ss1, ct1 = engine._encaps(pk_bytes_1, m)
    ss2, ct2 = engine._encaps(pk_bytes_1, m)

    assert ss1 == ss2
    assert ct1 == ct2

    recovered_ss = engine.decaps(sk_bytes_1, ct1)
    assert recovered_ss == ss1


def test_mlkem_repeated_operations_independence() -> None:
    """Verify that consecutive encapsulation operations generate distinct shared secrets."""
    pk, sk = generate_mlkem_keypair()

    ss1, ct1 = encapsulate(pk)
    ss2, ct2 = encapsulate(pk)

    assert ss1 != ss2
    assert ct1.raw_bytes != ct2.raw_bytes
    assert decapsulate(sk, ct1) == ss1
    assert decapsulate(sk, ct2) == ss2
