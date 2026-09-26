"""Unit and security tests for KeyWrapEngine."""

from __future__ import annotations

import base64
import pytest

from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.errors import CryptographicError
from tracecrypt.utils.identifiers import DistributionID, RecipientID


def test_key_wrap_roundtrip() -> None:
    """Verify that wrap_cek and unwrap_cek correctly recover the 256-bit CEK."""
    pk, sk = generate_mlkem_keypair()
    dist_id = SecureRandom.generate_typed_id(DistributionID)
    rcp_id = SecureRandom.generate_typed_id(RecipientID)
    cek = SecureRandom.random_bytes(32)

    envelope = KeyWrapEngine.wrap_cek_for_recipient(
        cek=cek,
        recipient_pk=pk,
        distribution_id=dist_id,
        recipient_id=rcp_id,
        key_id="key-01-kem",
        certificate_serial="crt-01",
        key_version=1,
    )

    assert envelope.recipient_id == rcp_id
    assert envelope.kem_algorithm == "ML-KEM-768"
    assert envelope.public_key_fingerprint == pk.fingerprint

    recovered_cek = KeyWrapEngine.unwrap_cek_for_recipient(
        envelope=envelope,
        recipient_sk=sk,
        distribution_id=dist_id,
        key_version=1,
    )

    assert bytes(recovered_cek) == cek


def test_key_wrap_wrong_private_key_fails_closed() -> None:
    """Verify that attempting to unwrap CEK with a different private key fails closed."""
    pk, _ = generate_mlkem_keypair()
    _, wrong_sk = generate_mlkem_keypair()
    dist_id = SecureRandom.generate_typed_id(DistributionID)
    rcp_id = SecureRandom.generate_typed_id(RecipientID)
    cek = SecureRandom.random_bytes(32)

    envelope = KeyWrapEngine.wrap_cek_for_recipient(
        cek=cek,
        recipient_pk=pk,
        distribution_id=dist_id,
        recipient_id=rcp_id,
        key_id="key-01-kem",
        certificate_serial="crt-01",
    )

    with pytest.raises(CryptographicError):
        KeyWrapEngine.unwrap_cek_for_recipient(
            envelope=envelope,
            recipient_sk=wrong_sk,
            distribution_id=dist_id,
        )


def test_key_wrap_tampered_wrapped_cek_fails_closed() -> None:
    """Verify that tampering with the wrapped CEK ciphertext or tag triggers authentication failure."""
    pk, sk = generate_mlkem_keypair()
    dist_id = SecureRandom.generate_typed_id(DistributionID)
    rcp_id = SecureRandom.generate_typed_id(RecipientID)
    cek = SecureRandom.random_bytes(32)

    envelope = KeyWrapEngine.wrap_cek_for_recipient(
        cek=cek,
        recipient_pk=pk,
        distribution_id=dist_id,
        recipient_id=rcp_id,
        key_id="key-01-kem",
        certificate_serial="crt-01",
    )

    raw_wrapped = bytearray(envelope.get_wrapped_cek_bytes())
    raw_wrapped[0] ^= 0xFF  # Corrupt first byte

    tampered_envelope = envelope.model_copy(
        update={"wrapped_cek_b64": base64.b64encode(bytes(raw_wrapped)).decode("ascii")}
    )

    with pytest.raises(CryptographicError):
        KeyWrapEngine.unwrap_cek_for_recipient(
            envelope=tampered_envelope,
            recipient_sk=sk,
            distribution_id=dist_id,
        )
