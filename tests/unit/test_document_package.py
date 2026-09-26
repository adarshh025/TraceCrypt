"""Unit tests for DistributionPackage and PackageValidator."""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.types import DistributionPackageHeader
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import PackageValidationError
from tracecrypt.utils.identifiers import DistributionID, DocumentID, RecipientID
from tracecrypt.utils.timestamps import utc_now_micros


@pytest.fixture
def sample_package() -> DistributionPackage:
    """Create a minimal valid DistributionPackage for testing."""
    pk, _ = generate_mlkem_keypair()
    dist_id = SecureRandom.generate_typed_id(DistributionID)
    doc_id = SecureRandom.generate_typed_id(DocumentID)
    rcp_id = SecureRandom.generate_typed_id(RecipientID)
    cek = SecureRandom.random_bytes(32)

    env = KeyWrapEngine.wrap_cek_for_recipient(
        cek=cek,
        recipient_pk=pk,
        distribution_id=dist_id,
        recipient_id=rcp_id,
        key_id="key-kem-01",
        certificate_serial="crt-kem-01",
    )

    header = DistributionPackageHeader(
        format_version="1.0.0",
        distribution_id=dist_id,
        document_id=doc_id,
        mime_type="application/pdf",
        filename="test.pdf",
        source_document_hash=DocumentHasher.hash_bytes(b"TEST DOCUMENT"),
        source_size_bytes=13,
        cipher_algorithm="AES-256-GCM",
        kem_algorithm="ML-KEM-768",
        recipient_envelopes=[env],
        created_at=utc_now_micros(),
    )

    nonce = SecureRandom.random_bytes(12)
    auth_tag = SecureRandom.random_bytes(16)
    ciphertext = b"ENCRYPTED_PAYLOAD_BYTES"

    return DistributionPackage(
        header=header,
        nonce=nonce,
        auth_tag=auth_tag,
        ciphertext=ciphertext,
    )


def test_package_binary_serialization_roundtrip(sample_package: DistributionPackage) -> None:
    """Verify that serialization to binary and deserialization preserves exact fields."""
    raw_bytes = sample_package.to_bytes()
    assert raw_bytes.startswith(b"TCDIST01")
    assert raw_bytes.endswith(b"TCDISTEND")

    recovered = DistributionPackage.from_bytes(raw_bytes)
    assert recovered.header.distribution_id == sample_package.header.distribution_id
    assert recovered.header.document_id == sample_package.header.document_id
    assert recovered.nonce == sample_package.nonce
    assert recovered.auth_tag == sample_package.auth_tag
    assert recovered.ciphertext == sample_package.ciphertext
    assert len(recovered.header.recipient_envelopes) == 1


def test_package_validator_valid_package(sample_package: DistributionPackage) -> None:
    """Verify that a valid package passes all 17 checks of PackageValidator."""
    res = PackageValidator.validate(sample_package)
    assert res.valid is True
    assert res.checks_passed == 17


def test_package_validator_corrupted_checksum_fails(sample_package: DistributionPackage) -> None:
    """Verify that corrupting any byte in the package body causes checksum rejection."""
    raw = bytearray(sample_package.to_bytes())
    # Modify a byte inside the header area
    raw[25] ^= 0xFF

    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(bytes(raw))
    assert "checksum verification failed" in str(exc.value)


def test_package_validator_bad_magic_fails(sample_package: DistributionPackage) -> None:
    """Verify that bad magic header or footer fails closed."""
    raw = bytearray(sample_package.to_bytes())
    raw[0] = ord(b"X")

    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(bytes(raw))
    assert "Invalid package header magic" in str(exc.value)


def test_package_validator_truncated_package_fails() -> None:
    """Verify that truncated data fails closed."""
    with pytest.raises(PackageValidationError):
        PackageValidator.validate(b"TCDIST01")
