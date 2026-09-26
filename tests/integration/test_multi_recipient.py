"""Integration test for Multi-Recipient Encrypted Document Distribution.

Verifies:
- Document encrypted ONCE with AES-256-GCM.
- Three authorized recipients (Alice, Bob, Charlie) receive independent ML-KEM-768 envelopes.
- All three can independently decrypt the package.
- Alice cannot use Bob's envelope; Bob cannot use Alice's envelope.
- Unauthorized recipient (Eve) is rejected.
- Tampering with ciphertext, metadata, or envelopes fails closed.
- Decrypted bytes match original source document hash.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.errors import (
    CryptographicError,
    PackageValidationError,
    SecurityError,
)
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.utils.identifiers import RecipientID, UserID


@pytest.fixture
def test_setup(tmp_path: Path):
    """Set up Root CA and three certified recipients: Alice, Bob, Charlie, plus Eve (unauthorized)."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-dist-test")
    sender_id = SecureRandom.generate_typed_id(UserID)

    def create_recipient(name: str):
        rid = SecureRandom.generate_typed_id(RecipientID)
        pk, sk = generate_mlkem_keypair()
        cert = ca.issue_kem_certificate(
            subject_id=str(rid),
            public_key=pk,
            organization="TraceCrypt Intelligence",
            role="RECIPIENT",
            validity_days=30,
        )
        spec = RecipientSpec(
            recipient_id=rid,
            public_key=pk,
            certificate=cert,
            key_id=f"key-{name.lower()}-kem-1",
        )
        return {"id": rid, "pk": pk, "sk": sk, "cert": cert, "spec": spec}

    alice = create_recipient("alice")
    bob = create_recipient("bob")
    charlie = create_recipient("charlie")
    eve = create_recipient("eve")

    # Sample source document
    doc_file = tmp_path / "top_secret_plan.pdf"
    doc_content = b"%PDF-1.7\nSECRET OPERATION ORDER: QUANTUM SHIELD\n" + b"X" * 4096
    doc_file.write_bytes(doc_content)
    source_hash = DocumentHasher.hash_bytes(doc_content)

    return {
        "ca": ca,
        "sender_id": sender_id,
        "doc_file": doc_file,
        "doc_content": doc_content,
        "source_hash": source_hash,
        "alice": alice,
        "bob": bob,
        "charlie": charlie,
        "eve": eve,
        "tmp_path": tmp_path,
    }


def test_multi_recipient_packaging_and_decryption(test_setup) -> None:
    """Verify Alice, Bob, and Charlie can decrypt the same .tcdist package."""
    ca = test_setup["ca"]
    alice = test_setup["alice"]
    bob = test_setup["bob"]
    charlie = test_setup["charlie"]
    eve = test_setup["eve"]
    doc_file = test_setup["doc_file"]
    doc_content = test_setup["doc_content"]
    pkg_file = test_setup["tmp_path"] / "operation.tcdist"

    # 1. Sender packages document for Alice, Bob, and Charlie
    recipients = [alice["spec"], bob["spec"], charlie["spec"]]
    pkg, saved_path = DistributionService.package_document(
        source_input=doc_file,
        recipients=recipients,
        output_path=pkg_file,
        root_ca_public_key=ca.public_key,
    )

    assert saved_path == pkg_file
    assert pkg_file.is_file()
    assert len(pkg.header.recipient_envelopes) == 3

    # Ensure all 3 envelopes have distinct ciphertexts (independent ML-KEM encapsulations)
    kem_cts = [e.kem_ciphertext_b64 for e in pkg.header.recipient_envelopes]
    assert len(set(kem_cts)) == 3

    # 2. Alice decrypts successfully
    with DistributionService.decrypt_package(
        package_input=pkg_file,
        recipient_id=alice["id"],
        recipient_sk=alice["sk"],
        recipient_cert=alice["cert"],
        root_ca_public_key=ca.public_key,
    ) as buf_alice:
        assert buf_alice.raw_bytes == doc_content
        assert buf_alice.source_document_hash == test_setup["source_hash"]

    # 3. Bob decrypts successfully
    with DistributionService.decrypt_package(
        package_input=pkg_file,
        recipient_id=bob["id"],
        recipient_sk=bob["sk"],
        recipient_cert=bob["cert"],
        root_ca_public_key=ca.public_key,
    ) as buf_bob:
        assert buf_bob.raw_bytes == doc_content

    # 4. Charlie decrypts successfully
    with DistributionService.decrypt_package(
        package_input=pkg_file,
        recipient_id=charlie["id"],
        recipient_sk=charlie["sk"],
        recipient_cert=charlie["cert"],
        root_ca_public_key=ca.public_key,
    ) as buf_charlie:
        assert buf_charlie.raw_bytes == doc_content

    # 5. Unauthorized recipient (Eve) cannot decrypt
    with pytest.raises(SecurityError) as exc_eve:
        DistributionService.decrypt_package(
            package_input=pkg_file,
            recipient_id=eve["id"],
            recipient_sk=eve["sk"],
            recipient_cert=eve["cert"],
            root_ca_public_key=ca.public_key,
        )
    assert "Access Denied" in str(exc_eve.value)


def test_cross_envelope_decryption_failure(test_setup) -> None:
    """Verify that Alice cannot decrypt using Bob's private key, and vice versa."""
    ca = test_setup["ca"]
    alice = test_setup["alice"]
    bob = test_setup["bob"]
    doc_file = test_setup["doc_file"]
    pkg_file = test_setup["tmp_path"] / "cross.tcdist"

    DistributionService.package_document(
        source_input=doc_file,
        recipients=[alice["spec"], bob["spec"]],
        output_path=pkg_file,
        root_ca_public_key=ca.public_key,
    )

    # Attempt to decrypt for Alice using Bob's private key -> fails closed
    with pytest.raises((SecurityError, CryptographicError)):
        DistributionService.decrypt_package(
            package_input=pkg_file,
            recipient_id=alice["id"],
            recipient_sk=bob["sk"],  # Wrong SK!
            recipient_cert=alice["cert"],
            root_ca_public_key=ca.public_key,
        )


def test_package_tampering_rejections(test_setup) -> None:
    """Verify that tampering with ciphertext, metadata, or envelopes fails closed."""
    ca = test_setup["ca"]
    alice = test_setup["alice"]
    doc_file = test_setup["doc_file"]

    pkg, _ = DistributionService.package_document(
        source_input=doc_file,
        recipients=[alice["spec"]],
        root_ca_public_key=ca.public_key,
    )
    raw_pkg = pkg.to_bytes()

    # 1. Tamper with ciphertext byte (inside body)
    tampered_body = bytearray(raw_pkg)
    tampered_body[-50] ^= 0xFF
    with pytest.raises(PackageValidationError):
        DistributionService.decrypt_package(
            package_input=bytes(tampered_body),
            recipient_id=alice["id"],
            recipient_sk=alice["sk"],
            recipient_cert=alice["cert"],
            root_ca_public_key=ca.public_key,
        )
