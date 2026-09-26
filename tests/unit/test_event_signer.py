"""Unit tests for DecryptionEventSigner enforcing post-quantum signature generation and key-purpose separation."""

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import SecurityError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


@pytest.fixture
def test_pki():
    """Set up an isolated test Root CA and recipient credentials."""
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-test")
    recipient_id = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")

    # 1. Issue valid ML-DSA-65 signing certificate
    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=recipient_id,
        public_key=dsa_pk,
        organization="Test Ops",
        role="RECIPIENT",
    )

    # 2. Issue ML-KEM-768 encapsulation certificate (different key purpose)
    kem_pk, kem_sk = generate_mlkem_keypair()
    kem_cert = root_ca.issue_kem_certificate(
        subject_id=recipient_id,
        public_key=kem_pk,
        organization="Test Ops",
        role="RECIPIENT",
    )

    return {
        "root_ca": root_ca,
        "recipient_id": recipient_id,
        "dsa_pk": dsa_pk,
        "dsa_sk": dsa_sk,
        "dsa_cert": dsa_cert,
        "kem_pk": kem_pk,
        "kem_sk": kem_sk,
        "kem_cert": kem_cert,
    }


def make_test_event(recipient_id: RecipientID) -> DecryptionEvent:
    return DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=SecureRandom.generate_typed_id(EventID),
        document_id=SecureRandom.generate_typed_id(DocumentID),
        distribution_id=SecureRandom.generate_typed_id(DistributionID),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recipient_id,
        session_id=SecureRandom.generate_typed_id(SessionID),
        watermark_id=SecureRandom.generate_typed_id(WatermarkID),
        watermark_version=1,
        anti_replay_nonce=SecureRandom.generate_nonce(16),
        timestamp=1727280000000000,
        pqc_algorithms=PQCAlgorithms(),
    )


@pytest.mark.unit
def test_sign_event_success(test_pki):
    event = make_test_event(test_pki["recipient_id"])

    signed_event = DecryptionEventSigner.sign_event(
        event=event,
        signing_key=test_pki["dsa_sk"],
        signing_cert=test_pki["dsa_cert"],
        root_ca_public_key=test_pki["root_ca"].public_key,
    )

    assert signed_event.event.event_id == event.event_id
    assert signed_event.certificate_id == test_pki["dsa_cert"].serial_number
    assert signed_event.certificate_fingerprint == test_pki["dsa_cert"].public_key_fingerprint
    assert len(signed_event.get_signature_bytes()) == 3309
    assert signed_event.event_digest.startswith("sha3-256:")


@pytest.mark.unit
def test_sign_event_rejects_kem_certificate(test_pki):
    """Enforce key-purpose separation: ML-KEM certificate cannot sign events."""
    event = make_test_event(test_pki["recipient_id"])

    with pytest.raises(SecurityError, match="Key purpose violation"):
        DecryptionEventSigner.sign_event(
            event=event,
            signing_key=test_pki["dsa_sk"],
            signing_cert=test_pki["kem_cert"],  # Purpose is KEY_ENCAPSULATION
            root_ca_public_key=test_pki["root_ca"].public_key,
        )


@pytest.mark.unit
def test_sign_event_rejects_identity_mismatch(test_pki):
    other_recipient = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")
    event = make_test_event(other_recipient)

    with pytest.raises(SecurityError, match="Identity binding mismatch"):
        DecryptionEventSigner.sign_event(
            event=event,
            signing_key=test_pki["dsa_sk"],
            signing_cert=test_pki["dsa_cert"],  # Belongs to original recipient_id
            root_ca_public_key=test_pki["root_ca"].public_key,
        )


@pytest.mark.unit
def test_sign_event_rejects_mismatched_private_key(test_pki):
    """Signing key must match the public key in the provided certificate."""
    event = make_test_event(test_pki["recipient_id"])
    _, other_sk = generate_mldsa_keypair()

    with pytest.raises(SecurityError, match="Cryptographic mismatch"):
        DecryptionEventSigner.sign_event(
            event=event,
            signing_key=other_sk,  # Wrong private key
            signing_cert=test_pki["dsa_cert"],
            root_ca_public_key=test_pki["root_ca"].public_key,
        )
