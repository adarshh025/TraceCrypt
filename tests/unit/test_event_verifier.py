"""Unit tests for DecryptionEventVerifier fail-closed 8-point verification pipeline and tamper detection."""

import base64
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.lifecycle import OfflineRevocationStore, RevocationReason
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


@pytest.fixture
def signed_pki_context(tmp_path):
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-test")
    recipient_id = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")

    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=recipient_id,
        public_key=dsa_pk,
        organization="Test Ops",
        role="RECIPIENT",
    )

    db_path = tmp_path / "revocations.db"
    store = SQLiteStorageManager(db_path)
    store.initialize()
    rev_provider = OfflineRevocationStore(store)

    event = DecryptionEvent(
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

    signed_event = DecryptionEventSigner.sign_event(
        event=event,
        signing_key=dsa_sk,
        signing_cert=dsa_cert,
        root_ca_public_key=root_ca.public_key,
    )

    return {
        "root_ca": root_ca,
        "recipient_id": recipient_id,
        "dsa_pk": dsa_pk,
        "dsa_sk": dsa_sk,
        "dsa_cert": dsa_cert,
        "signed_event": signed_event,
        "rev_provider": rev_provider,
        "store": store,
    }


@pytest.mark.unit
def test_verify_valid_signed_event(signed_pki_context):
    ctx = signed_pki_context
    result = DecryptionEventVerifier.verify_signed_event(
        signed_event=ctx["signed_event"],
        recipient_certificate=ctx["dsa_cert"],
        root_ca_public_key=ctx["root_ca"].public_key,
        revocation_provider=ctx["rev_provider"],
        expected_document_hash=ctx["signed_event"].event.document_hash,
        expected_watermark_id=ctx["signed_event"].event.watermark_id,
        expected_session_id=ctx["signed_event"].event.session_id,
    )

    assert result.valid is True
    assert result.digest_verified is True
    assert result.signature_verified is True
    assert result.certificate_verified is True
    assert result.key_purpose_verified is True
    assert result.document_binding_verified is True
    assert result.watermark_binding_verified is True
    assert len(result.errors) == 0


@pytest.mark.unit
def test_verify_detects_tampered_document_hash(signed_pki_context):
    ctx = signed_pki_context
    orig = ctx["signed_event"]

    # Tamper with document hash inside event data
    event_dict = orig.event.model_dump()
    event_dict["document_hash"] = "sha3-256:1111111111111111111111111111111111111111111111111111111111111111"
    tampered_event = DecryptionEvent.model_validate(event_dict)

    tampered_signed = SignedDecryptionEvent(
        event=tampered_event,
        canonical_event=orig.canonical_event,
        event_digest=orig.event_digest,
        signature=orig.signature,
        signing_key_id=orig.signing_key_id,
        certificate_id=orig.certificate_id,
        certificate_fingerprint=orig.certificate_fingerprint,
        signed_at=orig.signed_at,
    )

    result = DecryptionEventVerifier.verify_signed_event(
        signed_event=tampered_signed,
        recipient_certificate=ctx["dsa_cert"],
        root_ca_public_key=ctx["root_ca"].public_key,
    )

    assert result.valid is False
    assert result.digest_verified is False
    assert any("Event digest mismatch" in err for err in result.errors)


@pytest.mark.unit
def test_verify_detects_tampered_signature(signed_pki_context):
    ctx = signed_pki_context
    orig = ctx["signed_event"]

    # Invert bits in the signature
    sig_raw = bytearray(orig.get_signature_bytes())
    sig_raw[42] ^= 0xFF
    corrupted_sig_b64 = base64.b64encode(sig_raw).decode("ascii")

    tampered_signed = SignedDecryptionEvent(
        event=orig.event,
        canonical_event=orig.canonical_event,
        event_digest=orig.event_digest,
        signature=corrupted_sig_b64,
        signing_key_id=orig.signing_key_id,
        certificate_id=orig.certificate_id,
        certificate_fingerprint=orig.certificate_fingerprint,
        signed_at=orig.signed_at,
    )

    result = DecryptionEventVerifier.verify_signed_event(
        signed_event=tampered_signed,
        recipient_certificate=ctx["dsa_cert"],
        root_ca_public_key=ctx["root_ca"].public_key,
    )

    assert result.valid is False
    assert result.signature_verified is False
    assert any("digital signature verification failed" in err for err in result.errors)


@pytest.mark.unit
def test_verify_detects_wrong_public_key(signed_pki_context):
    ctx = signed_pki_context
    orig = ctx["signed_event"]

    other_pk, _ = generate_mldsa_keypair()

    result = DecryptionEventVerifier.verify_signed_event(
        signed_event=orig,
        recipient_public_key=other_pk,  # Wrong public key passed
    )

    assert result.valid is False
    assert result.signature_verified is False


@pytest.mark.unit
def test_verify_detects_revoked_certificate(signed_pki_context):
    ctx = signed_pki_context
    orig = ctx["signed_event"]
    cert = ctx["dsa_cert"]

    from tracecrypt.identity.lifecycle import KeyLifecycleManager
    record = KeyLifecycleManager.create_revocation_record(
        serial_number=cert.serial_number,
        key_id="key-revocation-test",
        reason=RevocationReason.KEY_COMPROMISE,
        ca=ctx["root_ca"],
    )
    ctx["rev_provider"].record_revocation(record)

    result = DecryptionEventVerifier.verify_signed_event(
        signed_event=orig,
        recipient_certificate=cert,
        root_ca_public_key=ctx["root_ca"].public_key,
        revocation_provider=ctx["rev_provider"],
    )

    assert result.valid is False
    assert result.certificate_verified is False
    assert any("revoked" in err.lower() for err in result.errors)
