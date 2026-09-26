"""Unit tests for DecryptionEvent and SignedDecryptionEvent schemas, canonicalization, and serialization."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from tracecrypt.errors import ValidationError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.utils.identifiers import (
    DeviceID,
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


def create_sample_event():
    return DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID("evt-0123456789abcdef0123456789abcdef"),
        document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
        distribution_id=DistributionID("dst-0123456789abcdef0123456789abcdef"),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=RecipientID("rcp-0123456789abcdef0123456789abcdef"),
        recipient_key_id="key-rcp-0123456789abcdef0123456789abcdef-dsa-v1",
        recipient_certificate_id="crt-0123456789abcdef0123456789abcdef",
        device_id=DeviceID("dev-0123456789abcdef0123456789abcdef"),
        session_id=SessionID("ses-0123456789abcdef0123456789abcdef"),
        watermark_id=WatermarkID("wm-0123456789abcdef0123456789abcdef"),
        watermark_version=1,
        anti_replay_nonce="f8a7c2b3d4e5f6011223344556677889",
        timestamp=1727280000000000,
        rendered_watermarked_artifact_hash="sha3-256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        pqc_algorithms=PQCAlgorithms(),
    )


@pytest.mark.unit
def test_valid_event_creation():
    event = create_sample_event()
    assert event.event_version == "1.0.0"
    assert event.schema_version == "1.0.0"
    assert event.protocol_version == "1.0.0"
    assert event.event_type == "DECRYPTION_ATTRIBUTION"
    assert str(event.event_id).startswith("evt-")
    assert str(event.document_id).startswith("doc-")
    assert str(event.distribution_id).startswith("dst-")
    assert event.watermark_version == 1


@pytest.mark.unit
def test_canonical_bytes_determinism():
    event1 = create_sample_event()
    event2 = create_sample_event()

    bytes1 = event1.to_canonical_bytes()
    bytes2 = event2.to_canonical_bytes()

    assert bytes1 == bytes2
    assert isinstance(bytes1, bytes)
    assert b"evt-0123456789abcdef0123456789abcdef" in bytes1

    digest1 = event1.compute_event_digest()
    digest2 = event2.compute_event_digest()
    assert digest1 == digest2
    assert digest1.startswith("sha3-256:")
    assert len(digest1) == 9 + 64

    raw_bytes = event1.compute_event_digest_bytes()
    assert len(raw_bytes) == 32
    assert raw_bytes == bytes.fromhex(digest1.split(":")[1])


@pytest.mark.unit
def test_event_schema_forbidden_extra_fields():
    data = create_sample_event().model_dump(mode="json")
    data["unauthorized_injected_field"] = "malicious_payload"

    with pytest.raises(PydanticValidationError):
        DecryptionEvent.model_validate(data)


@pytest.mark.unit
def test_event_invalid_hash_rejection():
    data = create_sample_event().model_dump(mode="json")
    data["document_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    with pytest.raises(ValidationError, match="sha3-256:"):
        DecryptionEvent.model_validate(data)


@pytest.mark.unit
def test_signed_decryption_event_container():
    event = create_sample_event()
    canon_bytes = event.to_canonical_bytes()
    digest = event.compute_event_digest()
    fake_sig_bytes = b"\x42" * 3309
    import base64
    sig_b64 = base64.b64encode(fake_sig_bytes).decode("ascii")

    signed_event = SignedDecryptionEvent(
        event=event,
        canonical_event=canon_bytes.decode("utf-8"),
        event_digest=digest,
        signature=sig_b64,
        signing_key_id="key-rcp-0123456789abcdef0123456789abcdef-dsa-v1",
        certificate_id="crt-0123456789abcdef0123456789abcdef",
        certificate_fingerprint="mldsa65:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        signed_at=1727280000000000,
        ledger_transaction_id="tx-0123456789abcdef0123456789abcdef",
    )

    assert signed_event.get_signature_bytes() == fake_sig_bytes
    assert len(signed_event.get_event_digest_bytes()) == 32
    assert signed_event.ledger_transaction_id == "tx-0123456789abcdef0123456789abcdef"

    # Canonical round-trip
    json_str = signed_event.to_canonical_json()
    reparsed = SignedDecryptionEvent.from_canonical_json(json_str)
    assert reparsed.event.event_id == event.event_id
    assert reparsed.event_digest == signed_event.event_digest


@pytest.mark.unit
def test_signed_decryption_event_invalid_signature_length():
    event = create_sample_event()
    canon_bytes = event.to_canonical_bytes()
    digest = event.compute_event_digest()
    import base64
    invalid_sig_b64 = base64.b64encode(b"\x00" * 100).decode("ascii")

    with pytest.raises(ValidationError, match="Invalid ML-DSA-65 signature length"):
        SignedDecryptionEvent(
            event=event,
            canonical_event=canon_bytes.decode("utf-8"),
            event_digest=digest,
            signature=invalid_sig_b64,
            signing_key_id="key-test",
            certificate_id="crt-test",
            certificate_fingerprint="mldsa65:test",
            signed_at=1727280000000000,
        )
