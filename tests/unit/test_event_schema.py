"""Unit tests for DecryptionEvent schema and canonical digest generation."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from tracecrypt.errors import ValidationError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.utils.identifiers import (
    DeviceID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


def create_sample_event():
    return DecryptionEvent(
        event_id=EventID("evt-0123456789abcdef0123456789abcdef"),
        document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=RecipientID("rcp-0123456789abcdef0123456789abcdef"),
        device_id=DeviceID("dev-0123456789abcdef0123456789abcdef"),
        session_id=SessionID("ses-0123456789abcdef0123456789abcdef"),
        watermark_id=WatermarkID("wm-0123456789abcdef0123456789abcdef"),
        anti_replay_nonce="f8a7c2b3d4e5f6011223344556677889",
        timestamp=1727280000000000,
        pqc_algorithms=PQCAlgorithms(),
    )


@pytest.mark.unit
def test_valid_event_creation():
    event = create_sample_event()
    assert event.schema_version == "1.0.0"
    assert event.protocol_version == "1.0.0"
    assert str(event.event_id).startswith("evt-")
    assert str(event.document_id).startswith("doc-")


@pytest.mark.unit
def test_canonical_bytes_and_digest():
    event = create_sample_event()
    canon_bytes = event.to_canonical_bytes()
    assert isinstance(canon_bytes, bytes)
    assert b"evt-0123456789abcdef0123456789abcdef" in canon_bytes

    digest = event.compute_event_digest()
    assert digest.startswith("sha3-256:")
    assert len(digest) == 9 + 64


@pytest.mark.unit
def test_forbidden_extra_fields():
    """Verify that arbitrary extra fields are strictly forbidden."""
    valid_data = create_sample_event().model_dump(mode="json")
    valid_data["unauthorized_field"] = "malicious_payload"

    with pytest.raises(PydanticValidationError):
        DecryptionEvent.model_validate(valid_data)


@pytest.mark.unit
def test_invalid_hash_format_rejection():
    valid_data = create_sample_event().model_dump(mode="json")
    # Missing 'sha3-256:' prefix
    valid_data["document_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    with pytest.raises(ValidationError, match="sha3-256:"):
        DecryptionEvent.model_validate(valid_data)
