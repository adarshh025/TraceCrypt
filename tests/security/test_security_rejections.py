"""Security regression tests: verifies that malformed inputs and boundary violations fail closed."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from tracecrypt.config.settings import AirGapConfig, AppMode, ConfigurationError, Settings
from tracecrypt.errors import CanonicalizationError, ValidationError
from tracecrypt.event.canonicalizer import canonical_hash, canonicalize
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.utils.identifiers import DeviceID, DocumentID, EventID, RecipientID, SessionID, WatermarkID
from tracecrypt.utils.timestamps import TimestampPolicy, utc_now_micros


@pytest.mark.security
def test_malformed_event_fails_closed():
    """Verify that an event missing required security fields fails closed."""
    incomplete_data = {
        "event_id": "evt-0123456789abcdef0123456789abcdef",
        "document_id": "doc-0123456789abcdef0123456789abcdef",
    }
    with pytest.raises(PydanticValidationError):
        DecryptionEvent.model_validate(incomplete_data)


@pytest.mark.security
def test_unknown_event_fields_rejected():
    """Verify that injected unexpected fields fail closed."""
    valid_event = DecryptionEvent(
        event_id=EventID("evt-0123456789abcdef0123456789abcdef"),
        document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=RecipientID("rcp-0123456789abcdef0123456789abcdef"),
        device_id=DeviceID("dev-0123456789abcdef0123456789abcdef"),
        session_id=SessionID("ses-0123456789abcdef0123456789abcdef"),
        watermark_id=WatermarkID("wm-0123456789abcdef0123456789abcdef"),
        anti_replay_nonce="f8a7c2b3d4e5f6011223344556677889",
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    raw_dict = valid_event.model_dump(mode="json")
    raw_dict["injected_bypass"] = "DROP ALL DEFENSES"

    with pytest.raises(PydanticValidationError):
        DecryptionEvent.model_validate(raw_dict)


@pytest.mark.security
def test_future_timestamp_rejected():
    """Verify that events with timestamp far in the future fail freshness check."""
    future_micros = utc_now_micros() + 300_000_000  # 5 minutes in future
    with pytest.raises(ValidationError, match="future"):
        TimestampPolicy.validate_freshness(future_micros, max_skew_seconds=60)


@pytest.mark.security
def test_nondeterministic_serialization_defense():
    """Verify that two semantically identical dictionaries with randomized keys yield identical canonical hash."""
    d1 = {"z": 10, "m": {"b": 2, "a": 1}, "a": "first"}
    d2 = {"a": "first", "z": 10, "m": {"a": 1, "b": 2}}

    h1 = canonical_hash(d1)
    h2 = canonical_hash(d2)

    assert h1 == h2


@pytest.mark.security
def test_nan_float_cannot_be_canonicalized():
    """Verify that floating point NaN fails canonicalization (cannot be signed)."""
    with pytest.raises(CanonicalizationError):
        canonicalize({"weight": float("nan")})


@pytest.mark.security
def test_production_airgap_violation_config():
    """Verify that disabling airgap in production fails configuration validation."""
    with pytest.raises(ConfigurationError):
        Settings(
            mode=AppMode.PRODUCTION,
            airgap=AirGapConfig(enforce_airgap=False),
        ).validate_security_invariants()
