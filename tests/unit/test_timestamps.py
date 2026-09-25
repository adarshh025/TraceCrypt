"""Unit tests for timestamp policy and utilities."""

import pytest

from tracecrypt.errors import ValidationError
from tracecrypt.utils.timestamps import TimestampPolicy, utc_now_iso, utc_now_micros


@pytest.mark.unit
def test_now_micros():
    t1 = utc_now_micros()
    assert isinstance(t1, int)
    assert t1 > 1_700_000_000_000_000  # Epoch beyond late 2023


@pytest.mark.unit
def test_now_iso():
    iso = utc_now_iso()
    assert isinstance(iso, str)
    assert iso.endswith("Z")
    assert "T" in iso


@pytest.mark.unit
def test_micros_iso_roundtrip():
    micros = 1_720_000_000_123_456
    iso = TimestampPolicy.micros_to_iso(micros)
    roundtrip = TimestampPolicy.iso_to_micros(iso)
    assert roundtrip == micros


@pytest.mark.unit
def test_non_utc_timestamp_rejection():
    # Naive timestamp without timezone
    with pytest.raises(ValidationError, match="UTC"):
        TimestampPolicy.iso_to_micros("2026-09-25T14:30:00")


@pytest.mark.unit
def test_freshness_validation():
    now_micros = utc_now_micros()
    # Past timestamp within reasonable bounds should pass
    TimestampPolicy.validate_freshness(now_micros - 1_000_000, max_skew_seconds=60)
    # Future timestamp within skew should pass
    TimestampPolicy.validate_freshness(now_micros + 10_000_000, max_skew_seconds=60)
    # Excessive future timestamp (> 60s) should fail
    with pytest.raises(ValidationError, match="future"):
        TimestampPolicy.validate_freshness(now_micros + 120_000_000, max_skew_seconds=60)
