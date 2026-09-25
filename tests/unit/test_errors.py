"""Unit tests for TraceCrypt exception hierarchy."""

import pytest

from tracecrypt.errors import (
    AirGapViolation,
    CanonicalizationError,
    ConfigurationError,
    CryptographicError,
    ForensicError,
    IntegrityError,
    LedgerError,
    SecurityError,
    StorageError,
    TraceCryptError,
    ValidationError,
    VerificationError,
    WatermarkError,
)

ALL_EXCEPTIONS = [
    ConfigurationError,
    ValidationError,
    CryptographicError,
    CanonicalizationError,
    SecurityError,
    StorageError,
    LedgerError,
    WatermarkError,
    ForensicError,
    AirGapViolation,
    IntegrityError,
    VerificationError,
]


@pytest.mark.unit
@pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
def test_all_inherit_from_base(exc_cls):
    err = exc_cls("Diagnostic error message", details={"code": 401, "target": "component_x"})
    assert isinstance(err, TraceCryptError)
    assert "Diagnostic error message" in str(err)
    assert "code=401" in str(err)
    assert err.details["target"] == "component_x"


@pytest.mark.unit
def test_airgap_violation_is_security_error():
    err = AirGapViolation("Network blocked")
    assert isinstance(err, SecurityError)
    assert isinstance(err, TraceCryptError)
