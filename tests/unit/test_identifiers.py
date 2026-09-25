"""Unit tests for TraceCrypt typed identifiers."""

import pytest

from tracecrypt.errors import ValidationError
from tracecrypt.utils.identifiers import (
    BlockID,
    CaseID,
    DeviceID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    TransactionID,
    UserID,
    WatermarkID,
)

ALL_ID_CLASSES = [
    (DocumentID, "doc-"),
    (UserID, "usr-"),
    (RecipientID, "rcp-"),
    (DeviceID, "dev-"),
    (SessionID, "ses-"),
    (WatermarkID, "wm-"),
    (EventID, "evt-"),
    (TransactionID, "tx-"),
    (BlockID, "blk-"),
    (CaseID, "cas-"),
]


@pytest.mark.unit
@pytest.mark.parametrize("cls,prefix", ALL_ID_CLASSES)
def test_valid_identifier_creation(cls, prefix):
    valid_hex = "0123456789abcdef0123456789abcdef"
    ident = cls(f"{prefix}{valid_hex}")
    assert str(ident) == f"{prefix}{valid_hex}"
    assert ident.startswith(prefix)


@pytest.mark.unit
@pytest.mark.parametrize("cls,prefix", ALL_ID_CLASSES)
def test_from_raw_hex(cls, prefix):
    raw_hex = "abcdef0123456789abcdef0123456789"
    ident = cls.from_raw_hex(raw_hex)
    assert ident == f"{prefix}{raw_hex}"


@pytest.mark.unit
@pytest.mark.parametrize("cls,prefix", ALL_ID_CLASSES)
def test_accidental_whitespace_rejection(cls, prefix):
    valid_hex = "0123456789abcdef0123456789abcdef"
    with pytest.raises(ValidationError, match="whitespace"):
        cls(f" {prefix}{valid_hex}")
    with pytest.raises(ValidationError, match="whitespace"):
        cls(f"{prefix}{valid_hex} ")


@pytest.mark.unit
@pytest.mark.parametrize("cls,prefix", ALL_ID_CLASSES)
def test_invalid_prefix_rejection(cls, prefix):
    valid_hex = "0123456789abcdef0123456789abcdef"
    with pytest.raises(ValidationError, match="prefix"):
        cls(f"bad-{valid_hex}")


@pytest.mark.unit
@pytest.mark.parametrize("cls,prefix", ALL_ID_CLASSES)
def test_malformed_length_rejection(cls, prefix):
    # Too short
    with pytest.raises(ValidationError):
        cls(f"{prefix}12345")
    # Non-hex characters
    with pytest.raises(ValidationError):
        cls(f"{prefix}0123456789abcdef0123456789abcdeg")
