"""Unit tests for domain models and data contracts."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from tracecrypt.models.domain import (
    Document,
    User,
    UserRole,
    UserStatus,
    VerificationResult,
    VerdictEnum,
)
from tracecrypt.utils.identifiers import CaseID, DocumentID, UserID


@pytest.mark.unit
def test_user_model_valid():
    user = User(
        user_id=UserID("usr-0123456789abcdef0123456789abcdef"),
        display_name="Security Analyst Alice",
        email_hash="sha3-256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        organization_unit="Forensics Division",
        role=UserRole.INVESTIGATOR,
        created_at=1727280000000000,
        status=UserStatus.ACTIVE,
    )
    assert user.role == UserRole.INVESTIGATOR
    assert user.status == UserStatus.ACTIVE


@pytest.mark.unit
def test_document_model_constraints():
    # Valid document
    doc = Document(
        document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
        title="Operation Blueprint",
        page_count=12,
        canonical_hash="sha3-256:abcd0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
        mime_type="application/pdf",
        file_size_bytes=1048576,
        sender_id=UserID("usr-0123456789abcdef0123456789abcdef"),
        created_at=1727280000000000,
    )
    assert doc.page_count == 12

    # Zero or negative page count rejected
    with pytest.raises(PydanticValidationError):
        Document(
            document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
            title="Invalid Doc",
            page_count=0,
            canonical_hash="sha3-256:abcd0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab",
            file_size_bytes=100,
            sender_id=UserID("usr-0123456789abcdef0123456789abcdef"),
            created_at=1727280000000000,
        )


@pytest.mark.unit
def test_verification_result_all_verdicts():
    for verdict in VerdictEnum:
        result = VerificationResult(
            case_id=CaseID("cas-0123456789abcdef0123456789abcdef"),
            verdict=verdict,
            verdict_timestamp=1727280000000000,
            confidence_score=0.98 if verdict == VerdictEnum.VERIFIED else 0.0,
        )
        assert result.verdict == verdict
