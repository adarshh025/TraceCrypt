"""Typed domain models for TraceCrypt.

These models represent domain entities and contracts. Private keys are explicitly
prohibited from these structures.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.utils.identifiers import (
    BlockID,
    CaseID,
    DeviceID,
    DocumentID,
    RecipientID,
    SessionID,
    TransactionID,
    UserID,
    WatermarkID,
)


class UserRole(str, Enum):
    """Authorized role within TraceCrypt."""
    SENDER = "SENDER"
    RECIPIENT = "RECIPIENT"
    INVESTIGATOR = "INVESTIGATOR"
    VALIDATOR = "VALIDATOR"
    ADMIN = "ADMIN"


class UserStatus(str, Enum):
    """User enrollment status."""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class User(BaseModel):
    """System user entity."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserID
    display_name: str = Field(min_length=1, max_length=100)
    email_hash: str = Field(description="SHA3-256 hash of email for offline privacy")
    organization_unit: str = Field(min_length=1, max_length=100)
    role: UserRole
    created_at: int = Field(description="POSIX microsecond timestamp")
    status: UserStatus = Field(default=UserStatus.ACTIVE)


class Recipient(BaseModel):
    """Authorized document recipient profile."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    recipient_id: RecipientID
    user_id: UserID
    clearance_level: str = Field(default="RESTRICTED")
    active_cert_id: Optional[str] = None
    status: UserStatus = Field(default=UserStatus.ACTIVE)


class Device(BaseModel):
    """Enrolled physical workstation bound to a user."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: DeviceID
    user_id: UserID
    hostname: str = Field(min_length=1, max_length=100)
    fingerprint_hash: str = Field(description="SHA3-256(CPU_ID || Motherboard_UUID || MAC)")
    os_version: str = Field(min_length=1, max_length=100)
    enrolled_at: int = Field(description="POSIX microsecond timestamp")
    is_trusted: bool = Field(default=True)


class KeyReference(BaseModel):
    """Metadata reference to a public post-quantum key."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1)
    owner_user_id: UserID
    algorithm: str = Field(description="ML-KEM-768 or ML-DSA-65")
    key_usage: str = Field(description="DIGITAL_SIGNATURE or KEY_ENCAPSULATION")
    public_key_b64: str = Field(description="Base64-encoded raw public key bytes")
    fingerprint: str = Field(description="SHA3-256 fingerprint of public key")
    created_at: int


class CertificateReference(BaseModel):
    """PQC identity certificate reference issued by offline Root CA."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    cert_id: str
    subject_user_id: UserID
    device_id: DeviceID
    issuer_ca_id: str
    algorithm: str
    public_key_b64: str
    valid_from: int
    valid_until: int
    signature_b64: str
    is_revoked: bool = False


class Document(BaseModel):
    """Document metadata and canonical pre-watermark hash."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: DocumentID
    title: str = Field(min_length=1, max_length=200)
    page_count: int = Field(ge=1)
    canonical_hash: str = Field(description="Pre-watermark original document SHA3-256 digest")
    mime_type: str = Field(default="application/pdf")
    file_size_bytes: int = Field(ge=1)
    sender_id: UserID
    created_at: int


class RecipientPackage(BaseModel):
    """Encapsulated key material for a specific authorized recipient."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    recipient_id: RecipientID
    cert_id: str
    mlkem_ciphertext_b64: str = Field(description="ML-KEM-768 ciphertext (1088 bytes b64)")
    wrapped_doc_key_b64: str = Field(description="AES-256 wrapped symmetric document key")


class Distribution(BaseModel):
    """Multi-recipient encrypted document package."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    distribution_id: str
    document_id: DocumentID
    sender_id: UserID
    document_hash: str
    recipients: List[RecipientPackage] = Field(min_length=1)
    ciphertext_nonce_b64: str
    ciphertext_tag_b64: str
    ciphertext_size_bytes: int
    created_at: int


class DecryptionSession(BaseModel):
    """Ephemeral context established upon recipient decryption."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: SessionID
    recipient_id: RecipientID
    document_id: DocumentID
    device_id: DeviceID
    watermark_id: WatermarkID
    anti_replay_nonce: str
    initiated_at: int
    is_finalized: bool = False


class WatermarkReference(BaseModel):
    """Forensic watermark metadata bound to a session."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    watermark_id: WatermarkID
    session_id: SessionID
    document_id: DocumentID
    recipient_id_hash: str = Field(description="Salted SHA3-256 hash of recipient reference")
    payload_bits_count: int = Field(default=256)
    ecc_type: str = Field(default="REED_SOLOMON_32_16")
    embedding_psnr: Optional[float] = None
    embedding_ssim: Optional[float] = None


class LedgerTransaction(BaseModel):
    """Committed transaction envelope on the permissioned ledger."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    tx_id: TransactionID
    block_id: BlockID
    event_digest: str = Field(description="SHA3-256 of canonical DecryptionEvent")
    canonical_event_json: str
    signature_b64: str = Field(description="ML-DSA-65 digital signature")
    public_key_ref: str
    block_height: int = Field(ge=0)
    committed_at: int


class ForensicCase(BaseModel):
    """Forensic investigation inquiry."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: CaseID
    case_name: str = Field(min_length=1, max_length=200)
    leaked_document_hash: str
    investigator_id: UserID
    opened_at: int
    status: str = Field(default="IN_PROGRESS")


class VerdictEnum(str, Enum):
    """Deterministic 9-state forensic verification verdicts."""
    VERIFIED = "VERIFIED"
    NOT_FOUND = "NOT_FOUND"
    INVALID_WATERMARK = "INVALID_WATERMARK"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    LEDGER_INVALID = "LEDGER_INVALID"
    DOCUMENT_MISMATCH = "DOCUMENT_MISMATCH"
    CORRUPTED_WATERMARK = "CORRUPTED_WATERMARK"
    AMBIGUOUS = "AMBIGUOUS"
    UNVERIFIABLE = "UNVERIFIABLE"


class VerificationResult(BaseModel):
    """Output of the forensic verification engine."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: CaseID
    verdict: VerdictEnum
    verdict_timestamp: int
    extracted_watermark_id: Optional[WatermarkID] = None
    document_hash_matched: bool = False
    signature_verified: bool = False
    ledger_verified: bool = False
    attributed_recipient_id: Optional[RecipientID] = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    diagnostic_trace: List[str] = Field(default_factory=list)


class ForensicReport(BaseModel):
    """Immutable forensic evidence and attribution report."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str
    case_id: CaseID
    verification_result: VerificationResult
    generated_at: int
    report_digest: str = Field(description="SHA3-256 of canonical verification result")
    investigator_notes: str = ""
