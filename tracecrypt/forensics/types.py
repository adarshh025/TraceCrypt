"""Strongly-typed data models for the TraceCrypt Forensic Investigation Subsystem.

Defines:
- ForensicEvidence: immutable record of ingested leaked document
- PageForensicResult: per-page watermark extraction and ECC telemetry
- WatermarkForensicAnalysis: aggregated multi-page watermark analysis
- LedgerVerificationDetails: cryptographic ledger and Merkle proof verification telemetry
- IdentityVerificationDetails: offline PKI and recipient signature verification telemetry
- DocumentBindingDetails: document hash and watermark context binding telemetry
- ChainOfCustodyEntry: cryptographically chained forensic audit log
- ForensicInvestigation: complete immutable record of an investigation
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.models.domain import CaseID, RecipientID, UserID, VerdictEnum
from tracecrypt.utils.identifiers import WatermarkID
from tracecrypt.watermark.types import ExtractionStatus

ForensicVerdict = VerdictEnum


class CustodyAction(str, Enum):
    """Deterministic lifecycle actions for forensic evidence chain of custody."""
    INGESTED = "INGESTED"
    NORMALIZED = "NORMALIZED"
    ANALYZED = "ANALYZED"
    VERIFIED = "VERIFIED"
    EXPORTED = "EXPORTED"


class ChainOfCustodyEntry(BaseModel):
    """Cryptographically chained record of a forensic operation on evidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence_index: int = Field(ge=0, description="Monotonically increasing log sequence number")
    action: CustodyAction
    actor_id: str = Field(description="Identifier of investigator, workstation, or system")
    timestamp: int = Field(ge=0, description="UTC microseconds timestamp of action")
    evidence_hash: str = Field(description="SHA3-256 hash of evidence artifact")
    previous_action_hash: str = Field(description="SHA3-256 hash of preceding custody entry")
    action_hash: str = Field(description="SHA3-256 hash committing to this custody entry")
    details: Dict[str, Any] = Field(default_factory=dict)


class ForensicEvidence(BaseModel):
    """Immutable metadata and cryptographic commitment of ingested evidence artifact."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(description="Unique deterministic or random evidence ID")
    sha3_256: str = Field(description="Formatted SHA3-256 digest of original evidence bytes")
    filename: str = Field(description="Source file name (without path) for reference")
    mime_type: str = Field(description="Detected MIME type (application/pdf, image/png, etc.)")
    size_bytes: int = Field(ge=0, description="Exact byte size of raw evidence artifact")
    page_count: int = Field(ge=1, description="Number of pages or frames in evidence")
    ingested_at: int = Field(ge=0, description="UTC microseconds timestamp of ingestion")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional non-PII case metadata")


class PageForensicResult(BaseModel):
    """Detailed forensic analysis record for a single page of evidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    page_number: int = Field(ge=1, description="1-indexed page number")
    status: ExtractionStatus
    detected: bool = Field(description="True if frequency-domain watermark signal was detected")
    decoded: bool = Field(description="True if Reed-Solomon decoded and CRC16 verified")
    correlation_score: float = Field(default=0.0, description="Blind spread-spectrum correlation metric")
    ecc_corrections: int = Field(default=0, ge=0, description="Number of RS(32,16) symbol corrections")
    watermark_id: Optional[WatermarkID] = None
    session_tag: Optional[str] = Field(default=None, description="Hex representation of 8-byte session tag")
    document_binding: Optional[str] = Field(default=None, description="Hex representation of 5-byte document binding")
    diagnostics: Dict[str, Any] = Field(default_factory=dict)


class WatermarkForensicAnalysis(BaseModel):
    """Aggregated multi-page watermark detection and consistency analysis."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    overall_status: ExtractionStatus
    pages_analyzed: int = Field(ge=0)
    pages_detected: int = Field(ge=0)
    pages_decoded: int = Field(ge=0)
    pages_corrupted: int = Field(ge=0)
    total_ecc_corrections: int = Field(ge=0)
    average_correlation: float = Field(default=0.0)
    consensus_watermark_id: Optional[WatermarkID] = None
    consensus_session_tag: Optional[str] = None
    consensus_document_binding: Optional[str] = None
    distinct_watermark_ids: List[str] = Field(default_factory=list)
    has_cross_page_conflict: bool = False
    diagnostics: Dict[str, Any] = Field(default_factory=dict)


class LedgerVerificationDetails(BaseModel):
    """Cryptographic verification record of ledger transaction and BFT consensus state."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    block_height: int = Field(ge=0)
    block_hash: str
    merkle_proof_valid: bool = False
    block_valid: bool = False
    chain_linkage_valid: bool = False
    commit_certificate_valid: bool = False
    quorum_satisfied: bool = False
    validator_count: int = Field(ge=0)
    verified_validators: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class IdentityVerificationDetails(BaseModel):
    """Cryptographic verification record of recipient identity and ML-DSA-65 signature."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    recipient_id: Optional[RecipientID] = None
    certificate_id: Optional[str] = None
    certificate_valid: bool = False
    key_purpose_valid: bool = False
    not_revoked: bool = False
    canonical_event_digest: Optional[str] = None
    signature_verified: bool = False
    signing_algorithm: str = "ML-DSA-65"
    errors: List[str] = Field(default_factory=list)


class DocumentBindingDetails(BaseModel):
    """Verification record of cryptographic binding between watermark and document."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    binding_verified: bool = False
    event_document_hash: str
    expected_document_hash: Optional[str] = None
    document_hash_matched: bool = False
    watermark_binding_matched: bool = False
    errors: List[str] = Field(default_factory=list)


class ForensicInvestigation(BaseModel):
    """Complete, self-contained, immutable forensic investigation artifact."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: CaseID
    case_name: str
    investigator_id: UserID
    evidence: ForensicEvidence
    watermark_analysis: WatermarkForensicAnalysis
    page_results: List[PageForensicResult]
    ledger_details: Optional[LedgerVerificationDetails] = None
    identity_details: Optional[IdentityVerificationDetails] = None
    document_binding_details: Optional[DocumentBindingDetails] = None
    verdict: VerdictEnum
    verdict_precedence_rank: int = Field(ge=1, le=9)
    diagnostic_trace: List[str] = Field(default_factory=list)
    chain_of_custody: List[ChainOfCustodyEntry] = Field(default_factory=list)
    investigated_at: int = Field(ge=0)
    report_digest: Optional[str] = None
