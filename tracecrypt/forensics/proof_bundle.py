"""Standalone Cryptographic Forensic Proof Bundle (.tcproof).

Encapsulates all cryptographic evidence, Merkle inclusion proofs, block headers,
commit certificates, recipient certificates, and verification telemetry required
for independent verification without workstation or ledger database access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.forensics.types import (
    ChainOfCustodyEntry,
    DocumentBindingDetails,
    ForensicEvidence,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
    PageForensicResult,
)
from tracecrypt.models.domain import VerdictEnum
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.types import WatermarkPayload


class ForensicProofBundle(BaseModel):
    """Self-contained, tamper-evident cryptographic proof bundle."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle_version: str = Field(default="1.0.0")
    case_id: str
    created_at: int = Field(ge=0)
    evidence: ForensicEvidence
    extracted_watermark: Optional[Dict[str, Any]] = None
    page_results: List[Dict[str, Any]] = Field(default_factory=list)
    ledger_proof: Optional[Dict[str, Any]] = None
    recipient_certificate: Optional[Dict[str, Any]] = None
    root_ca_public_key_b64: Optional[str] = None
    ledger_details: Optional[LedgerVerificationDetails] = None
    identity_details: Optional[IdentityVerificationDetails] = None
    binding_details: Optional[DocumentBindingDetails] = None
    verdict: VerdictEnum
    verdict_precedence_rank: int
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
    bundle_digest: str = Field(description="SHA3-256 hash of canonical proof content")

    @classmethod
    def compute_bundle_digest(cls, data_dict: Dict[str, Any]) -> str:
        """Compute deterministic SHA3-256 digest over canonical bundle dictionary."""
        payload = {k: v for k, v in data_dict.items() if k != "bundle_digest"}
        canonical_bytes = canonicalize(payload)
        return Hasher.digest_bytes(canonical_bytes, HashAlgorithm.SHA3_256.value).formatted

    @classmethod
    def create(
        cls,
        case_id: str,
        evidence: ForensicEvidence,
        verdict: VerdictEnum,
        verdict_precedence_rank: int,
        extracted_watermark: Optional[Dict[str, Any]] = None,
        page_results: Optional[List[PageForensicResult]] = None,
        ledger_proof: Optional[Dict[str, Any]] = None,
        recipient_certificate: Optional[Dict[str, Any]] = None,
        root_ca_public_key_b64: Optional[str] = None,
        ledger_details: Optional[LedgerVerificationDetails] = None,
        identity_details: Optional[IdentityVerificationDetails] = None,
        binding_details: Optional[DocumentBindingDetails] = None,
        chain_of_custody: Optional[List[ChainOfCustodyEntry]] = None,
        created_at: Optional[int] = None,
    ) -> ForensicProofBundle:
        """Construct a new ForensicProofBundle and compute its cryptographic digest."""
        now = created_at if created_at is not None else utc_now_micros()
        pages_dump = [p.model_dump() for p in (page_results or [])]
        custody_dump = [c.model_dump() for c in (chain_of_custody or [])]

        candidate = {
            "bundle_version": "1.0.0",
            "case_id": case_id,
            "created_at": now,
            "evidence": evidence.model_dump(),
            "extracted_watermark": extracted_watermark,
            "page_results": pages_dump,
            "ledger_proof": ledger_proof,
            "recipient_certificate": recipient_certificate,
            "root_ca_public_key_b64": root_ca_public_key_b64,
            "ledger_details": ledger_details.model_dump() if ledger_details else None,
            "identity_details": identity_details.model_dump() if identity_details else None,
            "binding_details": binding_details.model_dump() if binding_details else None,
            "verdict": verdict.value,
            "verdict_precedence_rank": verdict_precedence_rank,
            "chain_of_custody": custody_dump,
        }

        digest = cls.compute_bundle_digest(candidate)
        candidate["bundle_digest"] = digest

        return cls.model_validate(candidate)

    def to_canonical_json(self) -> str:
        """Export as canonical RFC 8785 JSON string."""
        return canonicalize(self.model_dump()).decode("utf-8")

    def save(self, output_path: str | Path) -> Path:
        """Save bundle to disk with .tcproof extension."""
        p = Path(output_path)
        if not str(p).endswith(".tcproof"):
            p = p.with_suffix(".tcproof")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.model_dump(), indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, file_path: str | Path) -> ForensicProofBundle:
        """Load bundle from disk and validate Pydantic model structure."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Proof bundle not found: {p}")
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.model_validate(data)

    load_file = load

    @classmethod
    def from_investigation(
        cls,
        investigation: Any,
        extracted_watermark: Optional[Dict[str, Any]] = None,
        ledger_proof: Optional[Dict[str, Any]] = None,
        recipient_certificate: Optional[Dict[str, Any]] = None,
        root_ca_public_key_b64: Optional[str] = None,
    ) -> ForensicProofBundle:
        """Construct a ForensicProofBundle directly from a ForensicInvestigation."""
        wm_dict = extracted_watermark
        if wm_dict is None and investigation.watermark_analysis.consensus_watermark_id:
            wmid_str = str(investigation.watermark_analysis.consensus_watermark_id)
            raw_wmid = bytes.fromhex(wmid_str.replace("wm-", ""))
            s_tag = bytes.fromhex(investigation.watermark_analysis.consensus_session_tag or "00" * 8)
            doc_bind = bytes.fromhex(investigation.watermark_analysis.consensus_document_binding or "00" * 5)
            pre_crc = bytes([1]) + raw_wmid + s_tag + doc_bind
            crc = WatermarkPayload.compute_crc16(pre_crc)
            wm_dict = {
                "version": 1,
                "watermark_id": wmid_str,
                "session_tag": s_tag.hex(),
                "document_binding": doc_bind.hex(),
                "checksum": crc,
            }

        return cls.create(
            case_id=str(investigation.case_id),
            evidence=investigation.evidence,
            verdict=investigation.verdict,
            verdict_precedence_rank=investigation.verdict_precedence_rank,
            extracted_watermark=wm_dict,
            page_results=investigation.page_results,
            ledger_proof=ledger_proof,
            recipient_certificate=recipient_certificate,
            root_ca_public_key_b64=root_ca_public_key_b64,
            ledger_details=investigation.ledger_details,
            identity_details=investigation.identity_details,
            binding_details=investigation.document_binding_details,
            chain_of_custody=investigation.chain_of_custody,
            created_at=investigation.investigated_at,
        )
