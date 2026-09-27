"""Forensic investigation and verification subsystem for TraceCrypt.

Phase 8 implements:
- EvidenceIngestion: read-only evidence loading and SHA3-256 digest commitment
- DocumentNormalizer: deterministic normalization for PDFs and raster images
- ForensicExtractionEngine: blind frequency-domain watermark extraction and multi-page analysis
- ForensicCryptographicVerifier: 12-point offline cryptographic verification pipeline
- VerdictEvaluator: deterministic 9-state verdict engine and precedence evaluator
- ForensicProofBundle: standalone verifiable .tcproof bundle export and import
- StandaloneProofVerifier: independent cryptographic verification without workstation state
- ForensicReportGenerator: tamper-evident JSON and PDF forensic reporting
- ChainOfCustody: cryptographic hash-chained audit logging
- ForensicInvestigationEngine: master end-to-end attribution coordinator
- ForensicAttributionLink: legacy bridge connecting extracted payloads to ledger events
"""

from tracecrypt.forensics.custody import ChainOfCustody
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.extraction import ForensicExtractionEngine
from tracecrypt.forensics.ingestion import EvidenceIngestion
from tracecrypt.forensics.normalization import DocumentNormalizer
from tracecrypt.forensics.preparation import ForensicAttributionLink
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.report import ForensicReportGenerator
from tracecrypt.forensics.standalone_verifier import (
    StandaloneProofVerifier,
    StandaloneVerificationResult,
)
from tracecrypt.forensics.types import (
    ChainOfCustodyEntry,
    CustodyAction,
    DocumentBindingDetails,
    ForensicEvidence,
    ForensicInvestigation,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
    PageForensicResult,
    WatermarkForensicAnalysis,
)
from tracecrypt.forensics.verdict import VERDICT_PRECEDENCE_MAP, VerdictEvaluator
from tracecrypt.forensics.verifier import ForensicCryptographicVerifier
from tracecrypt.models.domain import VerdictEnum

ForensicVerdict = VerdictEnum

__all__ = [
    "ChainOfCustody",
    "ChainOfCustodyEntry",
    "CustodyAction",
    "DocumentBindingDetails",
    "DocumentNormalizer",
    "EvidenceIngestion",
    "ForensicAttributionLink",
    "ForensicCryptographicVerifier",
    "ForensicEvidence",
    "ForensicExtractionEngine",
    "ForensicInvestigation",
    "ForensicInvestigationEngine",
    "ForensicProofBundle",
    "ForensicReportGenerator",
    "ForensicVerdict",
    "IdentityVerificationDetails",
    "LedgerVerificationDetails",
    "PageForensicResult",
    "StandaloneProofVerifier",
    "StandaloneVerificationResult",
    "VERDICT_PRECEDENCE_MAP",
    "VerdictEnum",
    "VerdictEvaluator",
    "WatermarkForensicAnalysis",
]
