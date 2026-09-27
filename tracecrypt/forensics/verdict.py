"""Deterministic 9-State Forensic Verdict Engine and Precedence Model.

Enforces:
1. Exactly 9 distinct verdicts defined by VerdictEnum.
2. Strict, reproducible verdict precedence without heuristic overrides.
3. Transparent failure mapping for every stage of the forensic verification pipeline.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from tracecrypt.forensics.types import (
    DocumentBindingDetails,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
    WatermarkForensicAnalysis,
)
from tracecrypt.models.domain import VerdictEnum
from tracecrypt.watermark.types import ExtractionStatus

# Explicit deterministic precedence order (1 = highest priority failure condition)
VERDICT_PRECEDENCE_MAP = {
    VerdictEnum.AMBIGUOUS: 1,
    VerdictEnum.UNVERIFIABLE: 2,
    VerdictEnum.CORRUPTED_WATERMARK: 3,
    VerdictEnum.INVALID_WATERMARK: 4,
    VerdictEnum.NOT_FOUND: 5,
    VerdictEnum.LEDGER_INVALID: 6,
    VerdictEnum.SIGNATURE_INVALID: 7,
    VerdictEnum.DOCUMENT_MISMATCH: 8,
    VerdictEnum.VERIFIED: 9,
}


class VerdictEvaluator:
    """Evaluates cryptographic telemetry against strict deterministic verdict rules."""

    @classmethod
    def evaluate(
        cls,
        analysis: WatermarkForensicAnalysis,
        ledger_details: Optional[LedgerVerificationDetails],
        identity_details: Optional[IdentityVerificationDetails],
        binding_details: Optional[DocumentBindingDetails],
    ) -> Tuple[VerdictEnum, int, List[str]]:
        """Evaluate complete investigation state and return (verdict, precedence_rank, trace).

        Returns:
            Tuple of:
            - Final VerdictEnum (one of the 9)
            - Deterministic precedence integer (1 to 9)
            - List of diagnostic trace messages justifying the verdict.
        """
        trace: List[str] = []

        # 1. Multi-page Ambiguity Check
        if analysis.has_cross_page_conflict or analysis.overall_status == ExtractionStatus.AMBIGUOUS:
            trace.append(
                f"[VERDICT RULE 1: AMBIGUOUS] Multiple conflicting watermark identities detected "
                f"across document pages: {analysis.distinct_watermark_ids}"
            )
            return VerdictEnum.AMBIGUOUS, VERDICT_PRECEDENCE_MAP[VerdictEnum.AMBIGUOUS], trace

        # 2. Unverifiable Signal Check (No watermark signal above noise floor)
        if analysis.overall_status == ExtractionStatus.NOT_DETECTED or analysis.pages_detected == 0:
            trace.append(
                "[VERDICT RULE 2: UNVERIFIABLE] No recoverable watermark signal detected in artifact."
            )
            return VerdictEnum.UNVERIFIABLE, VERDICT_PRECEDENCE_MAP[VerdictEnum.UNVERIFIABLE], trace

        # 3. Corrupted Watermark Check (Signal present, but ECC uncorrectable)
        if analysis.overall_status == ExtractionStatus.CORRUPTED:
            trace.append(
                "[VERDICT RULE 3: CORRUPTED_WATERMARK] Watermark signal detected, but symbol corruption "
                "exceeds Reed-Solomon RS(32, 16) error correction capacity."
            )
            return VerdictEnum.CORRUPTED_WATERMARK, VERDICT_PRECEDENCE_MAP[VerdictEnum.CORRUPTED_WATERMARK], trace

        # 4. Invalid Watermark Check (CRC16 failure or structural defect)
        if analysis.overall_status == ExtractionStatus.INVALID or analysis.consensus_watermark_id is None:
            trace.append(
                "[VERDICT RULE 4: INVALID_WATERMARK] Candidate watermark payload is structurally malformed "
                "or failed CRC-16 checksum."
            )
            return VerdictEnum.INVALID_WATERMARK, VERDICT_PRECEDENCE_MAP[VerdictEnum.INVALID_WATERMARK], trace

        # 5. Ledger Transaction Existence (NOT_FOUND)
        if ledger_details is None:
            trace.append(
                f"[VERDICT RULE 5: NOT_FOUND] Valid WatermarkID '{analysis.consensus_watermark_id}' recovered, "
                f"but no corresponding transaction was found on the committed ledger."
            )
            return VerdictEnum.NOT_FOUND, VERDICT_PRECEDENCE_MAP[VerdictEnum.NOT_FOUND], trace

        # 6. Ledger Integrity & BFT Commit Check (LEDGER_INVALID)
        if (
            not ledger_details.merkle_proof_valid
            or not ledger_details.block_valid
            or not ledger_details.chain_linkage_valid
            or not ledger_details.commit_certificate_valid
            or not ledger_details.quorum_satisfied
        ):
            errs = "; ".join(ledger_details.errors) if ledger_details.errors else "Cryptographic verification failed"
            trace.append(f"[VERDICT RULE 6: LEDGER_INVALID] Ledger integrity failure: {errs}")
            return VerdictEnum.LEDGER_INVALID, VERDICT_PRECEDENCE_MAP[VerdictEnum.LEDGER_INVALID], trace

        # 7. PKI & ML-DSA-65 Signature Check (SIGNATURE_INVALID)
        if (
            identity_details is None
            or not identity_details.certificate_valid
            or not identity_details.key_purpose_valid
            or not identity_details.not_revoked
            or not identity_details.signature_verified
        ):
            errs = "Signature check failed"
            if identity_details and identity_details.errors:
                errs = "; ".join(identity_details.errors)
            trace.append(f"[VERDICT RULE 7: SIGNATURE_INVALID] Recipient identity verification failure: {errs}")
            return VerdictEnum.SIGNATURE_INVALID, VERDICT_PRECEDENCE_MAP[VerdictEnum.SIGNATURE_INVALID], trace

        # 8. Document Binding Consistency Check (DOCUMENT_MISMATCH)
        if (
            binding_details is None
            or not binding_details.binding_verified
            or not binding_details.document_hash_matched
            or not binding_details.watermark_binding_matched
        ):
            errs = "Document binding check failed"
            if binding_details and binding_details.errors:
                errs = "; ".join(binding_details.errors)
            trace.append(f"[VERDICT RULE 8: DOCUMENT_MISMATCH] Watermark document context mismatch: {errs}")
            return VerdictEnum.DOCUMENT_MISMATCH, VERDICT_PRECEDENCE_MAP[VerdictEnum.DOCUMENT_MISMATCH], trace

        # 9. All Cryptographic Gates Succeeded (VERIFIED)
        trace.append(
            f"[VERDICT RULE 9: VERIFIED] Full cryptographic attribution successful: WatermarkID "
            f"'{analysis.consensus_watermark_id}', Transaction '{ledger_details.transaction_id}', "
            f"Recipient '{identity_details.recipient_id}' committed at block height {ledger_details.block_height}."
        )
        return VerdictEnum.VERIFIED, VERDICT_PRECEDENCE_MAP[VerdictEnum.VERIFIED], trace
