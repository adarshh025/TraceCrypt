"""Unit tests for the deterministic 9-state forensic verdict engine and precedence model."""

from __future__ import annotations

from tracecrypt.forensics.types import (
    DocumentBindingDetails,
    ForensicVerdict,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
    WatermarkForensicAnalysis,
)
from tracecrypt.forensics.verdict import VERDICT_PRECEDENCE_MAP, VerdictEvaluator
from tracecrypt.models.domain import RecipientID, VerdictEnum
from tracecrypt.utils.identifiers import WatermarkID
from tracecrypt.watermark.types import ExtractionStatus


class TestVerdictEngine:
    """Validate exactly nine verdicts and absolute deterministic precedence."""

    def test_exactly_nine_verdicts_exist(self) -> None:
        """Verify the closed verdict enum has exactly nine values."""
        assert len(VerdictEnum) == 9
        expected = {
            "VERIFIED",
            "NOT_FOUND",
            "INVALID_WATERMARK",
            "SIGNATURE_INVALID",
            "LEDGER_INVALID",
            "DOCUMENT_MISMATCH",
            "CORRUPTED_WATERMARK",
            "AMBIGUOUS",
            "UNVERIFIABLE",
        }
        actual = {v.value for v in VerdictEnum}
        assert actual == expected

    def test_verdict_precedence_ordering(self) -> None:
        """Verify strict priority hierarchy in VERDICT_PRECEDENCE_MAP."""
        ranks = [
            VERDICT_PRECEDENCE_MAP[VerdictEnum.AMBIGUOUS],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.UNVERIFIABLE],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.CORRUPTED_WATERMARK],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.INVALID_WATERMARK],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.NOT_FOUND],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.LEDGER_INVALID],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.SIGNATURE_INVALID],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.DOCUMENT_MISMATCH],
            VERDICT_PRECEDENCE_MAP[VerdictEnum.VERIFIED],
        ]
        assert ranks == list(range(1, 10))

    def test_ambiguous_precedence(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.AMBIGUOUS,
            pages_analyzed=2,
            pages_detected=2,
            pages_decoded=2,
            pages_corrupted=0,
            total_ecc_corrections=0,
            has_cross_page_conflict=True,
            distinct_watermark_ids=["wm-1", "wm-2"],
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=None,
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.AMBIGUOUS
        assert rank == 1

    def test_unverifiable_when_no_signal(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.NOT_DETECTED,
            pages_analyzed=1,
            pages_detected=0,
            pages_decoded=0,
            pages_corrupted=0,
            total_ecc_corrections=0,
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=None,
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.UNVERIFIABLE
        assert rank == 2

    def test_corrupted_watermark_verdict(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.CORRUPTED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=0,
            pages_corrupted=1,
            total_ecc_corrections=0,
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=None,
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.CORRUPTED_WATERMARK
        assert rank == 3

    def test_invalid_watermark_verdict(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.INVALID,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=0,
            pages_corrupted=0,
            total_ecc_corrections=0,
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=None,
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.INVALID_WATERMARK
        assert rank == 4

    def test_not_found_verdict_when_ledger_empty(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.DECODED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=1,
            pages_corrupted=0,
            total_ecc_corrections=0,
            consensus_watermark_id=WatermarkID.generate(),
            consensus_session_tag="0123456789abcdef",
            consensus_document_binding="aabbccddee",
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=None,  # No transaction found on ledger
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.NOT_FOUND
        assert rank == 5

    def test_ledger_invalid_verdict(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.DECODED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=1,
            pages_corrupted=0,
            total_ecc_corrections=0,
            consensus_watermark_id=WatermarkID.generate(),
        )
        ledger = LedgerVerificationDetails(
            transaction_id="tx-123",
            block_height=1,
            block_hash="sha3-256:1111",
            merkle_proof_valid=False,  # Failed Merkle proof
            block_valid=True,
            chain_linkage_valid=True,
            commit_certificate_valid=True,
            quorum_satisfied=True,
            validator_count=4,
            verified_validators=["val-1", "val-2", "val-3"],
            errors=["Merkle proof failed"],
        )
        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=ledger,
            identity_details=None,
            binding_details=None,
        )
        assert verdict == ForensicVerdict.LEDGER_INVALID
        assert rank == 6

    def test_signature_invalid_over_document_mismatch_precedence(self) -> None:
        """If both signature is invalid AND binding fails, SIGNATURE_INVALID takes precedence."""
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.DECODED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=1,
            pages_corrupted=0,
            total_ecc_corrections=0,
            consensus_watermark_id=WatermarkID.generate(),
        )
        ledger = LedgerVerificationDetails(
            transaction_id="tx-123",
            block_height=1,
            block_hash="sha3-256:1111",
            merkle_proof_valid=True,
            block_valid=True,
            chain_linkage_valid=True,
            commit_certificate_valid=True,
            quorum_satisfied=True,
            validator_count=4,
            verified_validators=["val-1", "val-2", "val-3"],
            errors=[],
        )
        identity = IdentityVerificationDetails(
            recipient_id=RecipientID.generate(),
            certificate_id="crt-1",
            certificate_valid=True,
            key_purpose_valid=True,
            not_revoked=True,
            signature_verified=False,  # Signature failed!
            errors=["ML-DSA signature verification failed"],
        )
        binding = DocumentBindingDetails(
            event_document_hash="sha3-256:1111222233334444555566667777888811112222333344445555666677778888",
            binding_verified=False,
            document_hash_matched=False,
            watermark_binding_matched=False,
            errors=["Binding mismatch"],
        )

        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=ledger,
            identity_details=identity,
            binding_details=binding,
        )
        # Precedence rule: SIGNATURE_INVALID (rank 7) precedes DOCUMENT_MISMATCH (rank 8)
        assert verdict == ForensicVerdict.SIGNATURE_INVALID
        assert rank == 7

    def test_document_mismatch_verdict(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.DECODED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=1,
            pages_corrupted=0,
            total_ecc_corrections=0,
            consensus_watermark_id=WatermarkID.generate(),
        )
        ledger = LedgerVerificationDetails(
            transaction_id="tx-123",
            block_height=1,
            block_hash="sha3-256:1111",
            merkle_proof_valid=True,
            block_valid=True,
            chain_linkage_valid=True,
            commit_certificate_valid=True,
            quorum_satisfied=True,
            validator_count=4,
            verified_validators=["val-1", "val-2", "val-3"],
            errors=[],
        )
        identity = IdentityVerificationDetails(
            recipient_id=RecipientID.generate(),
            certificate_id="crt-1",
            certificate_valid=True,
            key_purpose_valid=True,
            not_revoked=True,
            signature_verified=True,
            errors=[],
        )
        binding = DocumentBindingDetails(
            event_document_hash="sha3-256:1111222233334444555566667777888811112222333344445555666677778888",
            binding_verified=False,
            document_hash_matched=False,
            watermark_binding_matched=False,
            errors=["Document mismatch"],
        )

        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=ledger,
            identity_details=identity,
            binding_details=binding,
        )
        assert verdict == ForensicVerdict.DOCUMENT_MISMATCH
        assert rank == 8

    def test_verified_verdict(self) -> None:
        wm = WatermarkForensicAnalysis(
            overall_status=ExtractionStatus.DECODED,
            pages_analyzed=1,
            pages_detected=1,
            pages_decoded=1,
            pages_corrupted=0,
            total_ecc_corrections=0,
            consensus_watermark_id=WatermarkID.generate(),
        )
        ledger = LedgerVerificationDetails(
            transaction_id="tx-123",
            block_height=1,
            block_hash="sha3-256:1111",
            merkle_proof_valid=True,
            block_valid=True,
            chain_linkage_valid=True,
            commit_certificate_valid=True,
            quorum_satisfied=True,
            validator_count=4,
            verified_validators=["val-1", "val-2", "val-3"],
            errors=[],
        )
        identity = IdentityVerificationDetails(
            recipient_id=RecipientID.generate(),
            certificate_id="crt-1",
            certificate_valid=True,
            key_purpose_valid=True,
            not_revoked=True,
            signature_verified=True,
            errors=[],
        )
        binding = DocumentBindingDetails(
            event_document_hash="sha3-256:1111222233334444555566667777888811112222333344445555666677778888",
            binding_verified=True,
            document_hash_matched=True,
            watermark_binding_matched=True,
            errors=[],
        )

        verdict, rank, _ = VerdictEvaluator.evaluate(
            analysis=wm,
            ledger_details=ledger,
            identity_details=identity,
            binding_details=binding,
        )
        assert verdict == ForensicVerdict.VERIFIED
        assert rank == 9
