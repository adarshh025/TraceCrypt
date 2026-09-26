"""Centralized Document Release Gate for TraceCrypt.

The Release Gate is the cryptographic and transactional boundary between the private
decryption process and the external release of any document.

Invariant:
NO DECRYPTED DOCUMENT MAY BE RELEASED WITHOUT:
1. Successful transform-domain forensic watermark embedding.
2. Exact binding between watermark payload and DecryptionEvent.
3. Cryptographically valid ML-DSA-65 signature on RFC 8785 canonical event.
4. Confirmed COMMIT status from the distributed ledger.
5. Absolute zeroization of intermediate unwatermarked plaintext.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.errors import LedgerCommitRequiredError, ReleaseGateError
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.utils.identifiers import EventID
from tracecrypt.watermark.embedder import WatermarkEmbeddingResult
from tracecrypt.watermark.types import WatermarkPayload


class ReleaseDecision(str, Enum):
    """Explicit release gate decision."""
    ALLOWED = "RELEASE_ALLOWED"
    DENIED = "RELEASE_DENIED"


class ReleaseGateResult(BaseModel):
    """Structured decision returned by the DocumentReleaseGate."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: ReleaseDecision = Field(description="Release decision: ALLOWED or DENIED")
    is_allowed: bool = Field(description="Boolean indicator: True if release is permitted")
    event_id: Optional[EventID] = Field(default=None, description="Associated DecryptionEvent ID")
    transaction_id: Optional[str] = Field(default=None, description="Associated Ledger Transaction ID")
    reasons: List[str] = Field(default_factory=list, description="Reasons for denial or approval notes")


class DocumentReleaseGate:
    """Centralized, immutable release decision gate."""

    @classmethod
    def evaluate(
        cls,
        watermark_result: Optional[WatermarkEmbeddingResult],
        signed_event: Optional[SignedDecryptionEvent],
        ledger_receipt: Optional[LedgerTransactionReceipt],
        recipient_public_key: Optional[MLDSAPublicKey] = None,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
        expected_document_hash: Optional[str] = None,
    ) -> ReleaseGateResult:
        """Evaluate the complete set of release conditions.

        Fail-closed: Returns RELEASE_DENIED if ANY prerequisite fails.
        """
        reasons: List[str] = []

        # 1. Watermark Embedding Verification
        if watermark_result is None:
            reasons.append("RELEASE_DENIED: Watermark embedding result is missing.")
        else:
            if not watermark_result.watermarked_pdf:
                reasons.append("RELEASE_DENIED: Watermarked artifact is empty.")
            if watermark_result.payload is None:
                reasons.append("RELEASE_DENIED: Watermark payload is missing.")

        # 2. Signed Event Verification
        if signed_event is None:
            reasons.append("RELEASE_DENIED: Signed decryption event is missing.")
        else:
            event = signed_event.event

            # Check Watermark-Event Context Binding
            if watermark_result is not None and watermark_result.payload is not None:
                payload = watermark_result.payload
                if event.watermark_id != payload.watermark_id:
                    reasons.append(
                        f"RELEASE_DENIED: WatermarkID mismatch between event ('{event.watermark_id}') "
                        f"and embedded payload ('{payload.watermark_id}')."
                    )

                expected_session_tag = WatermarkPayload.compute_session_tag(event.session_id)
                if payload.session_tag != expected_session_tag:
                    reasons.append("RELEASE_DENIED: Session tag mismatch between event and embedded watermark.")

                if expected_document_hash is not None:
                    if event.document_hash.lower() != expected_document_hash.lower():
                        reasons.append(
                            f"RELEASE_DENIED: Document hash mismatch: event='{event.document_hash}', "
                            f"expected='{expected_document_hash}'."
                        )

            # Cryptographic signature and certificate verification
            verify_res = DecryptionEventVerifier.verify_signed_event(
                signed_event=signed_event,
                recipient_public_key=recipient_public_key,
                recipient_certificate=recipient_certificate,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=revocation_provider,
                expected_document_hash=expected_document_hash,
            )

            if not verify_res.valid:
                reasons.append(f"RELEASE_DENIED: Event cryptographic verification failed: {verify_res.errors}")

        # 3. Ledger Commitment Verification
        if ledger_receipt is None:
            reasons.append("LEDGER_COMMIT_REQUIRED: Ledger transaction receipt is missing.")
        else:
            if signed_event is not None and ledger_receipt.event_id != signed_event.event.event_id:
                reasons.append(
                    f"RELEASE_DENIED: Ledger receipt event_id '{ledger_receipt.event_id}' "
                    f"does not match signed event_id '{signed_event.event.event_id}'."
                )

            if ledger_receipt.status != CommitStatus.COMMITTED:
                if ledger_receipt.status == CommitStatus.UNKNOWN_COMMIT_STATE:
                    reasons.append(
                        "LEDGER_COMMIT_REQUIRED: Ledger transaction status is UNKNOWN_COMMIT_STATE. "
                        "Release is strictly prohibited while commit is unconfirmed."
                    )
                elif ledger_receipt.status == CommitStatus.REJECTED:
                    reasons.append(
                        f"LEDGER_COMMIT_REQUIRED: Ledger transaction was REJECTED: {ledger_receipt.error_message}"
                    )
                elif ledger_receipt.status == CommitStatus.PENDING:
                    reasons.append("LEDGER_COMMIT_REQUIRED: Ledger transaction is PENDING and not yet committed.")
                else:
                    reasons.append(
                        f"LEDGER_COMMIT_REQUIRED: Ledger transaction has non-committed status: {ledger_receipt.status}"
                    )

        is_allowed = len(reasons) == 0
        decision = ReleaseDecision.ALLOWED if is_allowed else ReleaseDecision.DENIED

        eid = signed_event.event.event_id if signed_event is not None else None
        txid = ledger_receipt.transaction_id if ledger_receipt is not None else None

        return ReleaseGateResult(
            decision=decision,
            is_allowed=is_allowed,
            event_id=eid,
            transaction_id=txid,
            reasons=reasons if not is_allowed else ["All cryptographic, watermark, and ledger checks passed."],
        )

    @classmethod
    def assert_release_allowed(
        cls,
        watermark_result: Optional[WatermarkEmbeddingResult],
        signed_event: Optional[SignedDecryptionEvent],
        ledger_receipt: Optional[LedgerTransactionReceipt],
        recipient_public_key: Optional[MLDSAPublicKey] = None,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
        expected_document_hash: Optional[str] = None,
    ) -> ReleaseGateResult:
        """Evaluate release gate and raise specific exception on denial.

        Raises:
            LedgerCommitRequiredError: If commit confirmation failed.
            ReleaseGateError: If watermark, signature, or context validation failed.
        """
        result = cls.evaluate(
            watermark_result=watermark_result,
            signed_event=signed_event,
            ledger_receipt=ledger_receipt,
            recipient_public_key=recipient_public_key,
            recipient_certificate=recipient_certificate,
            root_ca_public_key=root_ca_public_key,
            revocation_provider=revocation_provider,
            expected_document_hash=expected_document_hash,
        )

        if not result.is_allowed:
            has_ledger_issue = any("LEDGER_COMMIT_REQUIRED" in r for r in result.reasons)
            if has_ledger_issue:
                raise LedgerCommitRequiredError(f"Document release blocked: {result.reasons}")
            raise ReleaseGateError(f"Document release denied by release gate: {result.reasons}")

        return result
