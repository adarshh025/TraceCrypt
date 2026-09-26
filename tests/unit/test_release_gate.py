"""Unit tests for DocumentReleaseGate verifying mandatory prerequisites and fail-closed release denial."""

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.release_gate import DocumentReleaseGate, ReleaseDecision
from tracecrypt.errors import LedgerCommitRequiredError, ReleaseGateError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.watermark.embedder import WatermarkEmbeddingResult
from tracecrypt.watermark.types import FidelityMetrics, WatermarkPayload


@pytest.fixture
def gate_context():
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-test")
    recipient_id = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")

    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=recipient_id,
        public_key=dsa_pk,
        organization="Test Ops",
        role="RECIPIENT",
    )

    doc_hash = "sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    session_id = SecureRandom.generate_typed_id(SessionID)
    watermark_id = SecureRandom.generate_typed_id(WatermarkID)
    event_id = SecureRandom.generate_typed_id(EventID)

    payload = WatermarkPayload.create(
        watermark_id=watermark_id,
        session_id=session_id,
        document_hash=doc_hash,
        version=1,
    )

    wm_result = WatermarkEmbeddingResult(
        watermarked_pdf=b"%PDF-1.4 simulated watermarked pdf bytes",
        fidelity=FidelityMetrics(psnr=45.0, ssim=0.999, mse=1.0),
        page_fidelities=[FidelityMetrics(psnr=45.0, ssim=0.999, mse=1.0)],
        pages_count=1,
        payload=payload,
    )

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=event_id,
        document_id=SecureRandom.generate_typed_id(DocumentID),
        distribution_id=SecureRandom.generate_typed_id(DistributionID),
        document_hash=doc_hash,
        recipient_id=recipient_id,
        session_id=session_id,
        watermark_id=watermark_id,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.generate_nonce(16),
        timestamp=1727280000000000,
        pqc_algorithms=PQCAlgorithms(),
    )

    signed_event = DecryptionEventSigner.sign_event(
        event=event,
        signing_key=dsa_sk,
        signing_cert=dsa_cert,
        root_ca_public_key=root_ca.public_key,
    )

    receipt = LedgerTransactionReceipt(
        transaction_id="tx-0123456789abcdef0123456789abcdef",
        event_id=event_id,
        status=CommitStatus.COMMITTED,
        committed_at=1727280000000000,
    )

    return {
        "root_ca": root_ca,
        "dsa_cert": dsa_cert,
        "wm_result": wm_result,
        "signed_event": signed_event,
        "receipt": receipt,
        "doc_hash": doc_hash,
    }


@pytest.mark.unit
def test_release_gate_allows_valid_bundle(gate_context):
    ctx = gate_context
    result = DocumentReleaseGate.evaluate(
        watermark_result=ctx["wm_result"],
        signed_event=ctx["signed_event"],
        ledger_receipt=ctx["receipt"],
        recipient_certificate=ctx["dsa_cert"],
        root_ca_public_key=ctx["root_ca"].public_key,
        expected_document_hash=ctx["doc_hash"],
    )

    assert result.decision == ReleaseDecision.ALLOWED
    assert result.is_allowed is True


@pytest.mark.unit
def test_release_gate_denies_on_missing_watermark(gate_context):
    ctx = gate_context
    result = DocumentReleaseGate.evaluate(
        watermark_result=None,  # Missing watermark
        signed_event=ctx["signed_event"],
        ledger_receipt=ctx["receipt"],
        recipient_certificate=ctx["dsa_cert"],
    )

    assert result.decision == ReleaseDecision.DENIED
    assert result.is_allowed is False
    assert any("Watermark embedding result is missing" in r for r in result.reasons)

    with pytest.raises(ReleaseGateError):
        DocumentReleaseGate.assert_release_allowed(
            watermark_result=None,
            signed_event=ctx["signed_event"],
            ledger_receipt=ctx["receipt"],
            recipient_certificate=ctx["dsa_cert"],
        )


@pytest.mark.unit
def test_release_gate_denies_on_unknown_commit_state(gate_context):
    ctx = gate_context
    receipt = LedgerTransactionReceipt(
        transaction_id="tx-timeout",
        event_id=ctx["signed_event"].event.event_id,
        status=CommitStatus.UNKNOWN_COMMIT_STATE,
        committed_at=1727280000000000,
    )

    result = DocumentReleaseGate.evaluate(
        watermark_result=ctx["wm_result"],
        signed_event=ctx["signed_event"],
        ledger_receipt=receipt,
        recipient_certificate=ctx["dsa_cert"],
    )

    assert result.decision == ReleaseDecision.DENIED
    assert result.is_allowed is False
    assert any("UNKNOWN_COMMIT_STATE" in r for r in result.reasons)

    with pytest.raises(LedgerCommitRequiredError):
        DocumentReleaseGate.assert_release_allowed(
            watermark_result=ctx["wm_result"],
            signed_event=ctx["signed_event"],
            ledger_receipt=receipt,
            recipient_certificate=ctx["dsa_cert"],
        )


@pytest.mark.unit
def test_release_gate_denies_on_rejected_commit(gate_context):
    ctx = gate_context
    receipt = LedgerTransactionReceipt(
        transaction_id="tx-rejected",
        event_id=ctx["signed_event"].event.event_id,
        status=CommitStatus.REJECTED,
        committed_at=1727280000000000,
        error_message="Quorum denied",
    )

    result = DocumentReleaseGate.evaluate(
        watermark_result=ctx["wm_result"],
        signed_event=ctx["signed_event"],
        ledger_receipt=receipt,
        recipient_certificate=ctx["dsa_cert"],
    )

    assert result.decision == ReleaseDecision.DENIED
    assert result.is_allowed is False

    with pytest.raises(LedgerCommitRequiredError):
        DocumentReleaseGate.assert_release_allowed(
            watermark_result=ctx["wm_result"],
            signed_event=ctx["signed_event"],
            ledger_receipt=receipt,
            recipient_certificate=ctx["dsa_cert"],
        )


@pytest.mark.unit
def test_release_gate_denies_on_context_watermark_id_mismatch(gate_context):
    ctx = gate_context
    other_wm_id = SecureRandom.generate_typed_id(WatermarkID)
    payload = WatermarkPayload.create(
        watermark_id=other_wm_id,
        session_id=ctx["signed_event"].event.session_id,
        document_hash=ctx["doc_hash"],
    )
    mismatched_wm_res = WatermarkEmbeddingResult(
        watermarked_pdf=b"%PDF-1.4 simulated pdf",
        fidelity=ctx["wm_result"].fidelity,
        page_fidelities=ctx["wm_result"].page_fidelities,
        pages_count=1,
        payload=payload,
    )

    result = DocumentReleaseGate.evaluate(
        watermark_result=mismatched_wm_res,
        signed_event=ctx["signed_event"],
        ledger_receipt=ctx["receipt"],
        recipient_certificate=ctx["dsa_cert"],
    )

    assert result.decision == ReleaseDecision.DENIED
    assert any("WatermarkID mismatch" in r for r in result.reasons)
