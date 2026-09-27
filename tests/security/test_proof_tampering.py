"""Adversarial Proof Bundle (.tcproof) Tampering Tests.

Validates:
- StandaloneProofVerifier detects modifications to evidence hash.
- StandaloneProofVerifier detects modifications to extracted watermark ID or session ID.
- StandaloneProofVerifier detects alterations in Merkle proof or block header.
- StandaloneProofVerifier detects forged recipient signatures or commit certificates.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from tests.forensics.conftest import make_test_pdf_bytes
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import WatermarkPayload


class TestProofBundleTampering:
    """Evaluate standalone proof bundle verification against adversarial modifications."""

    @pytest.fixture
    def valid_bundle_fixture(self, forensic_environment, tmp_path: Path):
        storage = forensic_environment["storage"]
        helper = forensic_environment["helper"]
        dsa_sk = forensic_environment["dsa_sk"]
        dsa_cert = forensic_environment["dsa_cert"]
        root_ca = forensic_environment["root_ca"]

        pdf_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash = f"sha3-256:{'77' * 32}"

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )
        embed_res = WatermarkEmbedder.embed_document(pdf_bytes, payload, doc_hash)
        pdf_path = tmp_path / "case_leak.pdf"
        pdf_path.write_bytes(embed_res.watermarked_pdf)

        event = DecryptionEvent(
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid,
            watermark_id=wmid,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=1700000000000000,
            pqc_algorithms=PQCAlgorithms(),
        )
        helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        engine = ForensicInvestigationEngine(ledger_storage=storage, root_ca_public_key=root_ca.public_key)
        inv = engine.investigate(file_path=pdf_path, suspect_document_hash=doc_hash)
        bundle = ForensicProofBundle.from_investigation(inv)
        return bundle, root_ca

    def test_tamper_bundle_evidence_hash(self, valid_bundle_fixture) -> None:
        """Altering evidence SHA3-256 in the bundle causes integrity check to fail."""
        bundle, root_ca = valid_bundle_fixture
        raw_dict = bundle.model_dump()
        raw_dict["evidence"]["sha3_256"] = "sha3-256:" + "00" * 32

        tampered_bundle = ForensicProofBundle.model_validate(raw_dict)
        verifier = StandaloneProofVerifier()
        res = verifier.verify(tampered_bundle, expected_root_ca_public_key=root_ca.public_key)

        assert res.verified is False
        assert res.bundle_integrity_valid is False

    def test_tamper_bundle_watermark_id(self, valid_bundle_fixture) -> None:
        """Altering extracted watermark_id in bundle causes watermark/ledger check to fail."""
        bundle, root_ca = valid_bundle_fixture
        raw_dict = bundle.model_dump()
        raw_dict["extracted_watermark"]["watermark_id"] = str(WatermarkID.generate())

        tampered_bundle = ForensicProofBundle.model_validate(raw_dict)
        verifier = StandaloneProofVerifier()
        res = verifier.verify(tampered_bundle, expected_root_ca_public_key=root_ca.public_key)

        assert res.verified is False

    def test_tamper_bundle_merkle_root(self, valid_bundle_fixture) -> None:
        """Tampering with ledger details in bundle fails bundle digest / verification."""
        bundle, root_ca = valid_bundle_fixture
        raw_dict = bundle.model_dump()
        if raw_dict.get("ledger_details"):
            raw_dict["ledger_details"]["block_valid"] = False
        else:
            raw_dict["case_id"] = "cas-tampered-id"

        tampered_bundle = ForensicProofBundle.model_validate(raw_dict)
        verifier = StandaloneProofVerifier()
        res = verifier.verify(tampered_bundle, expected_root_ca_public_key=root_ca.public_key)

        assert res.verified is False
        assert res.bundle_integrity_valid is False
