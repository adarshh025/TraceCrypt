"""Unit tests for standalone .tcproof proof bundle generation and standalone verification."""

from __future__ import annotations

from pathlib import Path

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.forensics.types import ForensicVerdict
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import WatermarkParameters, WatermarkPayload
from tests.forensics.conftest import make_test_pdf_bytes


class TestProofBundle:
    """Validate standalone proof bundles and independent first-principles verification."""

    def test_proof_bundle_export_and_standalone_verify(self, forensic_environment, tmp_path: Path) -> None:
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]

        # 1. Create PDF and embed watermark
        pdf_bytes = make_test_pdf_bytes(num_pages=2)
        doc_hash = "sha3-256:7777777777777777777777777777777777777777777777777777777777777777"

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        embed_res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        leaked_pdf_path = tmp_path / "leaked_doc.pdf"
        leaked_pdf_path.write_bytes(embed_res.watermarked_pdf)

        # 2. Record DecryptionEvent and commit block
        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid,
            watermark_id=wmid,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )
        helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # 3. Investigate leaked artifact
        engine = ForensicInvestigationEngine(
            ledger_storage=storage,
            root_ca_public_key=root_ca.public_key,
        )
        inv = engine.investigate(
            file_path=leaked_pdf_path,
            suspect_document_hash=doc_hash,
        )
        assert inv.verdict == ForensicVerdict.VERIFIED

        # 4. Export proof bundle to disk
        proof_path = tmp_path / "case_proof.tcproof"
        _ = engine.export_proof_bundle(inv, proof_path)
        assert proof_path.is_file()

        # 5. Load proof bundle in isolation and verify with StandaloneProofVerifier
        loaded_bundle = ForensicProofBundle.load_file(proof_path)
        verifier = StandaloneProofVerifier()
        result = verifier.verify(loaded_bundle)

        assert result.verified is True
        assert result.bundle_integrity_valid is True
        assert result.watermark_valid is True
        assert result.block_hash_valid is True
        assert result.merkle_proof_valid is True
        assert result.commit_cert_valid is True
        assert result.recipient_cert_valid is True
        assert result.signature_valid is True
        assert result.document_binding_valid is True
        assert result.verdict_consistent is True

    def test_tampered_bundle_rejected_by_standalone_verifier(
        self, forensic_environment, tmp_path: Path
    ) -> None:
        """Standalone verifier must reject proof bundle if any cryptographic proof is altered."""
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]

        pdf_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash = "sha3-256:8888888888888888888888888888888888888888888888888888888888888888"

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        embed_res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        leaked_pdf_path = tmp_path / "leaked_doc_tamper.pdf"
        leaked_pdf_path.write_bytes(embed_res.watermarked_pdf)

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid,
            watermark_id=wmid,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )
        helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        engine = ForensicInvestigationEngine(
            ledger_storage=storage,
            root_ca_public_key=root_ca.public_key,
        )
        inv = engine.investigate(
            file_path=leaked_pdf_path,
            suspect_document_hash=doc_hash,
        )
        bundle = engine.export_proof_bundle(inv)

        # Tamper: Forge the bundle verdict to claims DOCUMENT_MISMATCH without matching checks
        tampered_bundle = bundle.model_copy(update={"verdict": ForensicVerdict.DOCUMENT_MISMATCH})
        verifier = StandaloneProofVerifier()
        result = verifier.verify(tampered_bundle)

        assert result.verified is False
        assert result.verdict_consistent is False
