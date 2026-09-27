"""End-to-End Multi-Recipient Forensic Attribution and Verification Tests.

Executes complete deterministic lifecycle:
1. Offline Root CA generation
2. Independent Recipient A and Recipient B ML-DSA-65 identities
3. Multi-recipient document distribution and decryption
4. Distinct watermark generation and embedding (Recipient A vs Recipient B)
5. DecryptionEvent generation and ML-DSA-65 signing
6. 4-validator offline BFT ledger commitment with Merkle trees and commit certificates
7. Blind forensic investigation from leaked artifacts:
   - Identifies Recipient A for leaked artifact A
   - Identifies Recipient B for leaked artifact B
   - Proves distinct non-overlapping attribution
8. Cross-document mismatch attack (Attack H) -> DOCUMENT_MISMATCH
9. Replay consistency test -> Identical cryptographic proof and verdict
"""

from __future__ import annotations

from pathlib import Path

from tests.forensics.conftest import make_test_pdf_bytes
from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.engine import ForensicInvestigationEngine
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


class TestEndToEndForensicAttribution:
    """Validate full blind attribution lifecycle for multiple certified recipients."""

    def test_multi_recipient_distinct_attribution(self, forensic_environment, tmp_path: Path) -> None:
        """Two recipients decrypting the same document produce distinct watermarks and deterministic attribution."""
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        root_ca = env["root_ca"]

        # Recipient A credentials
        dsa_sk_a = env["dsa_sk"]
        dsa_cert_a = env["dsa_cert"]
        rcp_a_id = RecipientID(dsa_cert_a.subject_id)

        # Issue credentials for Recipient B under same Root CA
        rcp_b_id = RecipientID.generate()
        dsa_pk_b, dsa_sk_b = generate_mldsa_keypair()
        dsa_cert_b = root_ca.issue_signing_certificate(
            subject_id=str(rcp_b_id),
            public_key=dsa_pk_b,
            organization="Forensic Testing Bureau",
            role="Recipient",
        )

        pdf_bytes = make_test_pdf_bytes(num_pages=2)
        doc_hash = "sha3-256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        # 1. Recipient A Watermark & DecryptionEvent
        wmid_a = WatermarkID.generate()
        sid_a = SessionID.generate()
        payload_a = WatermarkPayload.create(
            watermark_id=wmid_a,
            session_id=sid_a,
            document_hash=doc_hash,
        )
        embed_a = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload_a,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        leaked_a_path = tmp_path / "leaked_recipient_a.pdf"
        leaked_a_path.write_bytes(embed_a.watermarked_pdf)

        event_a = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=rcp_a_id,
            recipient_certificate_id=dsa_cert_a.serial_number,
            session_id=sid_a,
            watermark_id=wmid_a,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )
        block_a, _ = helper.commit_event(event_a, dsa_sk_a, dsa_cert_a, height=1)

        # 2. Recipient B Watermark & DecryptionEvent
        wmid_b = WatermarkID.generate()
        sid_b = SessionID.generate()
        payload_b = WatermarkPayload.create(
            watermark_id=wmid_b,
            session_id=sid_b,
            document_hash=doc_hash,
        )
        embed_b = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload_b,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        leaked_b_path = tmp_path / "leaked_recipient_b.pdf"
        leaked_b_path.write_bytes(embed_b.watermarked_pdf)

        event_b = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=rcp_b_id,
            recipient_certificate_id=dsa_cert_b.serial_number,
            session_id=sid_b,
            watermark_id=wmid_b,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros() + 1000,
            pqc_algorithms=PQCAlgorithms(),
        )
        helper.commit_event(
            event_b,
            dsa_sk_b,
            dsa_cert_b,
            height=2,
            prev_hash=block_a.header.block_hash,
        )

        # 3. Blind Forensic Investigation of Artifact A
        engine = ForensicInvestigationEngine(
            ledger_storage=storage,
            root_ca_public_key=root_ca.public_key,
        )

        inv_a = engine.investigate(file_path=leaked_a_path, suspect_document_hash=doc_hash)
        assert inv_a.verdict == ForensicVerdict.VERIFIED
        assert inv_a.watermark_analysis.consensus_watermark_id == wmid_a
        assert inv_a.identity_details.recipient_id == rcp_a_id

        # 4. Blind Forensic Investigation of Artifact B
        inv_b = engine.investigate(file_path=leaked_b_path, suspect_document_hash=doc_hash)
        assert inv_b.verdict == ForensicVerdict.VERIFIED
        assert inv_b.watermark_analysis.consensus_watermark_id == wmid_b
        assert inv_b.identity_details.recipient_id == rcp_b_id

        # 5. Assert strictly distinct non-overlapping attribution
        assert inv_a.watermark_analysis.consensus_watermark_id != inv_b.watermark_analysis.consensus_watermark_id
        assert inv_a.identity_details.recipient_id != inv_b.identity_details.recipient_id
        assert inv_a.ledger_details.block_height == 1
        assert inv_b.ledger_details.block_height == 2

    def test_cross_document_binding_mismatch_attack_h(self, forensic_environment, tmp_path: Path) -> None:
        """Attack H: Leaked document investigated against wrong document context yields DOCUMENT_MISMATCH."""
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]

        pdf_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash_true = "sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        doc_hash_wrong = "sha3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash_true,
        )
        embed = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash_true,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        leaked_path = tmp_path / "leaked_doc_a.pdf"
        leaked_path.write_bytes(embed.watermarked_pdf)

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash_true,
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

        # Investigate passing suspect document hash as doc_hash_wrong
        inv = engine.investigate(
            file_path=leaked_path,
            suspect_document_hash=doc_hash_wrong,
        )

        assert inv.verdict == ForensicVerdict.DOCUMENT_MISMATCH
        assert inv.document_binding_details.binding_verified is False
        assert inv.document_binding_details.document_hash_matched is False

    def test_replay_investigation_determinism(self, forensic_environment, tmp_path: Path) -> None:
        """Investigating the same evidence repeatedly yields identical cryptographic proofs and verdicts."""
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]

        pdf_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash = "sha3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )
        embed = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        leaked_path = tmp_path / "replay_evidence.pdf"
        leaked_path.write_bytes(embed.watermarked_pdf)

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

        inv_run_1 = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)
        inv_run_2 = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)

        assert inv_run_1.verdict == inv_run_2.verdict == ForensicVerdict.VERIFIED
        assert (
            inv_run_1.watermark_analysis.consensus_watermark_id
            == inv_run_2.watermark_analysis.consensus_watermark_id
            == wmid
        )
        assert (
            inv_run_1.ledger_details.transaction_id
            == inv_run_2.ledger_details.transaction_id
        )
        assert (
            inv_run_1.identity_details.signature_verified
            == inv_run_2.identity_details.signature_verified
            is True
        )
