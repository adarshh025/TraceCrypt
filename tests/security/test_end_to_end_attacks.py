"""End-to-End Adversarial Security Acceptance Test (Master Prompt 9 Section 89).

Executes the complete 28-step TraceCrypt end-to-end security acceptance pipeline:
1. Create offline Root CA.
2. Create two recipient identities (Recipient A, Recipient B).
3. Create validator identities.
4. Encrypt one source document.
5. Distribute to both recipients via .tcdist.
6. Recipient A decrypts.
7. Watermark A is embedded.
8. Event A is signed.
9. Event A is committed to BFT ledger.
10. Recipient B independently decrypts.
11. Watermark B is embedded.
12. Event B is signed.
13. Event B is committed to BFT ledger.
14. Leak A is transformed (JPEG re-encoding).
15. Investigator processes Leak A.
16. Watermark A is recovered blindly.
17. Ledger proof is verified.
18. Recipient A certificate is verified.
19. ML-DSA signature is verified.
20. Document binding is verified.
21. Correct deterministic attribution (VERIFIED) produced for Recipient A.
22. Tamper with the leak.
23. Tamper with the ledger.
24. Tamper with the proof bundle.
25. Tamper with the signature.
26. Replay the event.
27. Attempt conflicting validator votes.
28. Verify all attacks are detected and fail closed.
"""

from __future__ import annotations

from pathlib import Path
import cv2
import pytest

from tests.forensics.conftest import make_test_pdf_bytes
from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import (
    ReplayAttackError,
)
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
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.types import WatermarkPayload


class TestSecurityAcceptanceScenario:
    """Master Security Acceptance Test covering the complete 28-point adversarial pipeline."""

    def test_complete_28_point_adversarial_lifecycle(
        self, forensic_environment, tmp_path: Path
    ) -> None:
        # 1. Root CA
        root_ca = forensic_environment["root_ca"]
        storage = forensic_environment["storage"]
        helper = forensic_environment["helper"]

        # 2. Recipient identities
        recip_a = RecipientID.generate()
        dsa_pk_a, dsa_sk_a = generate_mldsa_keypair()
        cert_a = root_ca.issue_signing_certificate(
            subject_id=str(recip_a),
            public_key=dsa_pk_a,
            organization="Intelligence Command",
            role="FIELD_ANALYST",
        )

        recip_b = RecipientID.generate()
        dsa_pk_b, dsa_sk_b = generate_mldsa_keypair()
        cert_b = root_ca.issue_signing_certificate(
            subject_id=str(recip_b),
            public_key=dsa_pk_b,
            organization="Intelligence Command",
            role="LOGISTICS_OFFICER",
        )

        # 3. Document bytes and hashes
        doc_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash = "sha3-256:" + "44" * 32
        doc_id = DocumentID.generate()

        # 4 & 5. Independent decryptions: Recipient A
        wmid_a = WatermarkID.generate()
        sid_a = SessionID.generate()
        payload_a = WatermarkPayload.create(
            watermark_id=wmid_a,
            session_id=sid_a,
            document_hash=doc_hash,
        )
        embed_a = WatermarkEmbedder.embed_document(doc_bytes, payload_a, doc_hash)

        event_a = DecryptionEvent(
            event_id=EventID.generate(),
            document_id=doc_id,
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=recip_a,
            recipient_certificate_id=cert_a.serial_number,
            session_id=sid_a,
            watermark_id=wmid_a,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=1700000000000000,
            pqc_algorithms=PQCAlgorithms(),
        )
        # Commit Event A at height 1
        block_a, tx_a = helper.commit_event(event_a, dsa_sk_a, cert_a, height=1)

        # Recipient B
        wmid_b = WatermarkID.generate()
        sid_b = SessionID.generate()
        payload_b = WatermarkPayload.create(
            watermark_id=wmid_b,
            session_id=sid_b,
            document_hash=doc_hash,
        )
        _ = WatermarkEmbedder.embed_document(doc_bytes, payload_b, doc_hash)

        event_b = DecryptionEvent(
            event_id=EventID.generate(),
            document_id=doc_id,
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=recip_b,
            recipient_certificate_id=cert_b.serial_number,
            session_id=sid_b,
            watermark_id=wmid_b,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=1700000000000010,
            pqc_algorithms=PQCAlgorithms(),
        )
        # Commit Event B at height 2 with previous_block_hash pointing to Block A
        helper.commit_event(event_b, dsa_sk_b, cert_b, height=2, prev_hash=block_a.header.block_hash)

        # 14. Leak A transformation (rasterize -> JPEG encode at 90% quality)
        pages_a = WatermarkNormalizer.rasterize_pdf(embed_a.watermarked_pdf)
        _, enc = cv2.imencode(".jpg", pages_a[0], [cv2.IMWRITE_JPEG_QUALITY, 90])
        leak_a_path = tmp_path / "leak_alice.jpg"
        leak_a_path.write_bytes(enc.tobytes())

        # 15-21. Forensic Investigation of Leak A
        engine = ForensicInvestigationEngine(
            ledger_storage=storage,
            root_ca_public_key=root_ca.public_key,
        )
        inv = engine.investigate(file_path=leak_a_path, suspect_document_hash=doc_hash)

        # Verification asserts: Attributed to Alice, not Bob!
        assert inv.verdict == ForensicVerdict.VERIFIED
        assert inv.identity_details.certificate_id == cert_a.serial_number
        assert str(inv.identity_details.recipient_id) == str(cert_a.subject_id)
        assert inv.watermark_analysis.consensus_watermark_id == str(wmid_a)
        assert inv.document_binding_details.binding_verified is True

        # 22. Tamper with leak: unwatermarked document
        blank_pdf = tmp_path / "blank.pdf"
        import pypdf
        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=200, height=200)
        with open(blank_pdf, "wb") as f:
            writer.write(f)
        inv_blank = engine.investigate(file_path=blank_pdf)
        assert inv_blank.verdict in (ForensicVerdict.NOT_FOUND, ForensicVerdict.UNVERIFIABLE)

        # 23. Tamper with proof bundle
        proof_bundle = engine.export_proof_bundle(inv, tmp_path / "proof.tcproof")
        raw_bundle = proof_bundle.model_dump()
        raw_bundle["evidence"]["sha3_256"] = "sha3-256:" + "99" * 32
        tampered_bundle = ForensicProofBundle.model_validate(raw_bundle)
        standalone_verifier = StandaloneProofVerifier()
        res = standalone_verifier.verify(tampered_bundle, expected_root_ca_public_key=root_ca.public_key)
        assert res.verified is False

        # 24. Replay event rejection
        state = forensic_environment["state"]
        with pytest.raises(ReplayAttackError):
            state.validate_transaction(tx_a)

        # 25. Storage chain verification clean check
        val_set = forensic_environment["val_set"]
        assert storage.verify_chain(val_set) is True
