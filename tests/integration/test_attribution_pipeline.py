"""Integration tests for the complete recipient-side attribution pipeline.

Verifies:
1. End-to-end atomic decryption pipeline:
   DECRYPT -> CREATE SESSION -> CREATE UNIQUE WATERMARK -> EMBED WATERMARK
   -> BUILD CANONICAL EVENT -> SIGN EVENT WITH ML-DSA-65 -> PREPARE LEDGER TRANSACTION
   -> ONLY THEN RELEASE DOCUMENT
2. Session uniqueness: Same recipient + same document decrypted twice produces distinct
   SessionIDs, WatermarkIDs, and signed events.
3. Recipient separation: Different recipients decrypting the same document produce
   independent attribution trails.
4. Forensic preparation link: Leaked document watermark recovery locates the signed event
   on the ledger and verifies cryptographic attribution.
5. Fail-closed ledger commitment: Ledger commit failure strictly denies document release.
"""

from __future__ import annotations

import io
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.errors import LedgerCommitRequiredError
from tracecrypt.forensics.preparation import ForensicAttributionLink
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.types import CommitStatus
from tracecrypt.utils.identifiers import RecipientID
from tracecrypt.watermark.extractor import WatermarkExtractor
from tracecrypt.watermark.types import ExtractionStatus, WatermarkParameters


def create_test_pdf(num_pages: int = 2) -> bytes:
    """Generate in-memory multi-page test PDF document."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(num_pages):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 720, f"Classified Intelligence Briefing - Page {p + 1}")
        c.setFont("Helvetica", 10)
        c.drawString(72, 690, "Strict post-quantum recipient attribution test artifact.")
        for line in range(8):
            c.drawString(72, 650 - line * 20, f"Section {line}: Cryptographic record {p * 100 + line}.")
        c.showPage()
    c.save()
    return buf.getvalue()


@pytest.fixture
def attribution_env():
    """Set up Root CA and two enrolled recipients: Alice and Bob."""
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-pipeline")

    def enroll_recipient(name: str) -> RecipientCredentials:
        rid = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")
        kem_pk, kem_sk = generate_mlkem_keypair()
        kem_cert = root_ca.issue_kem_certificate(
            subject_id=rid,
            public_key=kem_pk,
            organization="Defense Intelligence",
            role="Recipient",
        )
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        dsa_cert = root_ca.issue_signing_certificate(
            subject_id=rid,
            public_key=dsa_pk,
            organization="Defense Intelligence",
            role="Recipient",
        )
        return RecipientCredentials(
            recipient_id=rid,
            kem_private_key=kem_sk,
            kem_certificate=kem_cert,
            dsa_private_key=dsa_sk,
            dsa_certificate=dsa_cert,
        )

    alice = enroll_recipient("Alice")
    bob = enroll_recipient("Bob")
    ledger = InMemoryLedgerAdapter()

    return {
        "root_ca": root_ca,
        "alice": alice,
        "bob": bob,
        "ledger": ledger,
    }


class TestAttributionPipeline:
    """Integration test suite for atomic recipient attribution and release gate."""

    def test_end_to_end_recipient_attribution_release(self, attribution_env):
        env = attribution_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        # 1. Sender packages document for Alice
        pdf_bytes = create_test_pdf(num_pages=2)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        # 2. Alice executes atomic decryption pipeline
        release = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
            watermark_params=WatermarkParameters(embedding_strength=8.0),
        )

        # 3. Verify Watermarked Document Release properties
        assert release.watermarked_pdf is not None
        assert len(release.watermarked_pdf) > 0
        assert release.watermarked_pdf[:5] == b"%PDF-"
        assert release.source_document_hash == doc_hash
        assert release.fidelity.psnr >= 42.0
        assert release.fidelity.ssim >= 0.970

        # 4. Verify Ledger Commitment
        assert release.ledger_receipt.status == CommitStatus.COMMITTED
        assert release.ledger_receipt.is_committed is True
        assert release.signed_event.ledger_transaction_id == release.ledger_receipt.transaction_id

        # 5. Verify ledger contains committed event
        committed_evt = ledger.get_event(release.signed_event.event.event_id)
        assert committed_evt is not None
        assert committed_evt.event.recipient_id == alice.recipient_id

    def test_session_uniqueness_same_recipient_different_sessions(self, attribution_env):
        env = attribution_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf(num_pages=1)
        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        # Session A
        release_a = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )

        # Session B (same recipient, same document package)
        release_b = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )

        # Invariant: Session A != Session B, Watermark A != Watermark B
        assert release_a.session_id != release_b.session_id
        assert release_a.watermark_id != release_b.watermark_id
        assert release_a.signed_event.event.event_id != release_b.signed_event.event.event_id
        assert release_a.ledger_receipt.transaction_id != release_b.ledger_receipt.transaction_id
        assert release_a.signed_event.signature != release_b.signed_event.signature

        # Both events must be committed in the ledger independently
        assert ledger.count_events() == 2
        assert ledger.get_event(release_a.signed_event.event.event_id) is not None
        assert ledger.get_event(release_b.signed_event.event.event_id) is not None

    def test_recipient_separation_alice_and_bob(self, attribution_env):
        env = attribution_env
        alice = env["alice"]
        bob = env["bob"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf(num_pages=1)
        specs = [
            RecipientSpec.from_certificate(alice.kem_certificate),
            RecipientSpec.from_certificate(bob.kem_certificate),
        ]
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=specs,
            root_ca_public_key=root_ca.public_key,
        )

        # Alice decrypts
        release_alice = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )

        # Bob decrypts
        release_bob = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=bob,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )

        assert release_alice.signed_event.event.recipient_id == alice.recipient_id
        assert release_bob.signed_event.event.recipient_id == bob.recipient_id
        assert release_alice.watermark_id != release_bob.watermark_id
        assert release_alice.session_id != release_bob.session_id

    def test_forensic_preparation_link_from_leaked_document(self, attribution_env):
        """Forensic recovery test: extract watermark from PDF, locate event on ledger, and verify."""
        env = attribution_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf(num_pages=2)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        release = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
            watermark_params=WatermarkParameters(embedding_strength=12.0),
        )

        # Investigator receives only the released watermarked PDF
        leaked_pdf = release.watermarked_pdf

        # 1. Blind extraction
        ext_res = WatermarkExtractor.extract_document(leaked_pdf, doc_hash)
        assert ext_res.status == ExtractionStatus.DECODED
        assert ext_res.watermark_id == release.watermark_id

        # 2. Reconstruct extracted payload object
        extracted_payload = ext_res.to_payload()
        assert extracted_payload is not None

        # 3. Lookup and verify attribution through ForensicAttributionLink
        signed_evt, verif_res = ForensicAttributionLink.lookup_and_verify(
            watermark_payload=extracted_payload,
            ledger=ledger,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

        assert signed_evt is not None
        assert signed_evt.event.event_id == release.signed_event.event.event_id
        assert verif_res is not None
        assert verif_res.valid is True
        assert verif_res.document_binding_verified is True
        assert verif_res.watermark_binding_verified is True

    def test_ledger_failure_blocks_release(self, attribution_env):
        env = attribution_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        # Ledger simulating timeout / unknown state
        faulty_ledger = InMemoryLedgerAdapter(simulate_timeout=True)

        pdf_bytes = create_test_pdf(num_pages=1)
        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        with pytest.raises(LedgerCommitRequiredError, match="Document release blocked"):
            RecipientAttributionPipeline.execute_decryption(
                package_input=pkg,
                credentials=alice,
                ledger=faulty_ledger,
                root_ca_public_key=root_ca.public_key,
            )
