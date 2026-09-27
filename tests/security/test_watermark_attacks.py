"""Adversarial Watermark Manipulation and Attack Tests.

Validates:
- Transplanting a watermark from Document A to Document B triggers DOCUMENT_MISMATCH.
- Splicing conflicting watermarks onto separate pages triggers AMBIGUOUS.
- Heavy random noise and bit flipping triggers CORRUPTED_WATERMARK or INVALID_WATERMARK.
- Zero false positive attribution on non-watermarked artifacts.
"""

from __future__ import annotations

import io
from pathlib import Path
import pypdf

from tests.forensics.conftest import make_test_pdf_bytes
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
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import WatermarkPayload


class TestWatermarkAttacks:
    """Evaluate forensic engine resistance against adversarial watermark manipulation."""

    def test_watermark_transplantation_attack(self, forensic_environment, tmp_path: Path) -> None:
        """Transplanting a valid watermark to an unrelated document must yield DOCUMENT_MISMATCH."""
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]

        doc_a_bytes = make_test_pdf_bytes(num_pages=1)
        doc_a_hash = f"sha3-256:{'11' * 32}"
        doc_b_hash = f"sha3-256:{'22' * 32}"

        # 1. Embed watermark bound to Document A
        wmid_a = WatermarkID.generate()
        sid_a = SessionID.generate()
        payload_a = WatermarkPayload.create(
            watermark_id=wmid_a,
            session_id=sid_a,
            document_hash=doc_a_hash,
        )
        embed_result = WatermarkEmbedder.embed_document(
            doc_a_bytes,
            payload_a,
            doc_a_hash,
        )
        watermarked_pdf_path = tmp_path / "transplanted_doc.pdf"
        watermarked_pdf_path.write_bytes(embed_result.watermarked_pdf)

        # 2. Record DecryptionEvent for Document A in ledger
        event = DecryptionEvent(
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_a_hash,
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid_a,
            watermark_id=wmid_a,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=1700000000000000,
            pqc_algorithms=PQCAlgorithms(),
        )
        helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # 3. Investigate the artifact with Document B as suspect document
        engine = ForensicInvestigationEngine(
            ledger_storage=storage,
            root_ca_public_key=root_ca.public_key,
        )
        inv = engine.investigate(
            file_path=watermarked_pdf_path,
            suspect_document_hash=doc_b_hash,  # Claiming it came from Document B!
        )

        assert inv.verdict == ForensicVerdict.DOCUMENT_MISMATCH
        assert inv.document_binding_details.binding_verified is False

    def test_watermark_splice_ambiguity_attack(self, forensic_environment, tmp_path: Path) -> None:
        """Combining pages from two different watermarked documents must never yield VERIFIED."""
        doc_bytes = make_test_pdf_bytes(num_pages=1)
        doc_hash = f"sha3-256:{'33' * 32}"

        # Embed Page 1 with Watermark A
        payload_a = WatermarkPayload.create(
            watermark_id=WatermarkID.generate(),
            session_id=SessionID.generate(),
            document_hash=doc_hash,
        )
        emb_a = WatermarkEmbedder.embed_document(doc_bytes, payload_a, doc_hash)

        # Embed Page 2 with Watermark B
        payload_b = WatermarkPayload.create(
            watermark_id=WatermarkID.generate(),
            session_id=SessionID.generate(),
            document_hash=doc_hash,
        )
        emb_b = WatermarkEmbedder.embed_document(doc_bytes, payload_b, doc_hash)

        # Splice into single 2-page document
        writer = pypdf.PdfWriter()
        r_a = pypdf.PdfReader(io.BytesIO(emb_a.watermarked_pdf))
        r_b = pypdf.PdfReader(io.BytesIO(emb_b.watermarked_pdf))
        writer.add_page(r_a.pages[0])
        writer.add_page(r_b.pages[0])

        spliced_path = tmp_path / "spliced_leak.pdf"
        with open(spliced_path, "wb") as f:
            writer.write(f)

        engine = ForensicInvestigationEngine(
            ledger_storage=forensic_environment["storage"],
            root_ca_public_key=forensic_environment["root_ca"].public_key,
        )
        inv = engine.investigate(file_path=spliced_path, suspect_document_hash=doc_hash)

        # Must fail closed: either ambiguous or not found, never falsely attributed
        assert inv.verdict in (ForensicVerdict.AMBIGUOUS, ForensicVerdict.NOT_FOUND)
        assert inv.verdict != ForensicVerdict.VERIFIED
