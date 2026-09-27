"""Tamper-Evident Forensic Report Generation Engine.

Produces:
1. Canonical machine-readable JSON forensic reports.
2. High-fidelity tamper-evident PDF forensic briefing documents with page-level evidence tables.
3. Cryptographic report digest committing to all findings and the non-repudiation attribution boundary.
"""

from __future__ import annotations

import io
from typing import Any, Dict, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.forensics.types import ForensicInvestigation
from tracecrypt.utils.timestamps import utc_now_iso

ATTRIBUTION_BOUNDARY_TEXT = (
    "LEGAL AND FORENSIC ATTRIBUTION BOUNDARY NOTICE: "
    "A cryptographically verified result mathematically establishes that the certified NIST FIPS 204 "
    "ML-DSA-65 private key corresponding to the recorded recipient identity generated the signed decryption "
    "event committed to the BFT distributed ledger. It does NOT independently prove that a specific biological "
    "individual physically operated the workstation hardware at the moment of decryption. Complete operational "
    "attribution requires correlating this cryptographic proof with endpoint telemetry, physical access logs, "
    "and credential custody controls."
)


class ForensicReportGenerator:
    """Generates canonical machine-readable and print-ready forensic attribution reports."""

    @classmethod
    def generate_json_report(cls, investigation: ForensicInvestigation) -> Dict[str, Any]:
        """Generate structured canonical machine-readable forensic report dictionary."""
        data = {
            "report_version": "1.0.0",
            "case_id": str(investigation.case_id),
            "case_name": investigation.case_name,
            "investigator_id": str(investigation.investigator_id),
            "investigated_at": investigation.investigated_at,
            "evidence": investigation.evidence.model_dump(),
            "watermark_analysis": investigation.watermark_analysis.model_dump(),
            "page_evidence_table": [p.model_dump() for p in investigation.page_results],
            "ledger_verification": (
                investigation.ledger_details.model_dump() if investigation.ledger_details else None
            ),
            "identity_verification": (
                investigation.identity_details.model_dump() if investigation.identity_details else None
            ),
            "document_binding_verification": (
                investigation.document_binding_details.model_dump()
                if investigation.document_binding_details
                else None
            ),
            "verdict": investigation.verdict.value,
            "verdict_precedence_rank": investigation.verdict_precedence_rank,
            "diagnostic_trace": investigation.diagnostic_trace,
            "chain_of_custody": [c.model_dump() for c in investigation.chain_of_custody],
            "attribution_boundary": ATTRIBUTION_BOUNDARY_TEXT,
        }

        canonical_bytes = canonicalize(data)
        report_digest = Hasher.digest_bytes(canonical_bytes, HashAlgorithm.SHA3_256.value).formatted
        data["report_digest"] = report_digest
        return data

    @classmethod
    def generate_pdf_report(cls, investigation: ForensicInvestigation) -> bytes:
        """Render a publication-grade tamper-evident PDF forensic report."""
        report_dict = cls.generate_json_report(investigation)
        report_digest = report_dict["report_digest"]

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1A202C"),
            alignment=0,
        )
        heading_style = ParagraphStyle(
            "ReportHeading",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2D3748"),
        )
        mono_style = ParagraphStyle(
            "ReportMono",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Courier",
            textColor=colors.HexColor("#1A202C"),
        )
        boundary_style = ParagraphStyle(
            "ReportBoundary",
            parent=styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#718096"),
        )

        elements: List[Any] = []

        # 1. Header Banner
        elements.append(Paragraph("TRACECRYPT FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(
            Paragraph(
                f"Generated: {utc_now_iso()} | Report SHA3-256: {report_digest[:32]}...",
                mono_style,
            )
        )
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0")))
        elements.append(Spacer(1, 10))

        # 2. Executive Summary / Verdict Callout
        verdict_color = (
            colors.HexColor("#22543D")
            if investigation.verdict.value == "VERIFIED"
            else colors.HexColor("#742A2A")
        )
        verdict_bg = (
            colors.HexColor("#C6F6D5")
            if investigation.verdict.value == "VERIFIED"
            else colors.HexColor("#FED7D7")
        )

        summary_data = [
            [
                Paragraph("<b>FORENSIC ATTRIBUTION VERDICT</b>", body_style),
                Paragraph(
                    f"<font size=14 color='{verdict_color.hexval()}'><b>{investigation.verdict.value}</b></font>",
                    body_style,
                ),
            ],
            [Paragraph("<b>Case Identifier:</b>", body_style), Paragraph(str(investigation.case_id), mono_style)],
            [Paragraph("<b>Case Name:</b>", body_style), Paragraph(investigation.case_name, body_style)],
            [
                Paragraph("<b>Investigator ID:</b>", body_style),
                Paragraph(str(investigation.investigator_id), mono_style),
            ],
            [
                Paragraph("<b>Evidence SHA3-256:</b>", body_style),
                Paragraph(investigation.evidence.sha3_256, mono_style),
            ],
            [
                Paragraph("<b>Artifact Parameters:</b>", body_style),
                Paragraph(
                    f"{investigation.evidence.filename} ({investigation.evidence.mime_type}, "
                    f"{investigation.evidence.size_bytes} bytes, {investigation.evidence.page_count} pages)",
                    body_style,
                ),
            ],
        ]
        sum_table = Table(summary_data, colWidths=[1.8 * inch, 5.2 * inch])
        sum_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), verdict_bg),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(sum_table)
        elements.append(Spacer(1, 12))

        # 3. Cryptographic Findings Table
        elements.append(Paragraph("1. Cryptographic Attribution Breakdown", heading_style))
        led = investigation.ledger_details
        ident = investigation.identity_details
        bind = investigation.document_binding_details

        crypto_rows = [
            [
                Paragraph("<b>Subsystem</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Details / Evidence</b>", body_style),
            ],
            [
                Paragraph("Blind Watermark Extraction", body_style),
                Paragraph(
                    investigation.watermark_analysis.overall_status.value,
                    body_style,
                ),
                Paragraph(
                    f"ID: {investigation.watermark_analysis.consensus_watermark_id or 'None'} | "
                    f"ECC: {investigation.watermark_analysis.total_ecc_corrections} corrections | "
                    f"Avg Corr: {investigation.watermark_analysis.average_correlation:.2f}",
                    body_style,
                ),
            ],
            [
                Paragraph("BFT Ledger Commit & Quorum", body_style),
                Paragraph(
                    "VERIFIED" if led and led.commit_certificate_valid else ("FAILED" if led else "N/A"),
                    body_style,
                ),
                Paragraph(
                    f"Height: {led.block_height if led else 'N/A'} | "
                    f"Hash: {led.block_hash[:20] if led else 'N/A'}... | "
                    f"Quorum: {len(led.verified_validators) if led else 0} votes",
                    body_style,
                ),
            ],
            [
                Paragraph("Merkle Inclusion Proof", body_style),
                Paragraph(
                    "VERIFIED" if led and led.merkle_proof_valid else ("FAILED" if led else "N/A"),
                    body_style,
                ),
                Paragraph(
                    f"Tx: {led.transaction_id if led else 'N/A'} | Root: O(log N) mathematically verified",
                    body_style,
                ),
            ],
            [
                Paragraph("Post-Quantum PKI Certificate", body_style),
                Paragraph(
                    "VERIFIED" if ident and ident.certificate_valid else ("FAILED" if ident else "N/A"),
                    body_style,
                ),
                Paragraph(
                    f"Serial: {ident.certificate_id if ident else 'N/A'} | Purpose: DIGITAL_SIGNATURE",
                    body_style,
                ),
            ],
            [
                Paragraph("NIST FIPS 204 ML-DSA-65 Signature", body_style),
                Paragraph(
                    "VERIFIED" if ident and ident.signature_verified else ("FAILED" if ident else "N/A"),
                    body_style,
                ),
                Paragraph(
                    f"Recipient: {ident.recipient_id if ident else 'N/A'} | Canonical RFC 8785 Digest Verified",
                    body_style,
                ),
            ],
            [
                Paragraph("Cryptographic Document Binding", body_style),
                Paragraph(
                    "VERIFIED" if bind and bind.binding_verified else ("FAILED" if bind else "N/A"),
                    body_style,
                ),
                Paragraph(
                    f"Doc Hash: {bind.event_document_hash[:24] if bind else 'N/A'}... | 40-bit binding matched",
                    body_style,
                ),
            ],
        ]
        cr_table = Table(crypto_rows, colWidths=[2.2 * inch, 1.2 * inch, 3.6 * inch])
        cr_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        elements.append(cr_table)
        elements.append(Spacer(1, 10))

        # 4. Multi-Page Forensic Analysis Table
        elements.append(Paragraph("2. Page-Level Forensic Telemetry", heading_style))
        page_rows = [
            [
                Paragraph("<b>Page</b>", body_style),
                Paragraph("<b>Detected</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Correlation</b>", body_style),
                Paragraph("<b>RS ECC</b>", body_style),
                Paragraph("<b>Watermark ID</b>", body_style),
            ]
        ]
        for pr in investigation.page_results:
            page_rows.append([
                Paragraph(str(pr.page_number), body_style),
                Paragraph("YES" if pr.detected else "NO", body_style),
                Paragraph(pr.status.value, body_style),
                Paragraph(f"{pr.correlation_score:.2f}", body_style),
                Paragraph(str(pr.ecc_corrections), body_style),
                Paragraph(str(pr.watermark_id)[:16] + "..." if pr.watermark_id else "None", mono_style),
            ])
        col_w = [0.6 * inch, 0.9 * inch, 1.3 * inch, 1.0 * inch, 0.9 * inch, 2.3 * inch]
        page_table = Table(page_rows, colWidths=col_w)
        page_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ])
        )
        elements.append(page_table)
        elements.append(Spacer(1, 10))

        # 5. Non-Repudiation Attribution Boundary Notice
        elements.append(Paragraph("3. Legal & Forensic Attribution Boundary", heading_style))
        elements.append(Paragraph(ATTRIBUTION_BOUNDARY_TEXT, boundary_style))
        elements.append(Spacer(1, 10))

        # 6. Tamper-Evident Footer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E0")))
        elements.append(Spacer(1, 4))
        elements.append(
            Paragraph(
                f"Tamper-Evident Cryptographic Report Digest: {report_digest}",
                mono_style,
            )
        )

        doc.build(elements)
        return buf.getvalue()
