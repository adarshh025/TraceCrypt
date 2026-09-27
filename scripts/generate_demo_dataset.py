#!/usr/bin/env python3
"""Synthetic Demo Dataset Generator for SIH 2026 Evaluation.

Generates 5 realistic synthetic demonstration PDF documents:
1. Government Memorandum
2. Corporate Confidential Report
3. Research Document
4. Defense-Style Restricted Document
5. Financial Audit Report

All documents are marked: 'DEMO DATA — NOT REAL SENSITIVE INFORMATION'.
"""

from __future__ import annotations

import io
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "docs" / "demo"


def create_demo_pdf(
    filename: str,
    title: str,
    doc_type: str,
    classification: str,
    paragraphs: list[str],
) -> Path:
    """Generate a clean, structured synthetic PDF document with clear demonstration banners."""
    out_path = DEMO_DIR / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    c = canvas.Canvas(str(out_path), pagesize=letter)
    width, height = letter

    # Banner Header
    c.setFillColor(colors.HexColor("#B71C1C"))
    c.rect(0, height - 32, width, 32, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width / 2.0, height - 20, f"*** DEMO DATA — NOT REAL SENSITIVE INFORMATION — {classification} ***")

    # Document Header
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(54, height - 70, title)

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.HexColor("#555555"))
    c.drawString(54, height - 90, f"Document Classification: {classification} | Type: {doc_type}")
    c.drawString(54, height - 104, "Hackathon: Smart India Hackathon 2026 (SIH 2026) | Problem ID: SIH26237")
    c.drawString(54, height - 118, "Team: Team Laccha Paratha (ID: 138638) | Platform: TraceCrypt Offline Engine")

    # Horizontal Rule
    c.setStrokeColor(colors.HexColor("#CCCCCC"))
    c.setLineWidth(1)
    c.line(54, height - 130, width - 54, height - 130)

    # Document Content Body
    y = height - 160
    for para in paragraphs:
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.black)

        # Word wrap manually for standard margins
        words = para.split(" ")
        line = []
        for word in words:
            line.append(word)
            text_line = " ".join(line)
            if c.stringWidth(text_line, "Helvetica", 10) > (width - 108):
                line.pop()
                c.drawString(54, y, " ".join(line))
                y -= 14
                line = [word]
        if line:
            c.drawString(54, y, " ".join(line))
            y -= 22

        if y < 80:
            # New page if needed
            c.showPage()
            y = height - 70

    # Banner Footer
    c.setFillColor(colors.HexColor("#B71C1C"))
    c.rect(0, 0, width, 24, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 9)
    c.drawCentredString(width / 2.0, 8, "SIH 2026 EVALUATION DATASET — TRACECRYPT CRYPTOGRAPHIC ATTRIBUTION PLATFORM")

    c.save()
    return out_path


def main() -> None:
    print(f"Generating synthetic demonstration dataset in {DEMO_DIR}...")

    # 1. Government Memorandum
    create_demo_pdf(
        filename="govt_memorandum.pdf",
        title="Cabinet Secretariat Memorandum: PQC Transition",
        doc_type="Government Memorandum",
        classification="OFFICIAL USE ONLY / DEMO",
        paragraphs=[
            "MEMORANDUM FOR HEADS OF ALL PRINCIPAL DEPARTMENTS AND AGENCIES.",
            "Subject: Mandatory Migration to Post-Quantum Cryptographic Standards (NIST FIPS 203 & 204).",
            "1. Purpose: This memorandum provides binding executive guidance for transitioning air-gapped critical infrastructure and defense data networks to post-quantum cryptographic primitives.",
            "2. Mandate: All document distribution workflows handling sensitive sovereign policy documents must enforce NIST FIPS 203 (ML-KEM-768) key encapsulation and NIST FIPS 204 (ML-DSA-65) digital signatures.",
            "3. Provenance and Attribution: Multi-recipient distributed documents must incorporate forensic invisible watermarking bound cryptographically to recipient decryptions to enforce legal accountability.",
            "4. Air-Gap Requirement: Telemetry, cloud key management systems (KMS), and public blockchains are strictly prohibited from critical document enclaves.",
        ],
    )

    # 2. Corporate Confidential Report
    create_demo_pdf(
        filename="corporate_confidential.pdf",
        title="Acme Global: 2026 Strategic M&A Expansion Report",
        doc_type="Corporate Confidential Report",
        classification="CONFIDENTIAL / RESTRICTED DEMO",
        paragraphs=[
            "EXECUTIVE COMMITTEE STRATEGIC MERGERS & ACQUISITIONS BRIEFING.",
            "Target Asset: Apex Advanced Aerospace Systems Private Limited.",
            "1. Financial Valuation: Project Vulcan enterprise valuation is estimated at INR 4,850 Crores based on audited EBITDA multiples of FY 2024-25.",
            "2. Board Restructuring: Acquisition terms mandate a 60% majority equity transfer with existing founders retaining executive operations for a 36-month earn-out milestone.",
            "3. Non-Disclosure Covenant: Recipients of this document are legally bound by bilateral non-disclosure agreements. Unlawful exfiltration will result in civil litigation and immediate termination.",
            "4. Traceability: This confidential package is monitored via TraceCrypt per-decryption attribution to prevent unauthorized distribution to competing bidding consortiums.",
        ],
    )

    # 3. Research Whitepaper
    create_demo_pdf(
        filename="research_whitepaper.pdf",
        title="DWT-DCT Frequency-Domain Forensic Watermarking",
        doc_type="Technical Research Paper",
        classification="ACADEMIC / RESEARCH DEMO",
        paragraphs=[
            "ABSTRACT: Digital document distribution across untrusted channels demands forensic watermarking that survives lossy print-scan-photocopy pipelines while maintaining imperceptibility.",
            "1. Methodology: We evaluate a 2-level Discrete Wavelet Transform (DWT-2D) coupled with block Discrete Cosine Transform (DCT) mid-frequency spread-spectrum modulation. Reed-Solomon RS(32, 16) error correction coding provides robust forward recovery.",
            "2. Fidelity Metrics: Empirical testing confirms Peak Signal-to-Noise Ratio (PSNR) exceeding 44.2 dB and Structural Similarity Index (SSIM) above 0.98, rendering watermarked documents visually identical to original counterparts.",
            "3. Experimental Results: The extraction engine recovers complete 256-bit payloads under JPEG compression down to Quality 65 and Gaussian filtering without requiring access to original source documents.",
        ],
    )

    # 4. Defense-Style Restricted Document
    create_demo_pdf(
        filename="defense_restricted.pdf",
        title="Joint Operations Command: Tactical Grid Deployment",
        doc_type="Defense Operational Plan",
        classification="RESTRICTED DEFENSE DEMO",
        paragraphs=[
            "RESTRICTED OPERATIONAL DIRECTIVE — AIR-GAPPED COMMUNICATIONS INFRASTRUCTURE.",
            "Theater of Operations: Northern Command Strategic Sector 4.",
            "1. Communication Invariant: All tactical battlefield tactical terminals must operate with physical Ethernet disconnects and disabled RF transmitters. Data exchange occurs exclusively via certified write-once physical media.",
            "2. Cryptographic Assurance: Content encryption must enforce AES-256-GCM authenticated encryption with ephemeral nonces. Key distribution across mobile units requires quantum-resistant encapsulation.",
            "3. Forensic Non-Repudiation: Any classified operational briefing leaked outside authorized military command channels must be uniquely traceable to the originating recipient terminal via immutable ledger audit proofs.",
        ],
    )

    # 5. Financial Audit Report
    create_demo_pdf(
        filename="financial_audit.pdf",
        title="Reserve Audit: Sovereign Institutional Holdings",
        doc_type="Financial Audit Report",
        classification="COMMERCIALLY SENSITIVE DEMO",
        paragraphs=[
            "INDEPENDENT STATUTORY AUDITOR'S REPORT TO THE GOVERNING BOARD.",
            "Fiscal Year Period: 2025-2026 Annual Comprehensive Financial Review.",
            "1. Audit Opinion: In our professional opinion, the accompanying financial schedules present fairly, in all material respects, the audited sovereign asset holdings totaling INR 182,400 Crores.",
            "2. Digital Asset Security: Institutional custodians confirmed zero usage of public decentralized ledgers for sovereign asset registry, relying instead on permissioned 4-node Byzantine fault-tolerant consensus.",
            "3. Traceability Compliance: Decryption event audits confirmed complete reconciliation between physical document releases and cryptographically signed ledger transactions.",
        ],
    )

    print("All 5 synthetic demo documents successfully generated:")
    for f in DEMO_DIR.glob("*.pdf"):
        print(f"  -> {f.name} ({f.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
