#!/usr/bin/env python3
"""Investigator Workstation Forensic Adjudication Script for TraceCrypt.

Environment E: Investigator Workstation
- Ingests leaked document artifact (PDF or image)
- Performs immutable evidence hashing & chain of custody tracking
- Blind frequency-domain DWT-DCT watermark extraction
- Reed-Solomon RS(32, 16) error correction & syndrome verification
- Ledger lookup and Merkle inclusion proof verification
- ML-DSA-65 post-quantum signature verification
- Evaluates deterministic nine-verdict decision matrix
- Generates signed forensic PDF report and standalone .tcproof bundle
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.models.domain import CaseID, UserID


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceCrypt Forensic Investigation & Attribution")
    parser.add_argument("--evidence", "-e", required=True, help="Path to leaked document artifact")
    parser.add_argument("--case-id", default=None, help="Case identifier")
    parser.add_argument("--case-name", default="Forensic Attribution Inquiry", help="Investigation title")
    parser.add_argument("--ledger-db", default="data/ledger.db", help="Path to validator ledger database")
    parser.add_argument("--ca-cert", default=None, help="Path to Root CA certificate / public key")
    parser.add_argument("--output-report", "-r", default=None, help="Output path for PDF forensic report")
    parser.add_argument("--output-proof", "-p", default=None, help="Output path for .tcproof bundle")
    parser.add_argument("--doc-hash", default=None, help="Optional document hash hint")
    args = parser.parse_args()

    evidence_path = Path(args.evidence)
    if not evidence_path.exists():
        print(f"[FAIL] Evidence artifact not found: {evidence_path}")
        return 1

    storage = LedgerStorage(Path(args.ledger_db))
    ca_pub = None
    if args.ca_cert and Path(args.ca_cert).exists():
        ca_pub = MLDSAPublicKey(Path(args.ca_cert).read_bytes())

    engine = ForensicInvestigationEngine(
        ledger_storage=storage,
        root_ca_public_key=ca_pub,
    )

    case_id = CaseID(args.case_id) if args.case_id else CaseID.generate()
    inv_id = UserID.generate()

    print(f"[*] Commencing forensic investigation: {case_id}...")
    inv = engine.investigate(
        file_path=evidence_path,
        case_id=case_id,
        case_name=args.case_name,
        investigator_id=inv_id,
        suspect_document_hash=args.doc_hash,
    )

    print("\n" + "=" * 70)
    print("FORENSIC ADJUDICATION COMPLETE")
    print(f"Case ID:               {inv.case_id}")
    print(f"Deterministic Verdict: {inv.verdict.value}")
    if inv.identity_details.recipient_id:
        print(f"Attributed Recipient:  {inv.identity_details.recipient_id}")
    print(f"Evidence SHA3-256:     {inv.evidence.sha3_256}")
    print("=" * 70)

    # Export report and proof bundle
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.output_report) if args.output_report else out_dir / f"report_{case_id}.pdf"
    proof_path = Path(args.output_proof) if args.output_proof else out_dir / f"case_{case_id}.tcproof"

    engine.export_pdf_report(inv, output_path=report_path)
    bundle = engine.export_proof_bundle(inv, output_path=proof_path)

    print(f"[SUCCESS] Forensic PDF Report: {report_path}")
    print(f"[SUCCESS] Proof Bundle:        {proof_path}")

    storage.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
