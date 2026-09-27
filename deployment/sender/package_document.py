#!/usr/bin/env python3
"""Sender Workstation Packaging Script for TraceCrypt.

Environment B: Responsible for:
- Reading source document
- Computing SHA3-256 hash
- Encrypting document once with AES-256-GCM Content-Encryption Key (CEK)
- Encapsulating CEK independently for each recipient via NIST FIPS 203 ML-KEM-768
- Producing verifiable .tcdist distribution packages
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.identity.certificate import PQCIdentityCertificate


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceCrypt Sender Package Creator")
    parser.add_argument("--input", "-i", required=True, help="Input PDF document path")
    parser.add_argument("--output", "-o", default=None, help="Output .tcdist package path")
    parser.add_argument("--recipient-cert", "-c", required=True, action="append", help="Path to recipient KEM certificate JSON")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[FAIL] Input file not found: {input_path}")
        return 1

    recipients = []
    for c_path in args.recipient_cert:
        cert_data = Path(c_path).read_text(encoding="utf-8")
        cert = PQCIdentityCertificate.model_validate_json(cert_data)
        recipients.append(RecipientSpec(cert))

    out_p = Path(args.output) if args.output else input_path.with_suffix(".tcdist")
    pkg, saved_p = DistributionService.package_document(
        source_input=input_path,
        recipients=recipients,
        output_path=out_p,
    )

    print(f"[SUCCESS] Package created: {saved_p}")
    print(f"Document ID: {pkg.header.document_id}")
    print(f"Recipients:  {len(pkg.header.recipients)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
