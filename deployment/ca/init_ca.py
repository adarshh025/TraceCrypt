#!/usr/bin/env python3
"""Root CA / Identity Authority Operational Script for TraceCrypt.

Environment A: Offline trusted authority responsible for:
- Root identity generation (NIST FIPS 204 ML-DSA-65)
- Certificate issuance for Senders, Recipients, and Consensus Validators
- Offline revocation management
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.types import MLDSAPublicKey, MLKEMPublicKey
from tracecrypt.identity.ca import OfflineRootCA


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceCrypt Root CA Role Operations")
    subparsers = parser.add_subparsers(dest="cmd")

    init_p = subparsers.add_parser("init", help="Initialize Root CA")
    init_p.add_argument("--ca-id", default="ca-root-airgap-primary", help="CA identifier")
    init_p.add_argument("--output-dir", default="data/ca", help="Output directory")

    args = parser.parse_args()

    if args.cmd == "init":
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ca = OfflineRootCA.initialize(args.ca_id)
        ca_data = {
            "ca_id": ca.ca_id,
            "public_key_b64": ca.public_key.to_b64(),
            "fingerprint": ca.fingerprint,
        }
        (out / "ca_identity.json").write_text(json.dumps(ca_data, indent=2), encoding="utf-8")
        print(f"[SUCCESS] Root CA initialized: {ca.ca_id}")
        print(f"Fingerprint: {ca.fingerprint}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
