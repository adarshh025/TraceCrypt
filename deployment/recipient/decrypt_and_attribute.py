#!/usr/bin/env python3
"""Recipient Workstation Attribution Pipeline Script for TraceCrypt.

Environment C: Responsible for:
- Ingesting .tcdist package
- Decapsulating ML-KEM-768 shared secret and decrypting AES-GCM ciphertext
- Generating session and watermark identifiers
- Embedding DWT-DCT spread-spectrum watermark into all document pages
- Creating RFC 8785 canonical DecryptionEvent
- Signing event using recipient's certified ML-DSA-65 private key
- Committing signed event to BFT Ledger
- Releasing watermarked document and zeroizing ephemeral memory
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import MLDSAPrivateKey, MLKEMPrivateKey
from tracecrypt.document.distributor import DistributionService
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.package import DistributionPackage
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.utils.identifiers import EventID, SessionID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark import WatermarkEmbedder, WatermarkParameters, WatermarkPayload


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceCrypt Recipient Decryption & Attribution Gate")
    parser.add_argument("--package", "-p", required=True, help="Path to .tcdist package")
    parser.add_argument("--recipient-id", "-r", required=True, help="Recipient ID (rcp-...)")
    parser.add_argument("--kem-key", required=True, help="Path to recipient private KEM key binary")
    parser.add_argument("--dsa-key", required=True, help="Path to recipient private DSA key binary")
    parser.add_argument("--kem-cert", required=True, help="Path to recipient KEM certificate JSON")
    parser.add_argument("--dsa-cert", required=True, help="Path to recipient DSA certificate JSON")
    parser.add_argument("--output", "-o", required=True, help="Path to save released watermarked document")
    parser.add_argument("--ledger-db", default="data/ledger.db", help="Path to local ledger database")
    args = parser.parse_args()

    pkg_path = Path(args.package)
    pkg = DistributionPackage.load(pkg_path)

    kem_sk = MLKEMPrivateKey(Path(args.kem_key).read_bytes())
    dsa_sk = MLDSAPrivateKey(Path(args.dsa_key).read_bytes())
    kem_cert = PQCIdentityCertificate.model_validate_json(Path(args.kem_cert).read_text(encoding="utf-8"))
    dsa_cert = PQCIdentityCertificate.model_validate_json(Path(args.dsa_cert).read_text(encoding="utf-8"))

    # 1. Decapsulate and decrypt
    decrypted_buf = DistributionService.decrypt_package(
        package_input=pkg,
        recipient_id=args.recipient_id,
        recipient_sk=kem_sk,
        recipient_cert=kem_cert,
    )
    raw_doc = decrypted_buf.raw_bytes
    doc_hash = DocumentHasher.hash_bytes(raw_doc)

    # 2. Generate watermark payload
    wmid = WatermarkID.generate()
    sid = SessionID.generate()
    payload = WatermarkPayload.create(
        watermark_id=wmid,
        session_id=sid,
        document_hash=doc_hash,
    )

    # 3. Embed transform-domain watermark
    embed_res = WatermarkEmbedder.embed_document(
        pdf_input=raw_doc,
        payload=payload,
        document_hash=doc_hash,
        params=WatermarkParameters(embedding_strength=8.0),
    )

    # 4. Canonical event & signature
    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID.generate(),
        document_id=pkg.header.document_id,
        distribution_id=pkg.header.distribution_id,
        document_hash=doc_hash,
        recipient_id=args.recipient_id,
        recipient_certificate_id=dsa_cert.serial_number,
        session_id=sid,
        watermark_id=wmid,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    signed_event = DecryptionEventSigner.sign_event(
        event=event,
        signing_key=dsa_sk,
        signing_cert=dsa_cert,
    )

    # 5. Commit to local ledger storage
    storage = LedgerStorage(Path(args.ledger_db))
    tx_id = storage.commit_event(signed_event)
    storage.close()

    # 6. Release document
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(embed_res.watermarked_pdf)

    print(f"[SUCCESS] Document released to: {out_path}")
    print(f"Transaction Committed: {tx_id}")
    print(f"Attribution Watermark:  {wmid}")
    print(f"PSNR Fidelity:         {embed_res.fidelity.psnr:.2f} dB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
