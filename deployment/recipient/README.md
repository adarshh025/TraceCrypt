# Environment C: Recipient Workstation

## Purpose
The Recipient Workstation enforces the mandatory attribution gate before a decrypted document can be viewed or released:
1. Ingests `.tcdist` package.
2. Unlocks recipient private keys using Argon2id-derived key wrapping.
3. Decapsulates ML-KEM-768 shared secret and decrypts AES-256-GCM document payload.
4. Synthesizes a unique forensic watermark embedding session (`SessionID`, `WatermarkID`).
5. Embeds DWT-DCT spread-spectrum forensic watermark using Reed-Solomon RS(32, 16) error correction into the document pages.
6. Encodes an RFC 8785 canonical `DecryptionEvent` binding the recipient identity, document hash, watermark ID, and session.
7. Digitally signs the event using the recipient's ML-DSA-65 private key.
8. Commits the signed attribution event to the local replicated BFT ledger.
9. Releases the watermarked document only after atomic confirmation of the ledger commitment.
10. Explicitly zeroizes all plaintext buffers and intermediate secret keys.

## Operational Workflow
```bash
# Execute the atomic recipient decryption and attribution release gate
python deployment/recipient/decrypt_and_attribute.py \
  --package "C:\Inbox\Classified_Briefing.tcdist" \
  --recipient-id "rcp-FIELD-OPERATIVE-01" \
  --kem-key "C:\Keys\rcp_kem.bin" \
  --dsa-key "C:\Keys\rcp_dsa.bin" \
  --kem-cert "C:\Certs\rcp_kem_cert.json" \
  --dsa-cert "C:\Certs\rcp_dsa_cert.json" \
  --output "C:\Released\Classified_Briefing_Personalized.pdf"
```
