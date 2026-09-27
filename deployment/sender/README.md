# Environment B: Sender Workstation

## Purpose
The Sender Workstation prepares confidential documents for distribution to field recipients:
1. Originates source documents (PDF format).
2. Calculates exact SHA3-256 cryptographic digests without normalization.
3. Encrypts document contents once using an ephemeral 256-bit AES-GCM Content-Encryption Key (CEK).
4. Wraps CEK independently for each authorized recipient using ML-KEM-768 public keys.
5. Assembles and exports the `.tcdist` distribution envelope.

## Operational Workflow
```bash
# 1. Package a confidential briefing document for recipient(s)
python deployment/sender/package_document.py \
  --input "C:\Documents\Classified_Briefing.pdf" \
  --output "C:\Outbox\Classified_Briefing.tcdist" \
  --recipient-cert "C:\Certs\recipient_1_kem_cert.json"

# 2. Or using the unified CLI:
tracecrypt encrypt \
  --input "C:\Documents\Classified_Briefing.pdf" \
  --recipient-cert "C:\Certs\recipient_1_kem_cert.json" \
  --output "C:\Outbox\Classified_Briefing.tcdist"
```
