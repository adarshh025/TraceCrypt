# TraceCrypt Air-Gapped Quickstart Guide

This quickstart guides you through the full end-to-end operational lifecycle on an offline, air-gapped workstation:

```text
Root CA Initialization
         ↓
Certified Identities (Sender & Recipient)
         ↓
Document Encryption & Distribution Packaging (.tcdist)
         ↓
Recipient Atomic Decryption & Watermarking
         ↓
BFT Ledger Event Commitment
         ↓
Blind Forensic Investigation of Leaked Artifact
         ↓
Independent Standalone Proof Verification (.tcproof)
```

---

## 1. Run System Doctor

Verify the local offline environment before proceeding:

```cmd
python -m tracecrypt.cli doctor
```

All 6 core diagnostic checks must report `[PASS]`.

---

## 2. Initialize the Offline Root CA

Generate the master post-quantum Root CA protected by an Argon2id keystore:

```cmd
python -m tracecrypt.cli ca init --ca-id ca-root-primary --passphrase "EnclaveMasterSecretPassphrase2026!"
```

---

## 3. Enroll Certified Recipient Identity

Generate certified ML-KEM-768 and ML-DSA-65 post-quantum key pairs:

```cmd
python -m tracecrypt.cli identity generate --owner-id rcp-alice-01 --org "Defense Ops" --role RECIPIENT --passphrase "AliceSecretPassphrase2026!" --ca-passphrase "EnclaveMasterSecretPassphrase2026!"
```

---

## 4. Initialize the 4-Node Permissioned BFT Ledger

Set up a local 4-validator offline cluster genesis configuration:

```cmd
python -m tracecrypt.cli ledger init --cluster-dir ./ledger_cluster --chain-id tracecrypt-airgap-1
```

---

## 5. Encrypt and Package Source Document (.tcdist)

Package a classified PDF document for Recipient Alice:

```cmd
python -m tracecrypt.cli document package --input ./briefing.pdf --output ./briefing.tcdist --recipient rcp-alice-01
```

Verify package integrity via 17-point offline validation:

```cmd
python -m tracecrypt.cli document validate ./briefing.tcdist
```

---

## 6. Recipient Decryption, Watermarking, and Release

Simulate recipient decryption through the atomic `DocumentReleaseGate`:

```cmd
python -m tracecrypt.cli decrypt simulate ./briefing.tcdist --recipient rcp-alice-01 --passphrase "AliceSecretPassphrase2026!" --output ./alice_watermarked.pdf
```

The pipeline:
1. Decapsulates the document key using Alice's ML-KEM private key.
2. Decrypts the AES-256-GCM ciphertext.
3. Generates unique 128-bit `SessionID` and `WatermarkID`.
4. Embeds imperceptible DWT-DCT watermark with RS(32,16) error correction into the PDF.
5. Formats the canonical RFC 8785 `DecryptionEvent`.
6. Signs the event using Alice's certified ML-DSA-65 private key.
7. Commits the transaction to the BFT ledger.
8. Releases `alice_watermarked.pdf`.

---

## 7. Blind Forensic Investigation of a Leaked Artifact

When a leaked page or document is discovered (even if compressed or rotated):

```cmd
python -m tracecrypt.cli forensic investigate ./leaked_evidence.png --output-proof ./evidence_case_01.tcproof --output-report ./report_case_01.pdf
```

The forensic engine:
1. Normalizes the raster image and searches skew angles.
2. Blindly extracts the DWT-DCT spread-spectrum signal without needing the original document.
3. Decodes Reed-Solomon RS(32,16) parity and checks the 16-bit CRC.
4. Queries the immutable BFT ledger using the extracted `WatermarkID`.
5. Verifies the cryptographic Merkle tree inclusion proof.
6. Verifies Alice's ML-DSA-65 digital signature and Root CA certificate.
7. Checks the 40-bit document binding tag.
8. Outputs the deterministic verdict (e.g. `VERIFIED`) and exports `./evidence_case_01.tcproof`.

---

## 8. Independent Standalone Proof Verification

Transfer the portable `.tcproof` bundle to an independent verifier workstation (or external legal auditor) holding only the Root CA public key:

```cmd
python -m tracecrypt.cli forensic verify ./evidence_case_01.tcproof
```

Output:
```text
=== Independent Forensic Proof Verification ===
Bundle File: evidence_case_01.tcproof
Proof Status: VALID
Verdict: VERIFIED
Attributed Recipient: rcp-alice-01
Signature Valid: YES (ML-DSA-65)
Ledger Proof Valid: YES (Merkle Root)
Root CA Path: VALID
```
