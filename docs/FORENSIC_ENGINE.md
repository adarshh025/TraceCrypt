# TraceCrypt Forensic Investigation Engine

## 1. Overview and Architectural Scope

The **TraceCrypt Forensic Investigation Engine** provides an offline, deterministic, tamper-evident document attribution pipeline for leaked artifacts. Operating without requiring the original pristine plaintext, candidate recipient lists, internet connectivity, or external trust anchors, the engine blindly extracts robust frequency-domain watermarks from physical or digital document leaks (PDF, PNG, JPEG, TIFF) and performs rigorous 12-point cryptographic verification against a replicated permissioned Byzantine Fault Tolerant (BFT) ledger.

```text
               LEAKED DOCUMENT ARTIFACT (PDF, PNG, JPEG, TIFF)
                                     │
                                     ▼
                        [1. Evidence Ingestion]
                     (Immutable read, SHA3-256 digest)
                                     │
                                     ▼
                    [2. Deterministic Normalization]
               (Grayscale luminance, 16px grid alignment)
                                     │
                                     ▼
                   [3. Blind Frequency Extraction]
                 (2D Haar DWT + 8x8 Block DCT + PN Seq)
                                     │
                                     ▼
                   [4. Reed-Solomon RS(32,16) ECC]
               (Payload recovery, CRC-16 integrity check)
                                     │
                                     ▼
                 [5. Multi-Page Aggregation & Splice]
             (Corroboration isolation, ambiguity detection)
                                     │
                                     ▼
                 [6. Replicated BFT Ledger Lookup]
               (Keyed by recovered 128-bit WatermarkID)
                                     │
                                     ▼
                     [7. Merkle Inclusion Proof]
           (Leaf hash verification to block transaction root)
                                     │
                                     ▼
                   [8. BFT Commit Certificate Check]
          (2f + 1 validator quorum, ML-DSA-65 signatures)
                                     │
                                     ▼
                 [9. 11-Point Offline PKI Validation]
               (Offline Root CA trust chain, revocation)
                                     │
                                     ▼
                [10. RFC 8785 Canonical Event Verify]
                 (Deterministic JSON, SHA3-256 digest)
                                     │
                                     ▼
               [11. Recipient ML-DSA-65 Event Verify]
            (Post-quantum signature verification on digest)
                                     │
                                     ▼
                 [12. 40-Bit Document Binding Gate]
             (Cryptographic binding to suspect document)
                                     │
                                     ▼
                 [Deterministic 9-State Closed Verdict]
                                     │
             ┌───────────────────────┴───────────────────────┐
             ▼                                               ▼
   Standalone Proof Bundle                       Tamper-Evident Report
         (.tcproof)                                   (PDF & JSON)
```

---

## 2. Ingestion and Evidence Chain of Custody

The engine ingests candidate leaked evidence in read-only mode, computing an immutable SHA3-256 fingerprint upon arrival:
- **Zero Evidence Mutation**: Original files are opened strictly in binary read mode (`rb`). Working representations are held in memory or isolated temporary scratch buffers.
- **Custody Hash Chaining**: Every lifecycle event (`INGESTED`, `NORMALIZED`, `ANALYZED`, `VERIFIED`, `EXPORTED`) appends to an internal cryptographic hash chain:
  $$\text{Hash}_i = \text{SHA3-256}\left(\text{"tracecrypt:custody:v1:"} \parallel i \parallel \text{Action} \parallel \text{ActorID} \parallel \text{Timestamp} \parallel \text{EvidenceHash} \parallel \text{Hash}_{i-1}\right)$$

---

## 3. Cryptographic Verification State Machine

The verification order is strictly deterministic and fail-closed:
1. **Multi-page Ambiguity Gate**: If conflicting watermarks exist across pages, emits `AMBIGUOUS`.
2. **Signal Floor Gate**: If no watermark carrier is detected above threshold, emits `UNVERIFIABLE`.
3. **ECC Threshold Gate**: If watermark signal is detected but symbol corruption exceeds RS(32,16) capability, emits `CORRUPTED_WATERMARK`.
4. **Structural CRC-16 Gate**: If payload is recovered but fails CRC-16 checksum, emits `INVALID_WATERMARK`.
5. **Ledger Lookup Gate**: If WatermarkID does not exist on the committed ledger, emits `NOT_FOUND`.
6. **Consensus & Block Integrity Gate**: If block header hash, chain linkage, Merkle inclusion proof, or BFT commit certificate quorum fails, emits `LEDGER_INVALID`.
7. **Identity & Signature Gate**: If recipient certificate is expired/revoked, or ML-DSA-65 signature fails verification over RFC 8785 canonical bytes, emits `SIGNATURE_INVALID`.
8. **Document Binding Gate**: If 40-bit binding digest does not bind to the document, emits `DOCUMENT_MISMATCH`.
9. **Full Cryptographic Attestation**: When all 12 cryptographic verification gates pass, emits `VERIFIED`.

---

## 4. Standalone Proof Bundles (`.tcproof`)

Investigations can be exported as standalone, self-contained `.tcproof` bundles containing:
- Case metadata and SHA3-256 evidence fingerprint
- Extracted watermark payload (WatermarkID, Session tag, Document binding, CRC-16)
- Committed ledger transaction and RFC 8785 canonical event bytes
- Block header and Merkle tree inclusion path
- BFT Commit Certificate with 2f+1 validator signatures
- Recipient identity certificate and Offline Root CA public key
- Cryptographic SHA3-256 canonical bundle digest

The bundle can be independently evaluated on an isolated air-gapped machine using `StandaloneProofVerifier` without workstation database access.

---

## 5. Non-Repudiation Attribution Boundary

> **LEGAL AND FORENSIC DISCLAIMER**:
> A forensic verdict of `VERIFIED` cryptographically establishes that the certified post-quantum private key (NIST FIPS 204 ML-DSA-65) assigned to the specified recipient identity was used to sign the decryption authorization event registered on the immutable BFT consensus ledger corresponding to the recovered frequency-domain watermark.
>
> It does **not** independently prove the biological identity of the human operator physically controlling the workstation at the moment of decryption. Operational attribution depends on workstation physical security, hardware security module access policies, OS user authentication, and organizational custodial controls.
