# TraceCrypt Forensic Engine Threat Model

## 1. Security Objectives

The TraceCrypt Forensic Subsystem provides **cryptographic non-repudiation** and **tamper-evident document attribution** under the following security guarantees:

1. **Blind Recovery**: No requirement for pristine original documents or candidate recipient lists during extraction.
2. **False Attribution Resistance**: A non-watermarked document or unrelated leak must never attribute to an innocent party.
3. **Tamper Resilience**: Direct ledger tampering, Merkle path alteration, forged certificates, or modified block headers must be deterministically rejected.
4. **Air-Gap Operational Security**: Zero network exposure (no cloud calls, external PKI, telemetry, or remote dependencies).
5. **Fail-Closed Execution**: Any ambiguity, corruption, or verification failure results in an explicit non-attribution verdict.

---

## 2. Adversarial Capability Matrix

| Attack Vector | Adversary Action | Forensic Defense | Resulting Verdict |
| :--- | :--- | :--- | :--- |
| **Attack A: Random / Blank Artifact** | Leaker circulates an unwatermarked document or noise image | Detector computes correlation score; if below noise floor, rejects without attribution | `UNVERIFIABLE` |
| **Attack B: Heavy Watermark Distortion** | Leaker applies heavy noise, severe downsampling, or blur | Reed-Solomon RS(32,16) detector detects uncorrectable symbol errors (> 8 symbols) | `CORRUPTED_WATERMARK` |
| **Attack C: Unregistered Watermark** | Adversary injects a syntactically valid watermark with a random WatermarkID | Forensic engine queries local replicated BFT ledger; lookup fails | `NOT_FOUND` |
| **Attack D: Block Header Tampering** | Adversary alters transaction content or height in local SQLite database | Engine recomputes block header SHA3-256 hash and validates chain linkage | `LEDGER_INVALID` |
| **Attack E: Merkle Root Tampering** | Adversary modifies transaction bytes without updating Merkle path | Merkle proof verification independently fails against block `transaction_root` | `LEDGER_INVALID` |
| **Attack F: Commit Certificate Forgery** | Adversary fakes consensus votes or submits insufficient validator signatures | Quorum check validates $\ge 2f + 1$ authorized validator signatures | `LEDGER_INVALID` |
| **Attack G: Event Signature Forgery** | Adversary signs a fake decryption event with an unauthorized private key | ML-DSA-65 post-quantum verification against certified public key fails | `SIGNATURE_INVALID` |
| **Attack H: Document Context Mismatch** | Adversary copies a valid watermark from Document X into leaked Document Y | 40-bit cryptographic document binding check detects mismatch | `DOCUMENT_MISMATCH` |
| **Attack I: Multi-Page Splice** | Leaker combines pages from Recipient A with pages from Recipient B | Multi-page consistency analyzer detects conflicting valid WatermarkIDs | `AMBIGUOUS` |
| **Attack J: Severe Destruction** | Evidence underwent destructive scanning or photocopy degradation | DWT-DCT carrier correlation drops below detection threshold | `UNVERIFIABLE` |

---

## 3. Trust Boundaries

```text
[UNTRUSTED LEAKED ARTIFACT]
          │
          ▼
┌──────────────────────────────────────────────┐
│ TraceCrypt Local Cryptographic Boundary       │
│                                              │
│  [Read-Only Evidence Sandbox]                │
│  [Blind DWT-DCT Extraction]                  │
│  [Deterministic Reed-Solomon Decoder]        │
│  [Replicated BFT Ledger (Local SQLite)]      │
│  [Offline Root CA Public Key]                │
│  [Deterministic 9-State Verdict Engine]      │
│                                              │
└──────────────────────────────────────────────┘
          │
          ▼
[TAMPER-EVIDENT FORENSIC REPORT & STANDALONE PROOF]
```

### Attribution Boundary Notice
A `VERIFIED` verdict proves that the certified ML-DSA-65 private key of the recipient recorded in the ledger committed to the decryption of the document. Operational attribution of the physical individual operating the workstation at that instant is bounded by local physical and endpoint security.
