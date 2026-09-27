# TraceCrypt Deterministic 9-State Forensic Verdict Model

## 1. Closed Verdict Space

TraceCrypt rejects subjective confidence scores, heuristics, probabilistic match percentages, and fuzzy thresholds for forensic attribution. Every forensic investigation deterministically evaluates to **exactly one of nine closed verdict states**:

| Verdict Enum | Precedence Rank | Description | Fail-Closed Rationale |
| :--- | :---: | :--- | :--- |
| `AMBIGUOUS` | 1 (Highest) | Multiple conflicting valid watermark identities detected across pages | Prevents picking a guess between conflicting splices |
| `UNVERIFIABLE` | 2 | No recoverable frequency watermark signal detected above noise floor | Insufficient signal for cryptographically sound extraction |
| `CORRUPTED_WATERMARK` | 3 | Watermark carrier signal detected, but symbol errors exceed RS(32,16) ECC capacity | Payload unrecoverable due to distortion or tampering |
| `INVALID_WATERMARK` | 4 | Payload recovered, but fails CRC-16 checksum or structural schema validation | Defective or forged bitstream payload |
| `NOT_FOUND` | 5 | WatermarkID recovered and valid, but no matching transaction exists on committed ledger | Artifact not issued through this ledger cluster |
| `LEDGER_INVALID` | 6 | Ledger transaction found, but block hash, chain linkage, Merkle proof, or BFT commit fails | Tampered ledger history or broken BFT consensus |
| `SIGNATURE_INVALID` | 7 | Decryption event found, but recipient certificate or ML-DSA-65 signature is invalid | Forged or corrupted recipient authorization event |
| `DOCUMENT_MISMATCH` | 8 | Watermark, signature, and ledger valid, but watermark binding digest contradicts document hash | Watermark belongs to a different document context |
| `VERIFIED` | 9 (Lowest) | All 12 cryptographic verification gates pass cleanly | Deterministic proof of certified recipient decryption |

No tenth verdict exists. No `probably_verified`, `high_confidence`, or heuristic score is ever emitted.

---

## 2. Verdict Evaluation Precedence Architecture

The precedence order is implemented in `VerdictEvaluator` (`tracecrypt/forensics/verdict.py`):

```text
Evidence Ingestion & Page Normalization
                   │
                   ▼
       [Multi-Page Splice Check]
      Conflicting valid watermarks? ──────► [AMBIGUOUS]
                   │ No
                   ▼
          [Signal Floor Check]
       Carrier correlation < floor? ──────► [UNVERIFIABLE]
                   │ No
                   ▼
           [ECC Capacity Check]
       RS(32,16) symbols unrecoverable? ──► [CORRUPTED_WATERMARK]
                   │ No
                   ▼
          [Structural CRC Check]
        CRC-16 checksum invalid? ─────────► [INVALID_WATERMARK]
                   │ No
                   ▼
           [Ledger Record Check]
        Transaction ID not on ledger? ────► [NOT_FOUND]
                   │ No
                   ▼
      [Consensus & Integrity Check]
      Block, Merkle, or Quorum fail? ─────► [LEDGER_INVALID]
                   │ No
                   ▼
        [PKI & Signature Check]
     Cert expired/revoked, ML-DSA fail? ──► [SIGNATURE_INVALID]
                   │ No
                   ▼
       [Document Binding Check]
     40-bit binding digest mismatch? ─────► [DOCUMENT_MISMATCH]
                   │ No
                   ▼
      [Full Cryptographic Attestation] ───► [VERIFIED]
```

---

## 3. Mathematical and Invariant Properties

1. **Determinism**: Given artifact $A$, ledger state $L$, and Root CA key $K_{\text{CA}}$, the verdict function $V(A, L, K_{\text{CA}})$ yields an identical verdict and diagnostic trace across all runs.
2. **Monotonic Failure Precedence**: If both an integrity failure and an attribution failure occur, the integrity failure always takes strict precedence.
3. **No Heuristic Override**: Neither investigator input, CLI flags, nor case metadata can force a `VERIFIED` verdict if any underlying cryptographic gate fails.
