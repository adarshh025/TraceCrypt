# Standalone Forensic Proof Bundle (`.tcproof`) Specification

## 1. Specification and Purpose

A **TraceCrypt Proof Bundle** (`.tcproof`) is an immutable, self-contained cryptographic container enabling court-admissible or cross-organizational independent verification of document attribution. The proof bundle contains all cryptographic artifacts necessary for an air-gapped auditor to verify attribution without access to:
- TraceCrypt internal ledger databases
- Investigator workstation state
- Key management stores
- Internet or cloud resources

---

## 2. Container Schema

The bundle is serialized as canonical RFC 8785 JSON:

```json
{
  "bundle_version": "1.0.0",
  "case_id": "cas-f53c12703a8480c1b0edca49f597daec",
  "created_at": 1790503643750331,
  "evidence": {
    "evidence_id": "evd-2223661159b94f58ec48767bfad4043d",
    "sha3_256": "sha3-256:4a1d1b1643212bc594d18bb1fef251b89d4bb1707bd58c039e0e6384ddd1ddcd",
    "filename": "leaked_classified_memo.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 769855,
    "page_count": 2,
    "ingested_at": 1790503643785864
  },
  "extracted_watermark": {
    "version": 1,
    "watermark_id": "wm-9c1f6a1e38c4b7218d34e9f501234567",
    "session_tag": "0102030405060708",
    "document_binding": "aabbccddee",
    "checksum": 43521
  },
  "ledger_proof": {
    "transaction": { ... },
    "block_header": { ... },
    "merkle_proof": {
      "leaf_index": 0,
      "audit_path": [ ... ],
      "leaf_hash": "sha3-256:...",
      "root_hash": "sha3-256:..."
    },
    "commit_certificate": {
      "chain_id": "tracecrypt-forensic-chain",
      "height": 1,
      "round": 0,
      "block_hash": "sha3-256:...",
      "validator_set_hash": "sha3-256:...",
      "votes": [ ... ]
    },
    "validator_set": { ... }
  },
  "recipient_certificate": {
    "serial_number": "cert-11223344556677889900aabbccddeeff",
    "subject_id": "rcp-9c1f...",
    "algorithm": "ML-DSA-65",
    "public_key_bytes": "...",
    "signature": "..."
  },
  "root_ca_public_key_b64": "...",
  "verdict": "VERIFIED",
  "verdict_precedence_rank": 9,
  "bundle_digest": "sha3-256:..."
}
```

---

## 3. Cryptographic Verification Pipeline

The `StandaloneProofVerifier` independently recomputes all mathematical checks from first principles:

1. **Bundle Digest Integrity**: Computes $\text{SHA3-256}(\text{RFC 8785 Canonical Bytes})$ over all bundle fields excluding `bundle_digest` and asserts bitwise equality.
2. **Watermark CRC-16 Check**: Recomputes CRC-16-CCITT over the extracted 30-byte header and verifies against `extracted_watermark.checksum`.
3. **Merkle Inclusion Proof**: Recomputes the transaction leaf hash and verifies the audit path against `block_header.transaction_root`.
4. **Block Header Hash**: Recomputes block header digest and verifies against `block_header.block_hash`.
5. **Commit Certificate Quorum**: Validates that $\ge 2f + 1$ authorized validators from `validator_set` signed the precommit vote for `(height, block_hash)`.
6. **Recipient PKI Validation**: Verifies recipient certificate signature against `root_ca_public_key`.
7. **RFC 8785 Canonicalization & Event Digest**: Reconstructs the canonical DecryptionEvent JSON, recomputes SHA3-256, and verifies matching against `signed_event.event_digest`.
8. **ML-DSA-65 Post-Quantum Signature**: Verifies recipient digital signature using NIST FIPS 204 ML-DSA-65 over canonical event bytes.
9. **Document Binding Consistency**: Recomputes 40-bit binding digest and verifies against watermark payload.
10. **Verdict Recomputation**: Evaluates `VerdictEvaluator` on synthesized evidence and asserts that `recomputed_verdict == bundle.verdict`.
