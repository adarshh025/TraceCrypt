# SIH26237 Problem Statement Requirements Traceability Matrix

**Hackathon:** Smart India Hackathon 2026 (SIH 2026)  
**Problem Statement ID:** `SIH26237`  
**Problem Title:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution  
**Team Name:** Team Laccha Paratha  
**Team ID:** `138638`  
**Team Leader:** Adarsh Aher  

---

## 1. Traceability Mapping Matrix

This document provides complete, bit-for-bit traceability from each individual requirement of Problem Statement **SIH26237** to the corresponding implementation source code, automated test suite, demonstration step, and verifiable evidence artifact.

| Req ID | SIH26237 Requirement | Implementation Details | Relevant Source Files | Test Suite Evidence | Demonstration Step | Generated Evidence Artifact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-01** | **Unique Invisible Forensic Watermark** | 2-level 2D Haar DWT + 8x8 DCT mid-frequency coefficient modulation; PSNR $\ge 40\text{ dB}$, SSIM $\ge 0.90$. | `tracecrypt/watermark/embedder.py`<br>`tracecrypt/watermark/transform.py` | `tests/unit/test_watermark_transform.py`<br>`tests/forensics/test_watermark_detection.py` | Step 4 & 5 (`tracecrypt demo decrypt`) | `decrypted_alice.pdf`<br>`decrypted_bob.pdf` |
| **REQ-02** | **Session-Specific Watermark ID** | Every decryption generates a unique 128-bit CSPRNG `SessionID` and 128-bit `WatermarkID` bound into a 256-bit payload. | `tracecrypt/watermark/types.py`<br>`tracecrypt/crypto/random.py` | `tests/unit/test_watermark_payload.py`<br>`tests/security/test_nonce_security.py` | Step 4 & 5 (Compare Alice vs Bob IDs) | `DecryptionEvent.session_id`<br>`DecryptionEvent.watermark_id` |
| **REQ-03** | **Recipient Cryptographic Binding** | 40-bit cryptographic binding $H(\text{"TraceCrypt"}\|doc\_hash\|ses\|wm)[:5]$ embedded in watermark payload. | `tracecrypt/watermark/types.py`<br>`tracecrypt/document/attribution_pipeline.py` | `tests/security/test_watermark_attacks.py`<br>`tests/forensics/test_document_binding.py` | Step 8 (`tracecrypt demo tamper`) | Verification failure on document transplant (`DOCUMENT_MISMATCH`) |
| **REQ-04** | **Post-Quantum Digital Signatures** | NIST FIPS 204 ML-DSA-65 post-quantum digital signatures over RFC 8785 canonical JSON bytes. | `tracecrypt/crypto/pqc_dsa.py`<br>`tracecrypt/event/signer.py` | `tests/unit/test_pqc_dsa.py`<br>`tests/security/test_event_tampering.py` | Step 4 (`tracecrypt demo decrypt`) | `SignedDecryptionEvent.signature` (3309-byte ML-DSA-65 sig) |
| **REQ-05** | **Post-Quantum Key Encapsulation (PQC)**| NIST FIPS 203 ML-KEM-768 for quantum-resistant document key wrapping and recipient decapsulation. | `tracecrypt/crypto/pqc_kem.py`<br>`tracecrypt/document/key_wrap.py` | `tests/unit/test_pqc_kem.py`<br>`tests/vectors/test_pqc_vectors.py` | Step 2 (`tracecrypt demo encrypt`) | `.tcdist` recipient envelopes (1088-byte ML-KEM-768 ciphertexts) |
| **REQ-06** | **Immutable Distributed Ledger** | Replicated Byzantine Fault Tolerant (PBFT) ledger with SHA3-256 block header chaining and binary Merkle trees. | `tracecrypt/ledger/store.py`<br>`tracecrypt/ledger/block.py`<br>`tracecrypt/ledger/merkle.py` | `tests/unit/test_ledger_storage.py`<br>`tests/unit/test_ledger_merkle.py` | Step 4 & 5 (Ledger commit & Merkle root) | `data/ledger/ledger.db`<br>`BlockHeader.transaction_root` |
| **REQ-07** | **Tamper Evidence & Auditability** | Transaction Merkle inclusion proofs verified independently against committed block header roots. | `tracecrypt/ledger/merkle.py`<br>`tracecrypt/forensics/standalone_verifier.py` | `tests/security/test_proof_tampering.py`<br>`tests/security/test_ledger_tampering.py` | Step 8 (`tracecrypt demo tamper`) | `MerkleInclusionProof`<br>`AuditPath` |
| **REQ-08** | **Blind Forensic Extraction** | Frequency-domain blind watermark extraction without requiring the original unwatermarked document or recipient list. | `tracecrypt/forensics/extraction.py`<br>`tracecrypt/forensics/engine.py` | `tests/forensics/test_watermark_extraction.py`<br>`tests/forensics/test_ecc_recovery.py` | Step 6 (`tracecrypt demo investigate`) | Extracted 32-byte `WatermarkPayload` |
| **REQ-09** | **Deterministic Recipient Attribution** | 9-state deterministic forensic verdict engine evaluating watermark, Merkle, signature, and certificate validity. | `tracecrypt/forensics/verdict.py`<br>`tracecrypt/forensics/engine.py` | `tests/forensics/test_verdicts.py`<br>`tests/unit/test_forensics.py` | Step 6 (`tracecrypt demo investigate`) | `ForensicVerdict.VERIFIED`<br>`ForensicProofBundle (.tcproof)` |
| **REQ-10** | **Court-Admissible Evidence Reporting**| Automated forensic report generation with SHA3-256 custody chain and standalone portable verifier. | `tracecrypt/forensics/report.py`<br>`tracecrypt/forensics/standalone_verifier.py` | `tests/forensics/test_proof_bundle.py`<br>`tracecrypt/smoke_test.py` | Step 6 & 7 (`tracecrypt demo investigate`) | `FORENSIC_REPORT.json`<br>`LEAK_ATTRIBUTION_PROOF.tcproof` |
| **REQ-11** | **100% Air-Gapped / Zero-Egress** | Fully isolated runtime: zero socket egress, zero DNS calls, zero telemetry, zero external package downloads. | `scripts/verify_airgap.py`<br>`tracecrypt/crypto/zeroize.py` | `tests/security/test_airgap.py`<br>`scripts/verify_airgap.py` (0 egress) | Step 9 (`scripts/verify_airgap.py`) | Air-gap verification log (`COMPLIANT - ZERO NETWORK EGRESS`) |
| **REQ-12** | **No Cloud KMS Dependency** | Local Argon2id ($m=64\text{MB}, t=3, p=4$) encrypted keystores; zero reliance on AWS KMS, Azure Key Vault, or Google Cloud KMS. | `tracecrypt/identity/keystore.py`<br>`tracecrypt/crypto/keystore.py` | `tests/security/test_keystore.py`<br>`tests/unit/test_keystore.py` | Step 1 (`tracecrypt demo init`) | Encrypted `.tckeystore` files on local filesystem |
| **REQ-13** | **No Public Blockchain Dependency** | Lightweight permissioned 4-node PBFT consensus ($n=4, f=1$); zero gas fees, zero public tokens, zero public chain data exposure. | `tracecrypt/ledger/consensus.py`<br>`scripts/bootstrap_four_node_ledger.py`| `tests/security/test_bft_byzantine.py`<br>`tests/security/test_bft_fault_injection.py` | Step 1 (`tracecrypt demo init`) | 4 local validator processes on localhost loopbacks |
| **REQ-14** | **Replay Protection** | Cryptographic anti-replay nonces and single-use session trackers prevent event replay. | `tracecrypt/document/attribution_pipeline.py`<br>`tracecrypt/ledger/state.py` | `tests/security/test_replay.py`<br>`tests/security/test_consensus_replay.py` | Step 8 (`tracecrypt demo replay`) | Replay rejected (`ReplayAttackError`) |

---

## 2. Conclusion & Verification Summary

Every requirement specified by the Smart India Hackathon Ministry / Problem Statement **SIH26237** is fully implemented in the TraceCrypt codebase, backed by automated tests, and demonstrable locally without network connectivity.
