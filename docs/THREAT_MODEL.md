# TraceCrypt Comprehensive Threat Model & Adversarial Actor Matrix

**Document Version:** 1.0.0  
**Classification:** Operational Security Standard  
**Standard:** STRIDE, NIST SP 800-154, ISO/IEC 27005  

---

## 1. Security Objectives

TraceCrypt provides **cryptographic non-repudiation**, **tamper-evident document attribution**, and **offline resilience** under the following security guarantees:

1. **Blind Recovery**: Zero requirement for pristine original documents or candidate recipient lists during extraction.
2. **False Attribution Resistance**: A non-watermarked document or unrelated leak must never attribute to an innocent party.
3. **Tamper Resilience**: Direct ledger tampering, Merkle path alteration, forged certificates, or modified block headers must be deterministically rejected.
4. **Air-Gap Operational Security**: Zero network exposure (no external cloud calls, external PKI, telemetry, or remote dependencies).
5. **Fail-Closed Execution**: Any ambiguity, corruption, or verification failure results in an explicit non-attribution verdict.

---

## 2. Threat Actor Capabilities & Defense Matrix

TraceCrypt explicitly evaluates seven distinct adversarial archetypes:

### Actor A: Malicious Recipient
- **Capabilities:** Possesses valid recipient credentials, can manipulate local files, replay requests, modify decrypted output, attempt watermark removal or cloning.
- **Defenses:**
  - Watermark embedded in frequency domain (2-level DWT-DCT) with Reed-Solomon RS(32, 16) error correction.
  - 40-bit cryptographic document binding prevents transplanting watermark to other documents (`DOCUMENT_MISMATCH`).
  - Canonical `DecryptionEvent` signed with ML-DSA-65 before document release gate opens.
  - Single-session anti-replay nonce tracking blocks session reuse.

### Actor B: Compromised Recipient Workstation
- **Capabilities:** Can inspect application files, alter local config/database, kill processes, manipulate temporary files, modify clocks, replace certificates.
- **Defenses:**
  - Private keys encrypted with Argon2id ($m=64\text{MB}, t=3, p=4$) and AES-256-GCM.
  - Ephemeral in-memory zeroization of plaintext documents; no unencrypted temporary files on disk.
  - Release gate atomicity: document cannot be released without confirmed ledger commit.
  - Timestamp tampering defeated by cryptographic nonces and immutable block sequence order.

### Actor C: Malicious Sender
- **Capabilities:** Can forge `.tcdist` packages, corrupt encapsulation, inject invalid document hashes or filenames.
- **Defenses:**
  - 17-point offline validation on all `.tcdist` packages before decapsulation.
  - SHA3-256 container checksum and AES-256-GCM authentication tag verified prior to plaintext release.
  - Recipient certificate purpose strictly checked (`KeyPurpose.KEY_ENCAPSULATION`).

### Actor D: Malicious Investigator
- **Capabilities:** Can substitute evidence, manipulate proof bundles, forge reports, tamper with local database.
- **Defenses:**
  - Standalone independent verifier (`tracecrypt.forensics.standalone_verifier`) executes with zero database trust.
  - Every proof bundle contains self-verifying Merkle inclusion paths, block headers, and ML-DSA signatures.
  - 9-state deterministic verdict engine enforces strict precedence without subjective overrides.

### Actor E: Malicious Validator
- **Capabilities:** Can propose conflicting blocks (equivocation), submit conflicting votes, replay old consensus rounds, forged validator identity.
- **Defenses:**
  - Byzantine Fault Tolerant (PBFT) consensus engine with $n=4, f=1$ threshold.
  - Automated cryptographic `ByzantineEvidence` generation on double-voting.
  - Commit certificates require $\ge 2f + 1$ (3 out of 4) valid validator signatures.

### Actor F: Compromised Database
- **Capabilities:** Direct SQL mutation of SQLite rows, transaction deletion, block tampering, database rollback.
- **Defenses:**
  - Cryptographic block header hash chaining (SHA3-256 parent hash).
  - Transactions anchored in Merkle tree roots committed in block headers.
  - SQLite WAL mode and integrity verification on node startup.

### Actor G: Malicious Network Participant
- **Capabilities:** LAN packet replay, message flooding, invalid peer identity, malformed wire frames.
- **Defenses:**
  - Air-gapped LAN model: all messages bound to unique `chain_id`.
  - ML-DSA-65 signatures on all consensus messages.
  - Message deduplication and idempotent processing preventing resource exhaustion.

---

## 3. Trust Boundaries & Data Flow

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

---

## 4. Fundamental Attribution Boundary Notice

> TraceCrypt cryptographically establishes that a certified NIST FIPS 204 ML-DSA-65 private key belonging to a registered recipient certificate produced the signed attribution event committed to the immutable ledger.  
> TraceCrypt **does not independently prove the biological identity of the human operator** manipulating the physical workstation at that instant. Physical attribution requires endpoint security, facility access logs, and biometric controls.
