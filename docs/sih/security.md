# TraceCrypt — Security Architecture & Threat Model

**Hackathon:** Smart India Hackathon 2026 (SIH 2026)  
**Team:** Team Laccha Paratha (Team ID: 138638)  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution (`SIH26237`)  

---

## 1. Adversarial Model

TraceCrypt is designed to withstand motivated, sophisticated adversaries operating within sensitive government and defense enclaves:

1. **Malicious Insider (Authorized Recipient):** Possesses legitimate credentials, decrypts the document, and leaks the resulting file to unauthorized third parties or media outlets.
2. **Colluding Insider:** Attempts to modify or frame another innocent colleague by altering metadata, injecting another recipient's ID, or tampering with signatures.
3. **Rogue Node Administrator:** Has local administrative access to one of the BFT validator machines and attempts to delete audit logs, rollback block heights, or forge consensus votes.
4. **Network Man-in-the-Middle:** Intercepts distribution packages in transit and attempts to alter recipient lists or extract plaintext without authorized private keys.

---

## 2. Threat Vectors & Defenses

### 2.1. Vector 1: Identity Framing & False Attribution
* **Attack:** Adversary alters the `recipient_id` field in the signed decryption event from Alice to Bob, attempting to make forensic investigators attribute the leak to Bob while retaining Alice's cryptographic signature.
* **TraceCrypt Defense:** In `ForensicCryptographicVerifier.verify_recipient_identity_and_signature`, the cryptographic signature is verified against the public key declared in Bob's certificate. Because ML-DSA-65 signatures are existentially unforgeable (EUF-CMA), the verification algorithm recalculates the message digest and immediately fails.
* **Test Verification:** Verified by `tests/adversarial/` and `tracecrypt demo tamper`.

### 2.2. Vector 2: Document Binding Mismatch
* **Attack:** An adversary extracts a legitimate watermark from an unclassified document and attempts to associate it with a leaked top-secret document.
* **TraceCrypt Defense:** Watermark payloads embed a 40-bit cryptographic binding hash:
  $$\text{Binding} = \text{SHA3-256}(\text{"TraceCrypt"} \parallel \text{doc\_hash} \parallel \text{session\_id} \parallel \text{watermark\_id})[:5]$$
  During investigation, `verify_document_binding` computes the actual hash of the recovered document and compares it to the committed event hash. Any mismatch triggers an immediate `DOCUMENT_MISMATCH` verdict rejection.
* **Test Verification:** Verified by `tests/forensics/test_document_binding.py` and `tracecrypt demo tamper`.

### 2.3. Vector 3: Digital Signature Bit-Flip Tampering
* **Attack:** Adversary corrupts or flips a single byte in the ML-DSA-65 signature block.
* **TraceCrypt Defense:** Module-Lattice digital signatures (NIST FIPS 204) strictly enforce polynomial vector relations. Any modified bit disrupts the lattice equation, returning `CRYPTOGRAPHIC_SIGNATURE_INVALID`.
* **Test Verification:** Verified by `tracecrypt demo tamper`.

### 2.4. Vector 4: Replay Attacks
* **Attack:** Adversary captures Alice's valid historical transaction and resubmits it to the ledger to trigger duplicate releases or confuse sequence heights.
* **TraceCrypt Defense:** Every transaction includes a 128-bit cryptographic `anti_replay_nonce` and `event_id`. The primary validator maintains an in-memory and database-backed unicity tracker. Duplicate nonces trigger an immediate `ReplayAttackError`.
* **Test Verification:** Verified by `tracecrypt demo replay`.

### 2.5. Vector 5: Database Rollback Attack
* **Attack:** A rogue administrator on a validator node deletes the SQLite database or replaces it with an older backup to erase evidence of a decryption event.
* **TraceCrypt Defense:** `LedgerStorage` writes an atomic `.checkpoint` file tracking the monotonically increasing maximum block height. If the database is opened with a height lower than the monotonic checkpoint, `_check_rollback` throws a `SecurityError` and halts node operations.
* **Test Verification:** Verified by `tests/security/test_ledger_tampering.py`.

### 2.6. Vector 6: Byzantine Node Failure ($f=1$)
* **Attack:** A compromised or crashing validator node sends invalid votes, drops packets, or powers off during consensus rounds.
* **TraceCrypt Defense:** PBFT protocol over $N=4$ nodes requires $2f+1=3$ votes. With 1 node completely offline, the remaining 3 nodes achieve consensus and commit blocks normally. When the failed node recovers, the `SyncManager` downloads missing blocks from peers and validates commit certificates back to Genesis.
* **Test Verification:** Verified by `tracecrypt demo bft`.

---

## 3. Cryptographic Standards Adherence

TraceCrypt strictly utilizes official, production-grade cryptographic implementations:
* **Key Encapsulation:** NIST FIPS 203 ML-KEM-768
* **Digital Signatures:** NIST FIPS 204 ML-DSA-65
* **Symmetric Encryption:** NIST SP 800-38D AES-256-GCM
* **Cryptographic Hashing:** NIST FIPS 202 SHA3-256 / SHAKE-256
* **Key Derivation (Keystore):** RFC 9106 Argon2id ($m=64\text{ MB}, t=3, p=4$)
