# TraceCrypt Security Boundaries & Attribution Guarantees

**Standard Baseline:** Common Criteria EAL4+ (Security Target), NIST SP 800-57 Part 1  
**Classification:** TECHNICAL SECURITY ARCHITECTURE SPECIFICATION  

---

## 1. What TraceCrypt Cryptographically Establishes

Under the assumption of an uncompromised Root CA and legitimate BFT consensus quorum ($\ge 2f + 1$ honest validators):

1. **Certified Identity Key Binding**:
   - The Root CA issued an identity certificate binding a specific `SubjectID` to an ML-DSA-65 public key.
   - The certificate was unexpired and unrevoked at the timestamp recorded on the immutable ledger.
2. **Canonical Event Authorization**:
   - The private key corresponding to the certified recipient's ML-DSA-65 public key generated a valid cryptographic digital signature over the RFC 8785 canonical representation of the `DecryptionEvent`.
   - Any modification of even a single bit in the event fields (document hash, watermark ID, session ID, timestamp, anti-replay nonce) invalidates the signature.
3. **Immutable Ledger Commitment**:
   - The signed decryption event was accepted by the mempool, included in a valid block, committed to a Merkle tree root, and verified by a quorum of authorized BFT validators.
   - The block is chained via SHA3-256 parent hash continuity to the genesis block.
4. **Watermark Extraction & Document Binding**:
   - The blind frequency-domain extractor recovered a valid DWT-DCT watermark payload with verified Reed-Solomon RS(32,16) parity and 16-bit CRC checksum.
   - The recovered `WatermarkID` exactly matches the watermark committed in the signed ledger transaction.
   - The 40-bit document binding tag embedded in the watermark matches the SHA3-256 hash of the suspected leaked document, establishing that the watermark was not transplanted from an unrelated document.

---

## 2. What TraceCrypt CANNOT Independently Establish

TraceCrypt is a digital, cryptographic attribution system. It does not replace physical security controls or biological identity verification:

1. **Biological Operator Identity**:
   - TraceCrypt proves possession and use of the certified ML-DSA-65 private key.
   - It cannot prove which physical human was operating the keyboard or whether an authorized user shared their passphrase with an unauthorized colleague.
2. **Absence of Endpoint Compromise**:
   - If an adversary acquires administrator or kernel root access on a recipient's physical workstation *while an authorized user has decrypted the keystore in RAM*, the plaintext document or ephemeral key material could theoretically be read from memory.
3. **Screen Photography & Physical Camcording**:
   - While TraceCrypt watermarks are robust against downsampling, compression, and mild rotation, an attacker using an analog camera at an extreme angle ($> 45^\circ$) or destroying more than 75% of the page area can degrade the optical carrier below detection thresholds. In such cases, TraceCrypt fails closed to `UNVERIFIABLE` rather than providing a false attribution.
4. **Physical Hardcopy Copying / Shredding**:
   - TraceCrypt cannot detect physical destruction or trace hardcopies that have been shredded or burned.
5. **Insider Collusion Beyond Byzantine Fault Bound**:
   - The 4-validator ledger tolerates up to $f = 1$ compromised Byzantine node. If 2 or more validators collude ($f \ge 2$), consensus safety and fork prevention can no longer be mathematically guaranteed.

---

## 3. Strict Verdict Non-Overstatement Policy

Forensic attribution output is restricted strictly to the 9 canonical states:
- `VERIFIED`: Complete, uncompromised cryptographic chain from Root CA to watermark payload.
- `NOT_FOUND`: Evidence does not contain any TraceCrypt watermark signals.
- `INVALID_WATERMARK`: Watermark pattern detected but fails CRC checksum or framing.
- `SIGNATURE_INVALID`: Recovered event signature does not verify under recipient certificate.
- `LEDGER_INVALID`: Event is missing from ledger or fails Merkle root / commit certificate verification.
- `DOCUMENT_MISMATCH`: Watermark document binding does not match the suspect document hash.
- `CORRUPTED_WATERMARK`: Reed-Solomon uncorrectable errors; signal destroyed.
- `AMBIGUOUS`: Conflicting valid watermarks detected across pages (splice attack).
- `UNVERIFIABLE`: Severe degradation preventing mathematical certainty.
