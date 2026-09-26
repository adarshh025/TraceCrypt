# Security: Attribution Boundary & Legal/Technical Semantics

## 1. What the Decryption Event Proves

A valid, signed, and ledger-committed `DecryptionEvent` proves mathematically:

1. **Cryptographic Identity Control:**
   The entity possessing the private key corresponding to the certified ML-DSA-65 public key authorized and executed the decryption operation.
2. **Document & Package Integrity:**
   The decryption was performed against the exact source document identified by `source_document_hash` within distribution package `distribution_id`.
3. **Session & Watermark Binding:**
   The ephemeral session (`session_id`) and forensic watermark (`watermark_id`) were generated and bound to this specific decryption attempt prior to document release.
4. **Temporal Ordering:**
   The operation occurred at or before the timestamp certified by the ledger transaction receipt.

---

## 2. What the Decryption Event DOES NOT Prove

In strict adherence to the TraceCrypt Threat Model and forensic sound principles:

### NOT Proof of Physical Human Presence
The signature proves that the private key was accessed and operated upon by the local TraceCrypt client runtime. It does **not** prove:
- The human named on the certificate was physically typing at the keyboard.
- The human was not coerced or impersonated by an adversary with local administrative access.
- Biometric presence was maintained throughout the session.

### NOT Proof of Malicious Intent
A decryption event indicates authorized consumption of a protected document. It does **not** prove:
- That the recipient intended to leak the document.
- That the recipient authored an unauthorized disclosure.
- That a subsequent leak was intentional rather than the result of shoulder-surfing, physical camera capture, or endpoint malware.

### Attribution Boundary Statement
> **TraceCrypt establishes cryptographic non-repudiation of document receipt and decryption by an enrolled cryptographic identity. Forensic attribution links a recovered leak to this event, establishing accountability without overreaching into unprovable claims of human psychology or physical presence.**
