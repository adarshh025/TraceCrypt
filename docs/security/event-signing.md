# Security: Post-Quantum Event Signing & Verification

## 1. Post-Quantum Signing Architecture

TraceCrypt utilizes the NIST FIPS 204 ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) standard to provide post-quantum tamper resistance and cryptographic non-repudiation for all decryption events.

```
       DecryptionEvent (Typed Model)
                     │
                     ▼
          1. Canonicalize (RFC 8785)
                     │
                     ▼
             Canonical Bytes
                     │
                     ▼
             2. Hash (SHA3-256)
                     │
                     ▼
           32-byte Event Digest
                     │
                     ▼
        3. Sign with Recipient ML-DSA-65
                     │
                     ▼
        NIST FIPS 204 Digital Signature
                     │
                     ▼
            SignedDecryptionEvent
```

---

## 2. Pre-Signing Validation Rules

Prior to applying the signature, `DecryptionEventSigner.sign_event()` enforces:
1. **Certificate Authenticity:** The recipient certificate must be validly signed by the Root CA.
2. **Key Purpose Separation:** The certificate must specify `KeyUsage.DIGITAL_SIGNATURE` and `KeyPurpose.EVENT_SIGNING`. Any attempt to sign with an ML-KEM encapsulation key is rejected immediately.
3. **Subject Matching:** The `recipient_id` in the `DecryptionEvent` must match `certificate.subject_id`.
4. **Revocation Check:** The certificate must not be listed in the active `OfflineRevocationStore`.
5. **Validity Period:** Current time must fall strictly between `valid_from` and `valid_until`.

---

## 3. Independent Verification Pipeline

The `DecryptionEventVerifier.verify_signed_event()` executes an 8-point validation pipeline:
1. **Canonical Byte Reconstruction:** Computes canonical bytes of the embedded `event` and verifies that `signed_event.canonical_event` matches exactly.
2. **Digest Verification:** Calculates `SHA3-256(canonical_bytes)` and verifies that `signed_event.event_digest` matches.
3. **ML-DSA-65 Cryptographic Verification:** Verifies the 3,309-byte signature over the 32-byte raw digest using the recipient's ML-DSA-65 public key.
4. **Certificate Validation:** Validates the recipient certificate chain to the Root CA.
5. **Key Purpose Check:** Verifies certificate usage flags.
6. **Revocation Check:** Verifies that the certificate serial number is not revoked.
7. **Document Binding:** Verifies that `event.document_hash` matches expected source hash.
8. **Watermark & Session Binding:** Verifies that `event.watermark_id` and `event.session_id` match the embedded watermark payload.

Verification returns a strictly-typed `DecryptionEventVerificationResult` containing explicit boolean status flags and diagnostic error descriptions.
