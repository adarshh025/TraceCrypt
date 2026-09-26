# Document Content Encryption & Authenticated Data Binding

## 1. Cryptographic Primitive: AES-256-GCM

TraceCrypt employs **AES-256-GCM (Galois/Counter Mode)** (NIST SP 800-38D / FIPS 197) as the exclusive symmetric cipher for bulk document encryption.

### Parameters
* **Key Length:** 256 bits (32 bytes), generated via `os.urandom()` (OS cryptographic CSPRNG).
* **Nonce Length:** 96 bits (12 bytes), fresh random nonce per distribution.
* **Tag Length:** 128 bits (16 bytes), standard GMAC authentication tag.
* **Content Limit:** Up to 100 MB per document (well below the NIST SP 800-38D safe limit of $2^{39}-256$ bits per key/nonce pair).

---

## 2. The Single-Encryption Invariant

The source document is encrypted **exactly once per distribution**.

```
                           Source Document
                                 │
                                 ▼
                     AES-256-GCM Encrypt (CEK)
                                 │
                                 ▼
                     Encrypted Document Payload
                                 │
                 ┌───────────────┼───────────────┐
                 ▼               ▼               ▼
           Recipient A     Recipient B     Recipient C
             Envelope        Envelope        Envelope
```

### Prohibitions
* **No Multi-Ciphertext Inflation:** The document is never re-encrypted per recipient.
* **No Unauthenticated Encryption:** Modes like AES-CBC, AES-CTR without HMAC, or raw electronic codebook are prohibited.
* **No PQC Bulk Encryption:** NIST FIPS 203 ML-KEM-768 is designed strictly for asymmetric key encapsulation, not stream or block encryption.

---

## 3. Deterministic AAD (Additional Authenticated Data) Construction

To prevent metadata decoupling attacks where an adversary swaps package identifiers, headers, or recipient manifests while preserving the ciphertext, TraceCrypt cryptographically binds the metadata header directly into the AES-256-GCM GMAC authentication tag.

### Construction Formula
```
AAD = RFC_8785_JCS({
    "format_version": header.format_version,
    "distribution_id": header.distribution_id,
    "document_id": header.document_id,
    "cipher_algorithm": "AES-256-GCM",
    "kem_algorithm": "ML-KEM-768",
    "source_document_hash": header.source_document_hash,
    "recipient_set_digest": header.recipient_set_digest,
    "created_at": header.created_at
})
```

### Invalidation Guarantee
If an attacker tampers with even a single bit of:
* The `document_id`
* The `distribution_id`
* The `source_document_hash`
* The `recipient_set_digest`
* The `format_version`
* The `cipher_algorithm`

The reconstructed AAD during recipient decryption will not match, causing AES-GCM tag verification to immediately fail and raise a `CryptographicError`.

---

## 4. Post-Decryption Plaintext Integrity Verification

Even when AES-GCM successfully authenticates the ciphertext and AAD, TraceCrypt executes an obligatory second-line verification check:

```
decrypted_bytes
      │
      ▼
   SHA3-256
      │
      ▼
computed_hash <─── compare ───> source_document_hash (from header)
      │
      ├── Match ────► Store in SecureDocumentBuffer & Proceed
      │
      └── Mismatch ─► Active Zeroize Buffer & Raise CryptographicError
```

### Rationale
* Catches any subtle corruption, partial bit errors, or implementation discrepancies.
* Guarantees that what the recipient processes is bit-for-bit identical to the exact file submitted by the sender before packaging.
