# Architecture: Decryption Event Schema and RFC 8785 Canonicalization

## 1. Schema Definition

The `DecryptionEvent` model is a strictly-typed Pydantic structure capturing the complete context of an authorized decryption operation.

```json
{
  "event_version": "1.0.0",
  "schema_version": "1.0.0",
  "protocol_version": "1.0.0",
  "software_version": "1.0.0",
  "event_type": "DECRYPTION_ATTRIBUTION",
  "event_id": "evt-77b31b316f393854eb44747ebc7b4198",
  "document_id": "doc-a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "distribution_id": "dst-9876543210abcdef0123456789abcdef",
  "document_hash": "sha3-256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "recipient_id": "rcp-fedcba9876543210fedcba9876543210",
  "recipient_key_id": "key-rcp-fedcba9876543210fedcba9876543210-dsa-v1",
  "recipient_certificate_id": "crt-11223344556677889900aabbccddeeff",
  "device_id": null,
  "session_id": "ses-3344556677889900aabbccddeeff0011",
  "watermark_id": "wm-99887766554433221100ffeeddccbbaa",
  "watermark_version": 1,
  "anti_replay_nonce": "e3b0c44298fc1c149afbf4c8996fb924",
  "timestamp": 1790450000000000,
  "rendered_watermarked_artifact_hash": "sha3-256:8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
  "pqc_algorithms": {
    "kem": "ML-KEM-768",
    "dsa": "ML-DSA-65",
    "hash": "SHA3-256"
  }
}
```

---

## 2. Distinction: Source Hash vs Rendered Artifact Hash

TraceCrypt maintains a strict conceptual and cryptographic boundary between:
1. `source_document_hash`:
   $$\text{SHA3-256}(\text{original unwatermarked source PDF bytes})$$
   This represents the ground truth document encrypted by the sender in the `.tcdist` package. It links the recipient event back to the original file distribution.
2. `rendered_watermarked_artifact_hash`:
   $$\text{SHA3-256}(\text{final rendered watermarked PDF bytes})$$
   This represents the physical or digital evidence released to the recipient. It allows forensic verification that a released artifact corresponds to the specific session without revealing the unwatermarked source document.

---

## 3. RFC 8785 Canonicalization Procedure

To guarantee deterministic hashing and signature verification across all platforms, implementations, and architectures:

1. **Serialization Ordering:** Dictionary keys are sorted lexicographically by UTF-16 code units (or UTF-8 byte ordering).
2. **Whitespace:** Whitespace is strictly eliminated (no indentation, no space after `:` or `,`).
3. **Number Formatting:** Numbers follow IEEE 754 double precision without trailing zeros or unnecessary exponential notation.
4. **String Escaping:** Control characters (< 0x20) and quotes are escaped using standard JSON rules (`\u00xx` or `\"`, `\\`). Unicode characters are output directly in UTF-8 without unnecessary `\u` escape sequences.

```
       DecryptionEvent (Typed Python Object)
                       │
                       ▼
             to_canonical_dict()
                       │
                       ▼
        RFC 8785 Canonicalizer Engine
                       │
                       ▼
          Deterministic Canonical UTF-8 Bytes
                       │
                       ▼
              SHA3-256 Hash Function
                       │
                       ▼
         Canonical Event Digest ("sha3-256:<hex>")
```

---

## 4. Elimination of Circular Self-Hashing

A common pitfall in signed audit logs is attempting to include a signature or digest inside the exact structure being signed, creating an impossible chicken-and-egg circular dependency.

TraceCrypt solves this cleanly:
- `DecryptionEvent`: Represents the unsigned canonical payload. It contains no signature and no self-digest.
- `SignedDecryptionEvent`: Represents the immutable outer container holding:
  - `event`: The structured `DecryptionEvent`
  - `canonical_event`: The exact RFC 8785 canonical JSON string
  - `event_digest`: The SHA3-256 hex digest of `canonical_event`
  - `signature`: The Base64-encoded NIST FIPS 204 ML-DSA-65 signature computed over the raw 32-byte digest
  - `signing_key_id`, `certificate_id`, `certificate_fingerprint`, `signed_at`
  - `ledger_transaction_id`: Attached post-commit

This decouples the payload from its cryptographic envelope while guaranteeing 100% verifiability.
