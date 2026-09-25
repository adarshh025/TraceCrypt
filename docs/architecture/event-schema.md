# Canonical DecryptionEvent Schema Specification

## 1. Purpose
The `DecryptionEvent` is the primary cryptographic audit record constructed at the moment a recipient successfully decrypts a document. It permanently and unforgeably links:
1. The exact source document (via its pre-watermark `SHA3-256` digest).
2. The authorized recipient (via certified `RecipientID`).
3. The enrolled physical workstation (via `DeviceID` hardware fingerprint).
4. The unique decryption session (`SessionID` and anti-replay nonce).
5. The embedded forensic watermark (`WatermarkID`).
6. The precise POSIX microsecond timestamp.

## 2. Schema Definition (Version 1.0.0)
```json
{
  "schema_version": "1.0.0",
  "protocol_version": "1.0.0",
  "event_id": "evt-0123456789abcdef0123456789abcdef",
  "document_id": "doc-0123456789abcdef0123456789abcdef",
  "document_hash": "sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "recipient_id": "rcp-0123456789abcdef0123456789abcdef",
  "device_id": "dev-0123456789abcdef0123456789abcdef",
  "session_id": "ses-0123456789abcdef0123456789abcdef",
  "watermark_id": "wm-0123456789abcdef0123456789abcdef",
  "anti_replay_nonce": "f8a7c2b3d4e5f6011223344556677889",
  "timestamp": 1790000000000000,
  "pqc_algorithms": {
    "kem": "ML-KEM-768",
    "dsa": "ML-DSA-65",
    "hash": "SHA3-256"
  }
}
```

## 3. Immutability & Signature Rules
* **No Arbitrary Fields:** Unknown or arbitrary fields are strictly forbidden (`extra="forbid"` in Pydantic).
* **Canonical Signing Input:** To sign an event, the recipient client serializes the event dictionary (excluding `signature` and `public_key_ref`) using **RFC 8785 (JCS)** and computes the `SHA3-256` digest.
* **Signature Generation:** The digest is signed using the recipient's **ML-DSA-65** private key.
* **Ledger Commit:** The canonical JSON string and the signature are committed as a single immutable transaction to the distributed ledger.
