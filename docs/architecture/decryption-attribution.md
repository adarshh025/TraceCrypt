# Architecture: Recipient-Side Attribution Pipeline

## 1. Overview and Core Invariant

The recipient-side attribution pipeline is the cryptographic and forensic bridge between protected `.tcdist` distribution packages and the local viewer/renderer in TraceCrypt.

### The Absolute Invariant
> **Unwatermarked plaintext MUST NEVER be released during the production workflow.**

Every decryption attempt that reaches the attribution stage results in an ephemeral session, a fresh cryptographically secure forensic watermark embedded directly into the document bytes in memory, a canonical RFC 8785 attribution event signed with the recipient's NIST FIPS 204 ML-DSA-65 private key, and a committed transaction on the distributed ledger. Only upon confirmed ledger finality does the release gate open to provide the watermarked document.

```
                    .tcdist Package
                          │
                          ▼
                  1. Validate Package
                          │
                          ▼
            2. Authenticate Recipient & Key
                          │
                          ▼
               3. ML-KEM Decapsulation
                          │
                          ▼
               4. Recover AES-256-GCM CEK
                          │
                          ▼
           5. Decrypt Plaintext (Controlled RAM)
                          │
                          ▼
             6. Verify Source SHA3-256
                          │
                          ▼
             7. Generate 128-bit SessionID
                          │
                          ▼
            8. Generate 128-bit WatermarkID
                          │
                          ▼
           9. Construct 256-bit WatermarkPayload
                          │
                          ▼
           10. Embed Forensic DWT-DCT Watermark
                          │
                          ▼
           11. Construct DecryptionEvent
                          │
                          ▼
           12. RFC 8785 Canonical JSON Serialization
                          │
                          ▼
            13. SHA3-256 Canonical Event Digest
                          │
                          ▼
          14. Sign with Recipient ML-DSA-65 Key
                          │
                          ▼
          15. Submit Signed Transaction to Ledger
                          │
                          ▼
             16. Confirm Commit / Finality
                          │
              ┌───────────┴───────────┐
         [COMMITTED]             [FAIL / TIMEOUT]
              │                          │
              ▼                          ▼
   17. Centralized Release Gate    RELEASE_DENIED
              │                 (LEDGER_COMMIT_REQUIRED)
              ▼
   18. Release Watermarked PDF
              │
              ▼
    19. Zeroize Plaintext & CEK
```

---

## 2. Dynamic Ephemeral Watermarks

Watermarks are never static:
- **No package-time generation:** Watermarks are not generated when the document is packaged by the sender.
- **No enrollment-time generation:** Watermarks are not generated during identity onboarding.
- **No recipient reuse:** If Recipient Alice decrypts the same document twice:
  $$\text{Session } A \neq \text{Session } B$$
  $$\text{Watermark } A \neq \text{Watermark } B$$
  $$\text{Event } A \neq \text{Event } B$$

Each decryption constitutes an independent attribution record with collision-resistant 128-bit identifiers generated via OS CSPRNG (`tracecrypt.crypto.random.SecureRandom`).

---

## 3. Cryptographic Identity Binding

The pipeline enforces strict post-quantum cryptographic separation:
1. **ML-KEM-768 (`KEY_ENCAPSULATION` / `DOCUMENT_DECRYPTION`):** Used strictly for decapsulating the ciphertext into the 256-bit AES Content Encryption Key (CEK).
2. **ML-DSA-65 (`DIGITAL_SIGNATURE` / `EVENT_SIGNING`):** Used strictly by the recipient to sign the RFC 8785 canonical bytes of the `DecryptionEvent`.

Root CA certificates or administrative keys are strictly forbidden from signing recipient decryption events; only the authorized recipient identity anchor can create valid attribution signatures.

---

## 4. In-Memory Security & Zeroization

To eliminate data remanence attacks:
- Decrypted plaintext exists purely in an in-memory mutable `bytearray` buffer.
- Recovered CEK exists purely in a mutable `bytearray` buffer.
- Embedding occurs in memory without writing temporary unwatermarked files to disk.
- In the `finally:` block of `RecipientAttributionPipeline.execute_decryption()`, both the plaintext buffer and recovered CEK are overwritten with zeros:
  ```python
  finally:
      for i in range(len(recovered_cek)):
          recovered_cek[i] = 0
      if raw_plaintext_buffer is not None:
          for i in range(len(raw_plaintext_buffer)):
              raw_plaintext_buffer[i] = 0
  ```

---

## 5. Ledger Interface & Fail-Closed Gate

The pipeline delegates transaction persistence to `DecryptionEventLedger`:
- `submit_event(signed_event: SignedDecryptionEvent) -> LedgerTransactionReceipt`
- `check_duplicate(event_id: EventID) -> bool`
- `check_session(session_id: SessionID) -> bool`
- `check_watermark(watermark_id: WatermarkID) -> bool`

If the ledger reports `REJECTED`, `PENDING`, or `UNKNOWN_COMMIT_STATE`, the `DocumentReleaseGate` asserts:
```python
raise LedgerCommitRequiredError("Document release blocked: LEDGER_COMMIT_REQUIRED")
```
The unwatermarked document is discarded, and the caller receives an explicit failure token.
