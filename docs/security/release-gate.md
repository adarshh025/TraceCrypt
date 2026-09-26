# Security: Centralized Document Release Gate

## 1. Release Gate Principles

The `DocumentReleaseGate` is the centralized, non-bypassable checkpoint controlling the release of watermarked documents to the recipient.

```
       Watermark Result
              +
     Signed Decryption Event
              +
      Ledger Commit Receipt
              +
    Recipient Certificate Chain
              +
       Expected Source Hash
              │
              ▼
   ┌───────────────────────────────────┐
   │       DocumentReleaseGate         │
   │                                   │
   │  1. Check Watermark Success       │
   │  2. Verify Signed Event Signature │
   │  3. Validate Certificate Chain    │
   │  4. Enforce DIGITAL_SIGNATURE     │
   │  5. Check Ledger Finality         │
   │  6. Verify Document Hash Binding  │
   │  7. Verify Watermark ID Binding   │
   │  8. Verify Session ID Binding     │
   └───────────────────────────────────┘
              │
       ┌──────┴──────┐
       │             │
  [ALL PASS]    [ANY FAIL]
       │             │
       ▼             ▼
RELEASE_ALLOWED  RELEASE_DENIED
                 (Raises LedgerCommitRequiredError
                  or ReleaseGateError)
```

---

## 2. Decision Logic and Rules

| Check | Failure Condition | Action / Exception |
|---|---|---|
| **Watermark Embedding** | Watermark embedding was unsuccessful or missing payload | `ReleaseGateError("Watermark embedding failed")` |
| **Signed Event Verification** | Signature, digest, or canonical bytes mismatch | `ReleaseGateError("Signed decryption event verification failed")` |
| **Certificate Chain** | Certificate is expired, revoked, or untrusted Root CA | `ReleaseGateError("Recipient certificate invalid")` |
| **Key Purpose** | Certificate purpose is not `KeyPurpose.DIGITAL_SIGNATURE` | `ReleaseGateError("Key purpose violation")` |
| **Ledger Commit** | Status is `PENDING`, `REJECTED`, or `UNKNOWN_COMMIT_STATE` | `LedgerCommitRequiredError("LEDGER_COMMIT_REQUIRED")` |
| **Document Binding** | Event document hash does not match source hash | `ReleaseGateError("Document hash mismatch")` |
| **Watermark Binding** | WatermarkID in watermark does not match event | `ReleaseGateError("WatermarkID mismatch")` |
| **Session Binding** | SessionID in watermark does not match event | `ReleaseGateError("SessionID mismatch")` |

---

## 3. Fail-Closed Enforcement

The production decryption API must never return raw plaintext or unwatermarked documents under any circumstance:
1. If the ledger is offline or encounters consensus timeout, the document is NOT released.
2. If watermark embedding fails, the document is NOT released.
3. If signature generation fails, the document is NOT released.
4. Memory buffers containing decrypted plaintext and CEK are zeroized before returning control to the caller.
