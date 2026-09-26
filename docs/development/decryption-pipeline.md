# Developer Guide: Recipient Decryption & Attribution Pipeline

## 1. Overview

Phase 5 introduces the atomic recipient-side decryption pipeline, connecting document distribution (`.tcdist`), invisible DWT-DCT watermarking, signed canonical events, and the distributed ledger interface.

---

## 2. Programmatic Usage

```python
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter

# 1. Initialize credentials with recipient's KEM and DSA certificates
credentials = RecipientCredentials(
    recipient_id=recipient_id,
    kem_private_key=kem_sk,
    kem_certificate=kem_cert,
    dsa_private_key=dsa_sk,
    dsa_certificate=dsa_cert,
)

# 2. Execute atomic decryption pipeline
release = RecipientAttributionPipeline.execute_decryption(
    package_input=package_bytes,
    credentials=credentials,
    ledger=ledger_adapter,
    root_ca_public_key=root_ca_public_key,
)

# 3. Access the released watermarked PDF and committed receipt
watermarked_pdf = release.watermarked_pdf
receipt = release.ledger_receipt
signed_event = release.signed_event
```

---

## 3. CLI Subcommands

### Validate a `.tcdist` package offline
```bash
tracecrypt decrypt validate /path/to/document.tcdist --root-ca /path/to/root_ca.crt
```

### Simulate recipient decryption and attribution release
```bash
tracecrypt decrypt simulate /path/to/document.tcdist \
  --recipient rcp-alice-001 \
  --keystore /path/to/alice.keystore \
  --passphrase "CorrectHorseBatteryStaple" \
  --root-ca /path/to/root_ca.crt \
  --output /path/to/watermarked_output.pdf
```

### Inspect a canonical signed event
```bash
tracecrypt event inspect /path/to/signed_event.json
```

### Verify an event signature independently
```bash
tracecrypt event verify /path/to/signed_event.json --root-ca /path/to/root_ca.crt
```

### Output RFC 8785 canonical bytes for an event
```bash
tracecrypt event canonicalize /path/to/signed_event.json
```

---

## 4. Local REST API Endpoints

- `POST /decrypt/prepare`: Validates package and inspects recipient envelope metadata without releasing plaintext.
- `POST /decrypt/execute`: Executes atomic decryption pipeline and returns watermarked document upon ledger commitment.
- `GET /events/{event_id}`: Retrieves stored signed decryption event by ID.
- `POST /events/verify`: Performs independent 8-point verification on a signed decryption event.

---

## 5. Development Ledger Adapter

For testing and local development, the pipeline uses `InMemoryLedgerAdapter`:
```python
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter

ledger = InMemoryLedgerAdapter()
```
**Important:** `InMemoryLedgerAdapter` is marked `DEVELOPMENT / TEST ONLY`. It does not execute BFT consensus or peer-to-peer state replication. The future Phase 6 will implement the production BFT distributed ledger.
