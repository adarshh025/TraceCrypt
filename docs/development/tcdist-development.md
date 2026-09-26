# Document Distribution Development Guide

## 1. Overview & Setup

The `tracecrypt.document` package provides all capabilities required to hash, encrypt, package, inspect, validate, and decrypt `.tcdist` distribution containers.

All operations execute in a strict offline, air-gapped posture.

---

## 2. CLI Usage Reference

### 2.1 Inspecting a Document
Inspect file dimensions, MIME type, and preliminary validation before packaging:
```bash
python -m tracecrypt document inspect <document_path>
```

### 2.2 Computing Document Integrity Hash
Computes the raw SHA3-256 integrity hash of a source document (without silent normalization):
```bash
python -m tracecrypt document hash <document_path>
```

### 2.3 Creating a Distribution Package (`.tcdist`)
Packages a source document for one or more authorized recipients:
```bash
python -m tracecrypt document package \
    --input secret_briefing.pdf \
    --output secret_briefing.tcdist \
    --recipient rcp-a1b2c3d4e5f6789012345678abcdef01 \
    --recipient rcp-00112233445566778899aabbccddeeff
```
* The command verifies that each recipient has an active certified ML-KEM-768 public key in the local SQLite store.
* Performs one AES-256-GCM content encryption.
* Generates independent ML-KEM-768 wrapped CEK envelopes for each recipient.
* Validates the final container using the 17-point validation pipeline before writing to `--output`.

### 2.4 Validating a Package Offline
Executes the full 17-point offline validation suite against a `.tcdist` container:
```bash
python -m tracecrypt document validate secret_briefing.tcdist
```
Output displays:
* Validation verdict (`VALID` or `INVALID`)
* Document ID (`doc-...`)
* Distribution ID (`dst-...`)
* Recipient count
* Source document SHA3-256 hash
* Detailed check results

### 2.5 Inspecting Authorized Recipients
Lists the authorized recipient IDs and key metadata embedded within a package without decrypting:
```bash
python -m tracecrypt document recipients secret_briefing.tcdist
```

### 2.6 Decrypting a Package (Developer Mode Only)
> [!CAUTION]
> The `decrypt` CLI command exposes raw decrypted plaintext and MUST NOT be used in production workflows. Production document release is strictly managed by the forensic watermark pipeline (Phase 4/5). This command requires explicit `--dev-mode`.

```bash
python -m tracecrypt document decrypt secret_briefing.tcdist \
    --recipient rcp-a1b2c3d4e5f6789012345678abcdef01 \
    --password "RecipientSecretPassphrase!" \
    --dev-mode \
    --output restored_briefing.pdf
```

---

## 3. Local FastAPI Endpoints

The TraceCrypt local service provides document distribution endpoints at `http://127.0.0.1:8000`:

### `POST /documents/package`
* Packages a document for designated recipient IDs.
* Accepts JSON body:
  ```json
  {
    "document_path": "C:/TraceCrypt/secret_memo.pdf",
    "recipient_ids": ["rcp-a1b2c3d4e5f6789012345678abcdef01"],
    "sender_id": "usr-f0e1d2c3b4a596877869504132231405"
  }
  ```
* Returns `document_id`, `distribution_id`, `source_hash`, `recipient_count`, and `package_b64`.

### `GET /documents/{document_id}`
* Retrieves document metadata from the local database.

### `POST /documents/validate`
* Validates a `.tcdist` container sent via base64.
* Returns 17-point validation verdict, document ID, distribution ID, and error details if invalid.

### `POST /documents/decrypt/validate`
* Performs cryptographic validation and recipient authorization check without persisting plaintext to disk.
* Returns recovery verification and plaintext match status.

---

## 4. Running Benchmarks Locally

To benchmark distribution operations (SHA3-256 hashing, AES-256-GCM encryption, ML-KEM-768 key encapsulation, package serialization, and 17-point validation):

```bash
python -m pytest tests/benchmarks/test_distribution_benchmarks.py -s
```

All metrics are measured directly using `time.perf_counter_ns()`.
