# TraceCrypt Block & Transaction Format Specification

## 1. Block Structure

A finalized block in TraceCrypt is completely immutable. It consists of:
1. `BlockHeader`: Commitments to chain, height, round, previous block, timestamps, Merkle root, state root, and validator set.
2. `transactions`: Ordered list of `LedgerTransaction` objects.
3. `commit_certificate`: Cryptographic quorum evidence of validator commitment.

```json
{
  "header": {
    "chain_id": "tracecrypt-airgap-1",
    "height": 1,
    "round": 0,
    "previous_block_hash": "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": 1790452951476726,
    "proposer_id": "val-88ee0dd4ca623d11ba9795d2c5e1d92f",
    "transaction_root": "sha3-256:a1b2c3d4...",
    "state_root": "sha3-256:e5f6g7h8...",
    "validator_set_hash": "sha3-256:99887766...",
    "protocol_version": "1.0.0",
    "block_hash": "sha3-256:44556677..."
  },
  "transactions": [ ... ],
  "commit_certificate": {
    "chain_id": "tracecrypt-airgap-1",
    "height": 1,
    "round": 0,
    "block_hash": "sha3-256:44556677...",
    "votes": [ ... ],
    "validator_set_hash": "sha3-256:99887766..."
  }
}
```

---

## 2. Block Header Hashing Construction

The `block_hash` is computed strictly over the canonical RFC 8785 representation of the header **excluding** the `block_hash` field itself:

$$\text{block\_hash} = \text{"sha3-256:"} \mathbin{\Vert} \text{Hex}\Big(\text{SHA3-256}\big(\texttt{"tracecrypt:block:header:"} \mathbin{\Vert} \text{Canonicalize}(\text{header\_dict\_without\_hash})\big)\Big)$$

- **Domain Separator:** `b"tracecrypt:block:header:"`
- No local database fields or mutable runtime metadata are included.

---

## 3. Transaction Format

A `LedgerTransaction` encapsulates the Phase 5 `SignedDecryptionEvent`:

```json
{
  "transaction_id": "tx-26db6d48465664c57159543310e874d1",
  "event_id": "evt-238cf63c5c0519a31dcfc3c9a87cca96",
  "submitted_at": 1790452951524714,
  "signed_event": {
    "event": {
      "event_version": "1.0.0",
      "schema_version": "1.0.0",
      "protocol_version": "1.0.0",
      "software_version": "1.0.0",
      "event_type": "DECRYPTION_ATTRIBUTION",
      "event_id": "evt-238cf63c5c0519a31dcfc3c9a87cca96",
      "document_id": "doc-5e1c14e7047dae326e0fdf5203df2b81",
      "distribution_id": "dst-775a2e9a52715546a851ee36c83bd256",
      "document_hash": "sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "recipient_id": "rcp-751bcf3ebb58ea3fc633cdc83e55435c",
      "recipient_key_id": "key-rcp-751bcf3ebb58ea3fc633cdc83e55435c-dsa-v1",
      "recipient_certificate_id": "crt-60bfb613774c4d395464a4d913202cdd",
      "session_id": "ses-79dab1479d19864d566cb4e39a01c08b",
      "watermark_id": "wm-39589bcf5da2416dab78bdff0c791cdc",
      "watermark_version": 1,
      "anti_replay_nonce": "4dfcb0b1a2d0c1bd78e790e0efa20ca5",
      "timestamp": 1790452951476726,
      "pqc_algorithms": {
        "kem": "ML-KEM-768",
        "dsa": "ML-DSA-65",
        "hash": "SHA3-256"
      }
    },
    "event_digest": "sha3-256:...",
    "signature": "...",
    "signing_key_id": "key-rcp-751bcf3ebb58ea3fc633cdc83e55435c-dsa-v1",
    "certificate_id": "crt-60bfb613774c4d395464a4d913202cdd",
    "certificate_fingerprint": "mldsa65:sha3-256:...",
    "signed_at": 1790452951524714
  },
  "recipient_certificate": { ... }
}
```

---

## 4. Commit Certificate Structure

The `CommitCertificate` proves that $\ge 2f + 1$ authorized validators independently verified and signed `PRECOMMIT` votes for the block:

```json
{
  "chain_id": "tracecrypt-airgap-1",
  "height": 1,
  "round": 0,
  "block_hash": "sha3-256:44556677...",
  "validator_set_hash": "sha3-256:99887766...",
  "votes": [
    {
      "chain_id": "tracecrypt-airgap-1",
      "height": 1,
      "round": 0,
      "vote_type": "PRECOMMIT",
      "block_hash": "sha3-256:44556677...",
      "validator_id": "val-88ee0dd4ca623d11ba9795d2c5e1d92f",
      "timestamp": 1790452951500000,
      "signature": "..."
    },
    ...
  ]
}
```
