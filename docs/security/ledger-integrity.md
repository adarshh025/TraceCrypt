# TraceCrypt Ledger Integrity & Cryptographic Security Architecture

## 1. Overview & Threat Model

The TraceCrypt BFT distributed ledger subsystem provides deterministic replicated state machine security for forensic event logging. It is designed to withstand:
- Host-level file tampering and manual SQLite database edits.
- Adversarial message replay across chains, heights, rounds, and transactions.
- Byzantine malicious validators attempting equivocation (conflicting votes/proposals).
- Network partitions (2+2 split).
- Unauthorized voting attempts by external or non-validator entities.

---

## 2. Core Cryptographic Invariants

| # | Security Invariant | Enforcement Mechanism |
|---|---|---|
| **1** | **Single Block Finality** | One height cannot have two finalized block hashes. Guaranteed by $2f+1$ quorum threshold. |
| **2** | **Hash Linkage Continuity** | Every finalized block's `previous_block_hash` strictly equals the `block_hash` of height $H-1$. |
| **3** | **Anti-Replay for Transactions** | A transaction cannot be finalized twice. Authoritative tracking on `EventID`, `SessionID`, `WatermarkID`, and `TransactionID`. |
| **4** | **WatermarkID Uniqueness** | A `WatermarkID` maps strictly to one committed event. Replay attempts trigger `ReplayAttackError`. |
| **5** | **SessionID Uniqueness** | A `SessionID` maps strictly to one committed event. |
| **6** | **Valid Commit Certificate** | Every block must have $\ge 2f + 1$ verified ML-DSA-65 signatures from active validators. |
| **7** | **Validator Set Membership** | Every vote must belong to the active validator set established at genesis. |
| **8** | **Deterministic State Root** | Every block's `state_root` must equal independent recomputation from canonical logical state. |
| **9** | **Deterministic Merkle Root** | Every block's `transaction_root` must equal independent binary Merkle recomputation. |
| **10** | **Key Purpose Separation** | Recipient keys (`DIGITAL_SIGNATURE`) cannot sign validator votes (`CONSENSUS_VALIDATION`). |

---

## 3. Storage Tamper Detection & Startup Integrity Verification

SQLite WAL is used solely for local node persistence; it is **not** consensus and **not** the chain.

Every validator node executes `self.storage.verify_chain()` automatically at process startup:
1. Validates `genesis_hash` against configuration.
2. Iterates from height 1 to tip:
   - Recalculates block hash over canonical header bytes and compares against `block_hash`.
   - Cross-checks raw SQL columns against `header_json` commitments (detecting direct SQLite column editing).
   - Recomputes binary Merkle tree over all transactions at height $H$ and asserts match with `transaction_root`.
   - Verifies the `CommitCertificate`, recalculating quorum ($\ge 2f + 1$) and validating every validator's ML-DSA-65 digital signature against their public verification key.
   - Asserts height continuity ($H = H_{\text{prev}} + 1$) and previous block hash linkage ($B_{\text{prev}} == B_H.\text{previous\_block\_hash}$).

If any manual alteration, deletion, or substitution has occurred on disk, startup halts immediately with `ChainVerificationError`.

---

## 4. Cryptographic Domain Separation Table

All hashing operations in TraceCrypt utilize explicit byte prefixes to prevent cross-protocol and cross-structure collision attacks:

| Structure | Domain Separator Prefix | Hash Algorithm |
|---|---|---|
| **Genesis Hash** | `b"tracecrypt:genesis:"` | SHA3-256 |
| **Validator Set Hash** | `b"tracecrypt:valset:"` | SHA3-256 |
| **Block Header Hash** | `b"tracecrypt:block:header:"` | SHA3-256 |
| **Transaction Leaf Hash** | `b"tracecrypt:merkle:leaf:"` | SHA3-256 |
| **Merkle Inner Node Hash** | `b"tracecrypt:merkle:node:"` | SHA3-256 |
| **Consensus Vote Signature** | `b"tracecrypt:vote:v1:"` | ML-DSA-65 (NIST FIPS 204) |
| **State Entry Leaf Hash** | `b"tracecrypt:state:entry:"` | SHA3-256 |
| **Byzantine Evidence Hash** | `b"tracecrypt:evidence:v1:"` | SHA3-256 |
| **P2P Wire Frame Integrity** | None (Raw SHA3-256 over payload) | SHA3-256 |
