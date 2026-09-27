# TraceCrypt BFT Distributed Ledger Architecture

## 1. Overview

The TraceCrypt Distributed Ledger Subsystem provides an air-gapped, permissioned, Byzantine Fault Tolerant (BFT) replicated state machine designed exclusively for forensic decryption attribution and tamper-evident audit logs.

The architecture strictly rejects common shortcuts:
- It is **not** a single SQLite audit table or centralized database.
- It is **not** an insecure hash chain without consensus.
- It does **not** rely on external public blockchains (Ethereum, Bitcoin) or cloud RPCs.
- It is an autonomous, self-contained replicated state machine operating under the safety and finality model inspired by Tendermint / CometBFT.

```
+-----------------------------------------------------------------------------------+
|                            TraceCrypt Validator Node                              |
|                                                                                   |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  |   Consensus Engine |<->|    Mempool (TxPool) |<->|      Ledger State        |  |
|  | (Propose/Prevote/  |   | (Anti-Replay / PQC  |   | (Validate -> Mutate /    |  |
|  |  Precommit/Commit) |   |  Sig Verification)  |   |  Logical State Root)     |  |
|  +--------------------+   +---------------------+   +--------------------------+  |
|            |                         |                           |                |
|            v                         v                           v                |
|  +-----------------------------------------------------------------------------+  |
|  |                            SQLite WAL Storage                               |  |
|  | (Blocks, Transactions, Event Indexes, Commit Certificates, Merkle Tree)     |  |
|  +-----------------------------------------------------------------------------+  |
|            ^                                                                      |
|            |                                                                      |
|  +--------------------+   +---------------------+                                 |
|  |  Sync Manager      |<->| P2P Network (LAN)   |                                 |
|  | (Header/Block/Cert)|   | (Framed SHA3-256)   |                                 |
|  +--------------------+   +---------------------+                                 |
+-----------------------------------------------------------------------------------+
```

---

## 2. Validator Model & Byzantine Bounds

The default deployment topology consists of **4 validator nodes** ($n = 4$):

$$f = \left\lfloor \frac{n - 1}{3} \right\rfloor = \left\lfloor \frac{4 - 1}{3} \right\rfloor = 1$$

- **Maximum Byzantine Fault Tolerance ($f$):** 1 malicious or crash-faulty validator.
- **Quorum Threshold ($Q$):** Generic formula:
  $$Q = 2f + 1 = 2(1) + 1 = 3 \text{ votes}$$
  More generally, for arbitrary voting power $W$:
  $$Q = \left\lfloor \frac{2 \cdot W}{3} \right\rfloor + 1$$
- **Safety Invariant:** As long as no more than $f=1$ validators are Byzantine, the ledger guarantees **zero conflicting finalized blocks** at any height.
- **Liveness Invariant:** If $n - f = 3$ honest validators are online and communicating, progress is guaranteed. If 2 or more validators crash or become partitioned, liveness halts safely (no blocks commit).

---

## 3. Node Roles & Cryptographic Identity Separation

Two distinct node roles exist:
1. `VALIDATOR`: Holds voting power, proposes blocks, broadcasts signed Prevotes and Precommits, and forms quorum certificates.
2. `OBSERVER`: Read-only replica. Synchronizes blocks, independently verifies Merkle roots, state roots, and validator signatures, and serves query APIs, but cannot vote in consensus.

### Cryptographic Separation of Keys
TraceCrypt enforces strict domain separation between recipient and validator keys:
- **Recipient Keys:** Used exclusively for signing `DecryptionEvent` payloads (`KeyPurpose.DIGITAL_SIGNATURE`).
- **Validator Keys:** Used exclusively for signing consensus votes and commit certificates (`KeyPurpose.CONSENSUS_VALIDATION`).

Attempting to sign consensus messages with a recipient key or submit recipient signatures as validator votes triggers immediate fail-closed validation rejection.

---

## 4. Subsystem Components

1. **`tracecrypt.ledger.validator`:** Validator set representation, identity management, voting power aggregation, and deterministic round-robin proposer selection.
2. **`tracecrypt.ledger.genesis`:** Canonical RFC 8785 genesis specification, binding chain ID, initial state root, and active validator set into an authoritative `genesis_hash`.
3. **`tracecrypt.ledger.merkle`:** Binary SHA3-256 Merkle tree with explicit domain separators for transaction root commitments and standalone $O(\log N)$ inclusion proofs.
4. **`tracecrypt.ledger.messages`:** Strongly-typed consensus messages (`VoteMessage`, `CommitCertificate`, `ByzantineEvidence`) bound to `chain_id`, `height`, `round`, and `block_hash`.
5. **`tracecrypt.ledger.block`:** Immutable block structures binding header metadata, ordered transactions, and quorum commit certificates.
6. **`tracecrypt.ledger.state`:** Replicated deterministic state machine enforcing "validate-before-mutate", maintaining anti-replay indexes (`EventID`, `SessionID`, `WatermarkID`, `TransactionID`) and computing canonical state roots.
7. **`tracecrypt.ledger.mempool`:** Thread-safe, bounded transaction pool providing deterministic sorting by `(submitted_at, transaction_id)`.
8. **`tracecrypt.ledger.consensus`:** 4-phase BFT consensus engine (Propose $\to$ Prevote $\to$ Precommit $\to$ Commit) with locking rules, equivocation detection, and round transitions.
9. **`tracecrypt.ledger.storage`:** SQLite WAL storage engine with cross-column tamper verification and end-to-end chain verification.
10. **`tracecrypt.ledger.network`:** Length-prefixed binary wire protocol with SHA3-256 framing, strictly isolated to configured local LAN peers.
11. **`tracecrypt.ledger.sync`:** Cryptographically validated block catch-up protocol for lagging or restarted nodes.
12. **`tracecrypt.ledger.node`:** Unified `BFTLedgerNode` coordinator implementing the `DecryptionEventLedger` interface required by the recipient attribution pipeline.
