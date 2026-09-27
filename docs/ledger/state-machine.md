# TraceCrypt Replicated State Machine & State Transition Semantics

## 1. Overview

TraceCrypt implements a deterministic replicated state machine. Every validator node executes identical state transitions given identical committed blocks, ensuring:

$$\text{State}_A(H) == \text{State}_B(H) == \text{State}_C(H) == \text{State}_D(H)$$

$$\text{StateRoot}_A(H) == \text{StateRoot}_B(H) == \text{StateRoot}_C(H) == \text{StateRoot}_D(H)$$

---

## 2. Validate-Before-Mutate

State mutations strictly obey the **Validate-Before-Mutate** principle. Transactions are never applied tentatively to authoritative state without prior cryptographic validation.

```python
apply_block(state, block):
    # 1. Structural and chain continuity checks
    assert block.header.height == state.height + 1
    assert block.header.previous_block_hash == state.last_block_hash

    # 2. Speculative validation of all transactions
    speculative_state = state.clone()
    for tx in block.transactions:
        speculative_state.validate_transaction(tx)
        speculative_state.apply_transaction(tx)

    # 3. State root recomputation
    computed_root = speculative_state.compute_state_root()
    assert computed_root == block.header.state_root

    # 4. Atomic authoritative commit
    state.commit_speculative(speculative_state)
    state.height = block.header.height
    state.last_block_hash = block.header.block_hash
```

---

## 3. Anti-Replay Authoritative Indexes

The state machine maintains four authoritative uniqueness indexes:

1. `events: Dict[EventID, SignedDecryptionEvent]`
2. `sessions: Dict[SessionID, EventID]`
3. `watermarks: Dict[WatermarkID, EventID]`
4. `transactions: Dict[TransactionID, str]`

### Uniqueness Invariants
- **EventID Uniqueness:** An `EventID` can be registered at most once in history.
- **SessionID Uniqueness:** A `SessionID` binds strictly to one decryption event. Reuse of a session ID by an adversary is rejected as a replay attack.
- **WatermarkID Uniqueness:** A `WatermarkID` generated during distribution binds immutably to one attribution event.
- **TransactionID Uniqueness:** A `TransactionID` cannot appear in multiple blocks or multiple times in the same block.

---

## 4. Canonical State Root Commitment

The state root is computed deterministically from the canonical logical state representation:

1. Each committed event index entry is formatted canonically:
   $$\text{entry} = (\text{event\_id}, \text{session\_id}, \text{watermark\_id}, \text{document\_hash}, \text{recipient\_id})$$
2. Entries are sorted lexicographically by `event_id`.
3. Each entry is hashed with domain separator `b"tracecrypt:state:entry:"`:
   $$L_i = \text{SHA3-256}\big(\texttt{"tracecrypt:state:entry:"} \mathbin{\Vert} \text{CanonicalBytes}(\text{entry}_i)\big)$$
4. A binary Merkle tree is computed over the leaf hashes.
5. The resulting root is formatted as `sha3-256:<hex>`.

Because the state root depends only on logical state entries and not physical SQLite row order or disk layouts, every validator computes the identical state root.
