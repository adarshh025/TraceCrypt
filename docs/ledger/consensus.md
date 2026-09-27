# TraceCrypt Consensus Engine & Round Lifecycle

## 1. Overview

TraceCrypt implements a deterministic permissioned Byzantine Fault Tolerant (BFT) consensus protocol inspired by the safety and finality properties of Tendermint / CometBFT.

Consensus proceeds in heights ($H = 1, 2, 3, \dots$) and rounds ($R = 0, 1, 2, \dots$). Each height finalizes exactly one block into the immutable ledger.

```
       [HEIGHT H, ROUND R]
                 |
                 v
         +---------------+
         |    PROPOSE    |  (Designated Proposer creates & signs Block)
         +---------------+
                 |
                 v
         +---------------+
         |    PREVOTE    |  (Validators validate proposal & broadcast Prevote)
         +---------------+
                 |
        (Quorum 2f+1 reached?)
            /         \
          Yes          No (Timeout / Round Change -> Round R+1)
          /             
         v              
  +-------------+       
  |  PRECOMMIT  |  (Validators lock on block & broadcast Precommit)
  +-------------+       
         |              
(Quorum 2f+1 reached?)  
     /         \        
   Yes          No (Timeout / Round Change -> Round R+1)
   /                    
  v                     
+-------------+         
|   COMMIT    |  (Form CommitCertificate, apply state transition, advance to Height H+1)
+-------------+         
```

---

## 2. Deterministic Proposer Selection

Proposer selection is strictly deterministic and depends exclusively on agreed chain state (the validator set, height, and round):

$$\text{slot} = (H + R) \pmod{N_{\text{active}}}$$

$$\text{proposer} = \text{sorted\_validators}[\text{slot}]$$

- Validators are sorted canonically by `ValidatorID`.
- No local clock timing, randomness beacon, or external oracle is consulted.
- Every honest node deterministically identifies the exact same proposer for any $(H, R)$.
- Proposals submitted by any node other than the designated proposer are immediately rejected with a log warning.

---

## 3. Consensus Phases

### Phase 1: Propose
The designated proposer:
1. Gathers pending transactions from its mempool sorted deterministically by `(submitted_at, transaction_id)`.
2. Computes the binary SHA3-256 Merkle root `transaction_root`.
3. Speculatively applies transactions to compute the new `state_root`.
4. Assembles and signs the `BlockHeader`, binding `previous_block_hash`, `height`, `round`, and `validator_set_hash`.
5. Broadcasts the proposal to all connected peers.

### Phase 2: Prevote
Upon receiving a proposal:
1. Validators verify:
   - Header binds to correct `chain_id`, `height`, and `round`.
   - Proposer matches deterministic selection for $(H, R)$.
   - `previous_block_hash` matches current state's `last_block_hash`.
   - `transaction_root` matches independent Merkle recomputation of transactions.
   - `state_root` matches speculative state execution.
2. If valid, the validator broadcasts a signed `PREVOTE` for `block_hash`.
3. If invalid or timed out, the validator prevotes `None` (nil).

### Phase 3: Precommit
1. A node observes Prevotes for height $H$, round $R$.
2. If $\ge 2f + 1$ (3 out of 4) Prevotes for `block_hash` are collected:
   - The node locks on `(round, block)`.
   - The node broadcasts a signed `PRECOMMIT` for `block_hash`.
3. If quorum is not reached before timeout, the validator precommits `None`.

### Phase 4: Commit
1. When $\ge 2f + 1$ matching `PRECOMMIT` votes for `block_hash` are collected, a cryptographic `CommitCertificate` is constructed.
2. The block is finalized and immutable:
   - `self.state.apply_block(finalized_block)` executes logical state mutations.
   - Committed transactions are atomically evicted from the mempool.
   - The block, transactions, indexes, and certificate are persisted to SQLite WAL.
   - Height advances: $H \leftarrow H + 1$, $R \leftarrow 0$.

---

## 4. Quorum Formula

For an active validator set of total voting power $W$:

$$\text{Quorum Threshold} = \left\lfloor \frac{2 \cdot W}{3} \right\rfloor + 1$$

For $n=4$ equal-weight validators ($W=4$):
$$\left\lfloor \frac{2 \cdot 4}{3} \right\rfloor + 1 = \lfloor 2.666 \dots \rfloor + 1 = 2 + 1 = 3 \text{ votes}$$

Consensus can never finalize a block with fewer than 3 valid signatures from authorized validators.

---

## 5. Round / View Change

If the designated proposer is offline, proposes an invalid block, or fails to deliver in time:
1. Honest validators timeout on the current round.
2. `advance_round()` increments round index: $R \leftarrow R + 1$.
3. A new proposer is deterministically selected for $(H, R + 1)$.
4. If a validator locked on a block in a previous round, it preserves safety by voting only for the locked block unless a higher round delivers $2f+1$ Prevotes for an alternative proposal.
