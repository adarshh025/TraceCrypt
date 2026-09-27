# TraceCrypt Byzantine Fault Model & Equivocation Defense

## 1. Byzantine Fault Assumptions

The security of TraceCrypt's permissioned ledger is founded on classical BFT assumptions:
- **Total Validators ($n$):** 4
- **Maximum Byzantine Nodes ($f$):**
  $$f = \left\lfloor \frac{n - 1}{3} \right\rfloor = \left\lfloor \frac{4 - 1}{3} \right\rfloor = 1$$
- **Consensus Quorum ($Q$):**
  $$Q = 2f + 1 = 3 \text{ votes}$$

---

## 2. Threat & Failure Scenarios

| Failure Scenario | Behavior / Consequence | Invariant Preserved |
|---|---|---|
| **1 Validator Offline / Crashed** | 3 honest nodes remain online. $3 \ge 2f + 1$. Consensus continues without delay. | **Safety & Liveness** |
| **1 Byzantine Proposer (Invalid Proposal)** | Honest validators independently verify state root, transaction root, and signatures. Proposal is rejected. | **Safety** |
| **1 Byzantine Proposer (Conflicting Proposals)** | Proposer sends Block A to some nodes and Block B to others. Neither block can gather 3 votes. Round times out and advances. | **Safety** |
| **1 Byzantine Validator (Conflicting Votes / Equivocation)** | Malicious validator signs two different Prevotes or Precommits for the same $(H, R)$. Detected immediately; `ByzantineEvidence` created. | **Safety** |
| **2 Validators Offline or Malicious ($f > 1$)** | With only 2 honest validators online, quorum of 3 cannot be formed ($2 < 3$). System halts cleanly. | **Safety** (Liveness safely suspended) |
| **2+2 Network Partition** | Cluster split into two groups of 2. Neither group can form quorum ($2 < 3$). Neither group commits blocks. Upon healing, nodes reconcile. | **Safety** (Zero conflicting finality) |

---

## 3. Byzantine Evidence Model

When any node observes two distinct votes signed by the same validator for the same height, round, and phase with different block hashes:

```python
class ByzantineEvidence(BaseModel):
    validator_id: ValidatorID
    height: int
    round: int
    vote_type: VoteType
    conflicting_vote_a: VoteMessage
    conflicting_vote_b: VoteMessage
    evidence_hash: str
```

### Evidence Verification
Evidence is self-authenticating:
1. Verify `conflicting_vote_a.signature` against validator's ML-DSA-65 public key.
2. Verify `conflicting_vote_b.signature` against validator's ML-DSA-65 public key.
3. Assert `vote_a.height == vote_b.height`.
4. Assert `vote_a.round == vote_b.round`.
5. Assert `vote_a.vote_type == vote_b.vote_type`.
6. Assert `vote_a.block_hash != vote_b.block_hash`.

If all assertions hold, the validator has committed provable equivocation. The evidence is permanently logged in `byzantine_evidence` storage for administrative audit and penalty.
