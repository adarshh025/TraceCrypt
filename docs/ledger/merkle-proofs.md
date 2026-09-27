# TraceCrypt Merkle Trees & Cryptographic Inclusion Proofs

## 1. Merkle Tree Architecture

TraceCrypt uses a deterministic binary SHA3-256 Merkle tree for all transactions in every block. The root commitment `transaction_root` is stored in the `BlockHeader`.

### Leaf and Node Domain Separation
To prevent second-preimage attacks and domain ambiguity, distinct domain separators are prepended:

- **Leaf Hash:**
  $$\text{Leaf}(T) = \text{SHA3-256}\big(\texttt{"tracecrypt:merkle:leaf:"} \mathbin{\Vert} \text{CanonicalBytes}(T)\big)$$
- **Node Hash:**
  $$\text{Node}(L, R) = \text{SHA3-256}\big(\texttt{"tracecrypt:merkle:node:"} \mathbin{\Vert} L \mathbin{\Vert} R\big)$$
- **Empty Tree Root:**
  $$\text{EmptyRoot} = \text{"sha3-256:0000000000000000000000000000000000000000000000000000000000000000"}$$

If a level has an odd number of elements, the last element is promoted directly to the next level (or paired deterministically per the RFC 6962 / standard binary tree specification).

---

## 2. Inclusion Proof Structure

A `MerkleInclusionProof` provides standalone proof that a specific transaction exists at index $i$ in a block without revealing or requiring the full transaction set:

```json
{
  "leaf_hash": "sha3-256:55aa66bb...",
  "leaf_index": 2,
  "total_leaves": 4,
  "audit_path": [
    {
      "direction": "LEFT",
      "sibling_hash": "sha3-256:11223344..."
    },
    {
      "direction": "RIGHT",
      "sibling_hash": "sha3-256:aabbccdd..."
    }
  ],
  "expected_root": "sha3-256:e3b0c442..."
}
```

---

## 3. Independent Verification Algorithm

Verification requires **zero database access**:

1. Hash the provided candidate transaction bytes:
   $$H_0 = \text{SHA3-256}(\texttt{"tracecrypt:merkle:leaf:"} \mathbin{\Vert} \text{CandidateBytes})$$
2. Assert $H_0 == \text{proof.leaf\_hash}$.
3. For each step $(D_k, S_k)$ in $\text{proof.audit\_path}$:
   - If $D_k == \texttt{"LEFT"}$: $H_{k+1} = \text{SHA3-256}(\texttt{"tracecrypt:merkle:node:"} \mathbin{\Vert} S_k \mathbin{\Vert} H_k)$
   - If $D_k == \texttt{"RIGHT"}$: $H_{k+1} = \text{SHA3-256}(\texttt{"tracecrypt:merkle:node:"} \mathbin{\Vert} H_k \mathbin{\Vert} S_k)$
4. Assert $H_K == \text{proof.expected\_root}$.

### Investigator Cryptographic Chain of Custody
An investigator verifies attribution end-to-end:
```
Transaction (Signed DecryptionEvent)
   ↓ (Leaf Hashing)
Transaction Leaf
   ↓ (Merkle Inclusion Proof)
Block Header transaction_root
   ↓ (Block Header Hashing)
Block Hash
   ↓ (Validator CommitCertificate)
Quorum (>= 2f+1 Valid Signatures)
   ↓ (Genesis Validator Set)
Authoritative Offline Replicated Ledger State
```
