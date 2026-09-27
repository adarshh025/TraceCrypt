# Environment D: Permissioned BFT Validator Nodes

## Topology Reference
TraceCrypt utilizes an offline, permissioned Byzantine Fault Tolerant (BFT) consensus network:
- Number of nodes: $n = 4$
- Byzantine fault threshold: $f = \lfloor(n - 1) / 3\rfloor = 1$
- Consensus quorum: $2f + 1 = 3$ votes
- Node roles: `node-1` (9101), `node-2` (9102), `node-3` (9103), `node-4` (9104)

## Guarantees
- Replicated commit: No single node can rewrite or falsify historical attribution records.
- Deterministic proposer rotation: Round-robin state-machine-driven leader selection.
- Merkle inclusion proofs: Independent mathematical verification of event commitment.
- Zero external network discovery: Explicit, static air-gapped peer matrix.

## Operational Workflow
```bash
# 1. Bootstrap 4-Node Cluster
python scripts/bootstrap_four_node_ledger.py --cluster-dir deployment/validator/cluster

# 2. Check cluster consensus status
tracecrypt ledger status --cluster-dir deployment/validator/cluster

# 3. Verify cryptographic chain integrity
tracecrypt ledger verify --cluster-dir deployment/validator/cluster

# 4. Start an individual validator node
python deployment/validator/start_validator.py --node-dir deployment/validator/cluster/node-1
```
