# Environment E: Investigator Workstation

## Purpose
The Investigator Workstation performs forensic attribution on leaked document artifacts:
1. Ingests evidence (PDF or images) with strict copy-on-ingest semantics.
2. Computes immutable SHA3-256 evidence digests and records timestamped custody actions.
3. Performs blind transform-domain watermark extraction without requiring the original pristine file.
4. Corrects bit errors using Reed-Solomon RS(32, 16) error correction.
5. Queries the distributed BFT ledger to locate the committed attribution event.
6. Verifies cryptographic Merkle inclusion proofs against finalized block headers.
7. Validates recipient ML-DSA-65 digital signatures and certificate chains.
8. Evaluates the deterministic nine-verdict adjudication state machine.
9. Exports tamper-evident PDF forensic investigation reports and portable `.tcproof` bundles.

## Operational Workflow
```bash
# 1. Investigate a leaked document artifact
python deployment/investigator/investigate_leak.py \
  --evidence "C:\Evidence\leaked_scan.pdf" \
  --case-id "cas-2026-HQ-LEAK-01" \
  --ledger-db "deployment/validator/cluster/node-1/ledger.db"

# 2. Or using the unified CLI:
tracecrypt investigate "C:\Evidence\leaked_scan.pdf" \
  --case-id "cas-2026-HQ-LEAK-01" \
  --node-dir "deployment/validator/cluster/node-1"

# 3. Independently verify a standalone proof bundle (zero database connection needed):
tracecrypt verify-bundle "reports\case_cas-2026-HQ-LEAK-01.tcproof"
```
