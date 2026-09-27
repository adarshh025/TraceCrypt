# TraceCrypt Security Findings Database & Vulnerability Register

**Document Version:** 1.0.0  
**Security Standard:** ISO/IEC 29147, NIST SP 800-218 (SSDF)  
**Scope:** TraceCrypt Core, Cryptography, PKI, BFT Consensus, Forensics, Storage  

---

## 1. Security Severity Model

TraceCrypt applies an objective, five-tier vulnerability severity model:

| Severity | Definition | SLA / Remediation Standard |
| :--- | :--- | :--- |
| **CRITICAL** | Flaws leading to arbitrary cryptographic key compromise, forged attribution events, bypassed BFT safety, or remote/local code execution. | Immediate hotfix; release gate blocked. |
| **HIGH** | Flaws causing ledger state divergence, denial of service across consensus nodes, unauthenticated document decapsulation, or directory traversal. | Fix required prior to production release. |
| **MEDIUM** | Incomplete input sanitization (e.g. null bytes in filenames), unhandled parser edge cases causing process termination, or non-deterministic verdict evaluation. | Fix required with regression test. |
| **LOW** | Minor information disclosure in local logs, non-standard exception types, or missing resource boundary assertions. | Remediation in scheduled maintenance cycle. |
| **INFORMATIONAL**| Security hygiene, defensive hardening suggestions, or operational best practice enhancements. | Tracked for continuous improvement. |

---

## 2. Findings Register

### SEC-FIND-01: Evidence Ingestion Null Byte Filename Pass-Through
- **ID:** `SEC-FIND-01`
- **Title:** Unsanitized Null Byte in Evidence Filename Hint Allows Null Byte Interaction (CWE-626)
- **Severity:** `MEDIUM`
- **Affected Component:** `tracecrypt/forensics/ingestion.py` (`EvidenceIngestion.ingest`)
- **Attack Preconditions:** An investigator or hostile actor provides a custom filename parameter containing an embedded null byte (`\x00`), such as `"harmless.pdf\x00malicious.exe"`.
- **Attack Steps:**
  1. Call `EvidenceIngestion.ingest(evidence_input, filename="evidence.pdf\x00hack.exe")`.
  2. Inspect the resulting `ForensicEvidence.filename`.
- **Observed Result:** The string retained the null byte without validation or exception, passing `"\x00"` to downstream logging, metadata storage, and report generators.
- **Expected Result:** The parser must detect the null byte and fail closed by raising `ForensicEvidenceError("Filename contains forbidden null byte character.")`.
- **Impact:** While Python 3 handles null bytes in memory, passing unsanitized strings containing `\x00` to native OS filesystem APIs, C extensions, or SQLite queries can cause string truncation or unexpected file extension behavior.
- **Root Cause:** `Path(filename).name` preserves embedded null characters in Python `str` without validation.
- **Fix:** Added an explicit fail-closed null byte assertion in `EvidenceIngestion.ingest`:
  ```python
  if "\x00" in resolved_filename:
      raise ForensicEvidenceError("Filename contains forbidden null byte character.")
  ```
- **Regression Test:** `tests/security/test_filesystem_archive_attacks.py::test_null_byte_in_filename_rejected`
- **Status:** **RESOLVED**

---

### SEC-FIND-02: Strict Boundary on Two-Byzantine Failure in 4-Node Cluster
- **ID:** `SEC-FIND-02`
- **Title:** Byzantine Liveness Stall under 2 Malicious Validators ($n=4, f=2$)
- **Severity:** `INFORMATIONAL` (Documented Protocol Boundary)
- **Affected Component:** `tracecrypt/ledger/consensus.py` (`ConsensusEngine`)
- **Attack Preconditions:** In an $n=4$ BFT network, two validators ($f=2$) are compromised or colluding.
- **Attack Steps:**
  1. Two malicious validators produce conflicting votes for an unauthorized block.
  2. The two honest validators refuse to vote for the conflicting proposal.
- **Observed Result:** Consensus halts; neither block reaches quorum ($2 < 3$ required). The cluster enters a liveness stall without committing any state.
- **Expected Result:** Under Byzantine consensus theory, a network of $n$ nodes tolerates at most $f = \lfloor(n-1)/3\rfloor$ Byzantine nodes. For $n=4$, $f_{max} = 1$. When $f=2$, safety must be preserved at the expense of liveness.
- **Impact:** System availability halts, but zero false blocks are committed (zero split-brain, zero double-spend).
- **Root Cause:** Inherent mathematical bound of Byzantine fault tolerance.
- **Fix / Mitigation:** Documented in `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`, and validated by regression test.
- **Regression Test:** `tests/security/test_bft_fault_injection.py::test_two_byzantine_validators_cannot_force_commit`
- **Status:** **VERIFIED & DOCUMENTED**

---

### SEC-FIND-03: Spatial Watermark Grid Desynchronization under Unregistered Cropping
- **ID:** `SEC-FIND-03`
- **Title:** Cropping Without Coordinate Registration Causes Reed-Solomon Fail-Closed Degradation
- **Severity:** `INFORMATIONAL` (Expected Forensic Defense)
- **Affected Component:** `tracecrypt/watermark/` and `tracecrypt/forensics/extraction.py`
- **Attack Preconditions:** Leaker crops more than 5% of document margins and scales the remaining image arbitrarily.
- **Attack Steps:**
  1. Leaker crops outer margins of watermarked PDF page.
  2. Investigator runs extraction without geometric feature alignment.
- **Observed Result:** The 8x8 DCT block lattice shifts relative to the 2D Haar sub-bands, causing pseudo-random chip correlation loss. Reed-Solomon RS(32, 16) error correction flags uncorrectable symbol errors, resulting in `CORRUPTED_WATERMARK` or `NOT_DETECTED`.
- **Expected Result:** Under severe non-registered cropping, the system must fail closed rather than hallucinating an incorrect attribution.
- **Impact:** Zero false positive attribution; clean degradation to `CORRUPTED_WATERMARK` (Verdict V6).
- **Mitigation:** Pre-extraction normalizer includes Hough line deskewing and canonical dimension alignment.
- **Regression Test:** `tests/security/test_watermark_lab.py::test_cropping_attack`
- **Status:** **VERIFIED & DOCUMENTED**
