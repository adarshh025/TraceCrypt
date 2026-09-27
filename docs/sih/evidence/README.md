# TraceCrypt — Cryptographic Evidence Dossier

This directory contains live, forensically generated evidence artifacts produced by the TraceCrypt SIH 2026 demonstration engine:

1. **`LEAKED_DOCUMENT.pdf`**:
   * The recovered electronic document leaked by Alice Intelligence Officer (`rcp-000000000000000000000000000a11ce`).
   * Contains embedded, imperceptible DWT-DCT spread-spectrum watermarks with high visual quality (PSNR > 40 dB, SSIM > 0.90).
2. **`LEAK_ATTRIBUTION_PROOF.tcproof`**:
   * A standalone, self-contained post-quantum cryptographic proof bundle.
   * Can be independently audited without database access using:
     ```bash
     python -m tracecrypt.cli.main verify-bundle LEAK_ATTRIBUTION_PROOF.tcproof --root-ca <root_ca_file>
     ```
3. **`FORENSIC_REPORT.json`**:
   * Full structured investigation report detailing the multi-factor cryptographic checks:
     * Watermark detection correlation: $\tau = 6.772$
     * Block Height: #2
     * Merkle Inclusion Proof: `VALID`
     * Commit Certificate (2f+1 Quorum): `VALID`
     * Recipient ML-DSA-65 Digital Signature: `VALID`
     * Attribution Verdict: `VERIFIED`
     * Attributed Subject: Alice Intelligence Officer
