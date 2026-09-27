# Smart India Hackathon 2026 — TraceCrypt Submission Dossier

**Event:** Smart India Hackathon 2026 (SIH 2026)  
**Team Name:** Team Laccha Paratha  
**Team ID:** 138638  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution  
**Problem Statement ID:** SIH26237  
**Team Leader:** Adarsh Aher  
**Team Members:** Adarsh Aher, Kashish, Twinkle Belhekar, Pratibha Kumari, Utkarsh Magar, Akash Rajput  
**Repository:** https://github.com/adarshh025/TraceCrypt  

---

## Submission Documentation Index

This directory serves as the consolidated submission dossier for the SIH 2026 evaluation committee:

1. **[Implementation Status](implementation-status.md):** Exhaustive audit of all 13 core subsystems verifying 100% real implementation with zero mocks.
2. **[Requirements Traceability Matrix](traceability.md):** Complete bidirectional mapping of REQ-01 through REQ-14 to code implementations and tests.
3. **[Live Demonstration Script](demo-script.md):** Step-by-step 8–10 minute evaluation guide for judges with expected terminal outputs and presenter dialogues.
4. **[System Architecture](architecture.md):** Detailed technical breakdown of post-quantum PKI, packaging, release gate, watermarking, and BFT consensus.
5. **[Security & Adversarial Analysis](security.md):** Red-team test results covering identity framing, signature tampering, replay attacks, and fault tolerance.
6. **[Empirical Robustness & Limitations](limitations.md):** Transparent documentation of watermark degradation boundaries under lossy compression and transformation channels.
7. **[Benchmark Summary](benchmark-summary.md):** Real performance metrics across encryption, watermarking, consensus latency, and blind extraction.
8. **[Evidence Artifacts](evidence/):** Cryptographic evidence generated during demonstration, including the standalone `.tcproof` audit bundle and forensic JSON report.

---

## 60-Second Quickstart for Judges

To run the complete automated evaluation on any air-gapped terminal:

```bash
# 1. Verify 100% offline air-gap compliance
python -m tracecrypt.cli.main security airgap-check

# 2. Run master end-to-end demonstration across all 11 stages
python -m tracecrypt.cli.main demo all
```
