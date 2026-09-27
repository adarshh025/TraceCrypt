# TraceCrypt Forensic Engine Operational Limitations & Boundaries

**Document Version:** 1.0.0  
**Classification:** Technical & Legal Guidance  
**Scope:** Forensic Attribution, Watermark Survivability, Cryptographic Scope  

---

## 1. The Cryptographic Attribution Boundary

> [!IMPORTANT]
> **Fundamental Attribution Principle:**  
> TraceCrypt cryptographically establishes that a certified NIST FIPS 204 ML-DSA-65 private key corresponding to a registered recipient certificate produced the signed attribution event recorded on the immutable ledger.  
> TraceCrypt **does not and cannot independently prove the biological identity of the human operator** manipulating the physical workstation at the time of decryption.

Attribution of a physical human being requires complementary physical security controls, facility access logs, CCTV records, and workstation biometric authentication.

---

## 2. Watermark Survivability Boundaries

The DWT-DCT spread-spectrum watermark engine combined with Reed-Solomon RS(32, 16) error correction provides high robustness against non-malicious distortions and common leak channels. However, the following operational thresholds define the boundary of recovery:

| Distortion Channel | Robust / Decodable Range | Degradation Mode (Fail-Closed) |
| :--- | :--- | :--- |
| **JPEG Compression** | Quality $\ge 65$ (100% recovery) | Quality $< 65$ degrades to `CORRUPTED_WATERMARK` or `NOT_DETECTED`. |
| **Resolution / Downsampling** | $\ge 150\text{ DPI}$ (100% recovery) | $< 96\text{ DPI}$ degrades to `NOT_DETECTED` (carrier loss). |
| **Geometric Cropping** | $\le 10\%$ margins with alignment | $> 15\%$ unaligned crop degrades to `CORRUPTED_WATERMARK`. |
| **Rotation / Skew** | $\pm 3^\circ$ (Automated deskew) | Large unaligned rotations require manual pre-processing. |
| **Impulsive / Gaussian Noise** | $\le 1\%$ pixel noise | Severe additive noise triggers Reed-Solomon uncorrectable error. |
| **Physical Print / Scan** | High-res 300+ DPI optical scan | Moiré patterns and severe halftone screening may degrade high frequencies. |

---

## 3. Cryptographic & Protocol Limitations

1. **BFT Consensus Threshold:**  
   In a 4-node cluster ($n=4$), TraceCrypt guarantees safety and liveness against at most $f=1$ Byzantine validator. If $f \ge 2$ validators act maliciously or collude, the cluster will stall (liveness loss), maintaining safety by refusing to commit conflicting state.
2. **Endpoint OS Compromise:**  
   If an adversary gains root/kernel privilege on an active recipient workstation while a decrypted document is in memory, the adversary may dump volatile memory before zeroization completes.
3. **High-Level Language Memory Management:**  
   While TraceCrypt explicitly executes zeroization via `ctypes.memset` on sensitive buffers, operating system page swapping (paging files) or hypervisor memory snapshots are outside the runtime boundary. Operating system disk encryption (BitLocker) and swap file disabling are mandatory hardening controls.
