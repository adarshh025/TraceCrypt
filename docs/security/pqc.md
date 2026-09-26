# Post-Quantum Cryptography (PQC) Specification: ML-KEM-768 & ML-DSA-65

## 1. Executive Summary

TraceCrypt operates under an air-gapped threat model that accounts for the "Harvest Now, Decrypt Later" (HNDL) paradigm and future quantum cryptanalytic capabilities. In compliance with **NIST FIPS 203** and **NIST FIPS 204**, TraceCrypt eliminates classical public key cryptography (RSA, ECDSA, ECDH) in favor of standardized lattice-based post-quantum algorithms:

1. **Key Encapsulation Mechanism (KEM):** ML-KEM-768 (NIST FIPS 203)
2. **Digital Signature Algorithm (DSA):** ML-DSA-65 (NIST FIPS 204)

Both algorithms operate at **NIST Security Category 3** (equivalent to AES-192 in classical work factor, providing robust 128-bit quantum security margins against Shor's and Grover's algorithms).

---

## 2. Algorithm Parameters & Byte Formats

### 2.1 Key Encapsulation: ML-KEM-768 (FIPS 203)
* **Underlying Lattice Problem:** Module Learning with Errors (M-LWE).
* **Parameters:** $k = 3$, $\eta_1 = 2$, $\eta_2 = 2$, $d_u = 10$, $d_v = 4$, $q = 3329$.
* **Byte Specifications:**
  * **Public Key ($pk$):** Exactly **1,184 bytes**.
  * **Private/Secret Key ($sk$):** Exactly **2,400 bytes**.
  * **Ciphertext ($c$):** Exactly **1,088 bytes**.
  * **Shared Secret ($K$):** Exactly **32 bytes** (256 bits).
* **Decapsulation Behavior:** Implements the Fujisaki-Okamoto transform. On invalid or corrupted ciphertext inputs, the algorithm executes **implicit rejection**, outputting a pseudorandom key derived from the secret seed rather than a recognizable error, defeating chosen-ciphertext oracle attacks.

### 2.2 Digital Signatures: ML-DSA-65 (FIPS 204)
* **Underlying Lattice Problem:** Module Learning with Errors (M-LWE) and Module Short Integer Solution (M-SIS).
* **Parameters:** $k = 6$, $l = 5$, $\eta = 4$, $\gamma_1 = 2^{19}$, $\gamma_2 = (q-1)/32$, $\tau = 49$, $\beta = 196$, $q = 8380417$.
* **Byte Specifications:**
  * **Public Key ($pk$):** Exactly **1,952 bytes**.
  * **Private/Secret Key ($sk$):** Exactly **4,032 bytes**.
  * **Signature ($\sigma$):** Exactly **3,309 bytes**.
* **Verification Determinism:** Verification evaluates polynomial bounds and matrix equations over $R_q$. Verification returns a deterministic boolean verdict (`True` or `False`), failing closed on malformed encodings, wrong message bytes, or invalid signatures.

---

## 3. Cryptographic Implementation Provenance

TraceCrypt uses vetted, offline-installed packages implementing the final FIPS 203 and FIPS 204 standards:

| Algorithm | Package Name | Installed Version | License | Implementation Details | Deterministic Vector Support |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | `mlkem` | `0.0.3` | MIT / Apache-2.0 | Pure Python / C-extension implementation conforming to FIPS 203 Algorithm 16 (`KeyGen_internal`) and Algorithm 17 (`Encaps_internal`). | **VERIFIED** via fixed $(d, z, m)$ seed vectors. |
| **ML-DSA-65** | `dilithium-py` | `1.4.0` | MIT | Python implementation conforming to FIPS 204 Algorithm 1 (`KeyGen_internal`) and Algorithm 2 (`Sign_internal`). | **VERIFIED** via fixed $\zeta$ seed vectors. |

---

## 4. Cryptographic Role Separation

ML-KEM and ML-DSA address orthogonal cryptographic requirements:

```
┌───────────────────────────────────────┐    ┌───────────────────────────────────────┐
│        ML-KEM-768 (FIPS 203)          │    │         ML-DSA-65 (FIPS 204)          │
├───────────────────────────────────────┤    ├───────────────────────────────────────┤
│ Purpose: Key Encapsulation            │    │ Purpose: Digital Signatures           │
│ Role: Confidentiality & Session Keys  │    │ Role: Identity & Event Non-Repudiation│
│ Key Type: MLKEMPublicKey / PrivateKey │    │ Key Type: MLDSAPublicKey / PrivateKey │
└───────────────────────────────────────┘    └───────────────────────────────────────┘
```

### Strict Architectural Enforcement:
1. **Type Safety:** `MLKEMPublicKey` and `MLDSAPublicKey` are distinct immutable Python classes inheriting from `CryptographicKey`. Passing an `MLKEMPublicKey` to a digital signature routine raises `ValidationError` at invocation time.
2. **Key Purpose Binding:** Every key object and metadata record carries an explicit `KeyPurpose` enum (`KEY_ENCAPSULATION`, `DIGITAL_SIGNATURE`, `ROOT_AUTHORITY`).
3. **No Key Reuse:** A recipient identity consists of two independently generated key pairs. Under no circumstances may an ML-KEM private key be used for signing, nor may an ML-DSA private key be used for key decapsulation.

---

## 5. Fail-Closed Security Guarantees

* **Length Verification:** All constructors (`MLKEMPublicKey`, `MLDSAPublicKey`, `MLKEMCiphertext`, `MLDSASignature`, etc.) enforce exact byte lengths before passing buffers to underlying routines. Malformed lengths raise `ValidationError`.
* **Zero Exception Leakage:** Cryptographic exceptions sanitise error descriptions to ensure raw key material, intermediate polynomials, or passphrases are never leaked in stack traces or logs.
* **Deterministic Public Key Fingerprints:**
  * ML-DSA-65: `mldsa65:sha3-256:<hex_digest>`
  * ML-KEM-768: `mlkem768:sha3-256:<hex_digest>`
