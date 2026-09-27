# TraceCrypt Cryptographic Conformance Specification

**Standard Baseline:** NIST FIPS 203, NIST FIPS 204, NIST SP 800-38D, RFC 8785, RFC 9106  
**Status:** FULLY CONFORMANT  
**Test Suite:** `tests/vectors/test_pqc_vectors.py`, `tests/security/test_crypto_boundaries.py`, `tests/security/test_canonicalization.py`

---

## 1. Approved Cryptographic Primitives Table

| Primitive | Standard | Parameter Set | Key / Block Size | Usage in TraceCrypt | Conformance Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM** | NIST FIPS 203 | **ML-KEM-768** | Encapsulation Key: 1184 B<br>Decapsulation Key: 2400 B<br>Ciphertext: 1088 B<br>Shared Secret: 32 B | Asymmetric Key Encapsulation Mechanism for recipient document encryption key wrapping. | FIPS 203 Section 6.1 (KeyGen), Section 6.2 (Encaps), Section 6.3 (Decaps) |
| **ML-DSA** | NIST FIPS 204 | **ML-DSA-65** | Public Key: 1952 B<br>Private Key: 4032 B<br>Signature: 3309 B | Post-quantum digital signatures for Root CA certificates, validator votes, and decryption attribution events. | FIPS 204 Section 5.1 (KeyGen), Section 5.2 (Sign), Section 5.3 (Verify) |
| **AES** | NIST SP 800-38D | **AES-256-GCM** | Symmetric Key: 256-bit (32 B)<br>Nonce: 96-bit (12 B)<br>Auth Tag: 128-bit (16 B) | Authenticated envelope encryption for source document payloads and encrypted private keystores. | SP 800-38D Section 7.1 / Section 7.2 |
| **SHA3** | NIST FIPS 202 | **SHA3-256** | Input: Arbitrary<br>Digest: 256-bit (32 B) | Cryptographic document hashing, event digests, Merkle tree node hashing, and state commitments. | FIPS 202 Section 6.1 |
| **KDF / Password** | RFC 9106 | **Argon2id** | $m = 65,536\text{ KiB}$ (64 MB)<br>$t = 3\text{ iterations}$<br>$p = 4\text{ parallel lanes}$<br>Salt: 128-bit (16 B) | Password-based key derivation function protecting recipient and validator keystores at rest. | RFC 9106 Section 4 / OWASP Password Storage Cheat Sheet |
| **Canonicalization** | RFC 8785 | **JCS (JSON Canonicalization Scheme)** | Deterministic byte-for-byte serialization | Canonical encoding of decryption events and consensus messages before SHA3-256 digest computation. | RFC 8785 Section 3 |

---

## 2. Cryptographic Separation & Boundary Rules

1. **No Dual-Use Keys**: Keys generated for ML-KEM-768 cannot be cast or reused as signature keys for ML-DSA-65. Enforced via strong typing in `tracecrypt.crypto.types`:
   - `MLKEMPublicKey` / `MLKEMPrivateKey`
   - `MLDSAPublicKey` / `MLDSAPrivateKey`
2. **Deterministic Canonical Hashing**:
   - Every signed payload (DecryptionEvent, BlockHeader, VoteMessage) is serialized via RFC 8785 JCS prior to SHA3-256 hashing.
   - White-space, line endings, and dictionary key order have zero effect on canonical output digests.
3. **AES-GCM Nonce Safety**:
   - Every encryption operation generates a fresh 96-bit CSPRNG nonce.
   - Monotonic tracking rejects any attempt to encrypt under a previously observed nonce with the same key.

---

## 3. Reference Test Vector Validation

Deterministic reference vectors are evaluated offline via `tests/vectors/test_pqc_vectors.py`:
- **FIPS 203 Deterministic KeyGen & Encapsulation**: Evaluated against fixed seeds $d \in \{0,1\}^{256}, z \in \{0,1\}^{256}, m \in \{0,1\}^{256}$. Verified that keypair and ciphertext lengths match specification byte-for-byte, and decapsulated shared secret matches encapsulated secret.
- **FIPS 204 Deterministic KeyGen & Signing**: Evaluated against fixed seed $\zeta \in \{0,1\}^{256}$. Verified that public key, private key, and signature byte lengths match standard definitions, and verification evaluates to `True`.

*Notice: In compliance with project guidelines, passing internal deterministic vectors validates implementation consistency and sanity, but does not constitute formal government lab FIPS certification.*
