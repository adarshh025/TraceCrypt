# Offline Post-Quantum PKI & Certificate Architecture

## 1. Threat Model & Air-Gap Principles

Traditional Public Key Infrastructure (PKI) relies heavily on connected network services:
* Online Certificate Status Protocol (OCSP) responders.
* Public Certificate Revocation List (CRL) distribution points.
* Web-based Certificate Authorities (ACME, Let's Encrypt).
* Public Root Stores maintained by operating system vendors.

In the **TraceCrypt Air-Gapped Environment**, zero outbound network communication is permitted. The PKI architecture must be completely self-contained, offline-verifiable, and anchored in an offline post-quantum root authority.

---

## 2. Standards Interoperability & Envelope Design

### 2.1 The Post-Quantum X.509 Interoperability Dilemma
Classical X.509 v3 structures (RFC 5280) specify ASN.1 Object Identifiers (OIDs) primarily for RSA, DSA, and ECDSA. While draft IETF specifications exist for ML-DSA and ML-KEM, conventional offline tooling (OpenSSL 1.1/3.0, Windows CryptoAPI, standard Python `cryptography` x509 module) cannot natively serialize or validate post-quantum certificates without proprietary or non-standard OID monkey-patching.

**TraceCrypt Architectural Decision:**
Rather than constructing a misleading "pseudo-X.509" certificate that falsely asserts standard RFC 5280 compliance, TraceCrypt explicitly defines a **Versioned Authenticated Identity Envelope**:
* **RFC 8785 JSON Canonicalization Scheme (JCS)** is used to achieve deterministic canonical byte representation across heterogeneous architectures.
* Canonical envelope bytes are signed directly by the Root CA using **NIST FIPS 204 ML-DSA-65**.
* The certificate format is cryptographically deterministic, transparent, and auditable.

### 2.2 PQC Identity Certificate Schema
A `PQCIdentityCertificate` encapsulates:
```json
{
  "format_version": "1.0.0",
  "serial_number": "crt-d34db33f...",
  "issuer_id": "ca-root-airgap-01",
  "subject_id": "rcp-operative-42",
  "device_id": "dev-airgap-ws01",
  "role": "RECIPIENT",
  "organization": "TraceCrypt Air-Gap Cell",
  "key_purpose": "DIGITAL_SIGNATURE",
  "algorithm": "ML-DSA-65",
  "parameter_set": "ML-DSA-65",
  "public_key_fingerprint": "mldsa65:sha3-256:a1b2...",
  "public_key_b64": "<base64_encoded_1952_bytes>",
  "valid_from": 1774579200000000,
  "valid_until": 1777171200000000,
  "signature_b64": "<base64_encoded_3309_bytes>"
}
```

---

## 3. The 12-Point Offline Validation Pipeline

Validation is executed by `CertificateValidator.validate()` without any online lookups. The process evaluates 12 sequential checks, failing closed on the first violation:

```
Certificate Input
       │
       ▼
 [Check 1: Structure & Protocol Version] ── Fail ──► ValidationError
       │
       ▼
 [Check 2: Issuer Identity] ─────────────── Fail ──► SecurityError
       │
       ▼
 [Check 3: Issuer ML-DSA-65 Signature] ─── Fail ──► SecurityError
       │
       ▼
 [Check 4: Subject Identity] ────────────── Fail ──► ValidationError
       │
       ▼
 [Check 5: Public Key Binding & Digest] ── Fail ──► SecurityError
       │
       ▼
 [Check 6: Authorized Algorithm] ───────── Fail ──► ValidationError
       │
       ▼
 [Check 7: Parameter Set Match] ────────── Fail ──► ValidationError
       │
       ▼
 [Check 8: Temporal Validity Window] ───── Fail ──► SecurityError
       │
       ▼
 [Check 9: Certificate Status Invariants] ─ Fail ──► SecurityError
       │
       ▼
 [Check 10: Expected Key Purpose] ──────── Fail ──► SecurityError
       │
       ▼
 [Check 11: Offline Revocation Status] ─── Fail ──► SecurityError
       │
       ▼
 [Check 12: Chain to Trusted Root CA] ──── Fail ──► SecurityError
       │
       ▼
  Validation Successful (Valid = True)
```

1. **Structure:** Verifies all mandatory fields conform to schema version `1.0.0`.
2. **Issuer Identity:** Checks issuer matches known Root CA identifier.
3. **Cryptographic Signature:** Verifies ML-DSA-65 signature over canonical RFC 8785 bytes using the Root CA's public key.
4. **Subject Identity:** Rejects empty or malformed subject IDs.
5. **Public Key Binding:** Decodes raw public key bytes, checks exact size (1,184 for KEM; 1,952 for DSA), recalculates SHA3-256 fingerprint, and verifies equality against `public_key_fingerprint`.
6. **Algorithm Check:** Ensures algorithm is strictly `ML-DSA-65` or `ML-KEM-768`.
7. **Parameter Set:** Confirms exact parameter set alignment.
8. **Temporal Validity:** Compares current microsecond timestamp against `valid_from` and `valid_until`.
9. **Status Invariants:** Verifies certificate is in active standing.
10. **Key Purpose:** Asserts certificate purpose matches the requested operational context (`DIGITAL_SIGNATURE`, `KEY_ENCAPSULATION`, or `ROOT_AUTHORITY`).
11. **Offline Revocation Check:** Verifies certificate serial is not present in local `OfflineRevocationStore`.
12. **Root CA Chain:** Verifies issuer public key equals the trusted offline Root CA public key.

---

## 4. Offline Revocation Architecture

In the absence of online CRL or OCSP responders, revocation operates via signed **Revocation Records**:
* When an authority revokes a certificate, an immutable `RevocationRecord` is generated containing the revoked `serial_number`, `key_id`, `reason`, and timestamp.
* The Root CA signs the canonical record using its ML-DSA-65 master private key.
* Revocation records are persisted locally in SQLite (`revocation_records` table) and packaged into distribution bundles to be synchronized across air-gapped nodes during data exchanges.
* In Phase 6, revocation records are permanently committed to the tamper-evident distributed ledger.
