# TraceCrypt Protocol Versioning & Cross-Version Compatibility Matrix

**Document Version:** 1.0.0  
**Status:** Canonical Reference  
**Applicability:** TraceCrypt Core, Ledger Consensus, PKI, Forensics  

---

## 1. Versioning Architecture

TraceCrypt decouples software releases from cryptographic protocols and serialization formats to ensure long-term archive stability, backward compatibility, and court admissibility of historical evidence.

The canonical version definitions are centralized in [`tracecrypt/version.py`](file:///c:/TraceCrypt/tracecrypt/version.py):

| Subsystem | Version Identifier | Current Value | Versioning Standard | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Application** | `APPLICATION_VERSION` | `1.0.0` | Semantic Versioning (SemVer 2.0) | User-facing distribution package version. |
| **Protocol** | `PROTOCOL_VERSION` | `1.0.0` | Major.Minor.Patch | BFT consensus and wire message serialization format. |
| **Ledger Storage** | `LEDGER_VERSION` | `1` | Integer Monotonic | Immutable block header and Merkle tree format. |
| **Database Schema** | `DATABASE_SCHEMA_VERSION`| `1` | Integer Monotonic | Relational SQLite metadata schema version. |
| **Watermark Format** | `WATERMARK_FORMAT_VERSION`| `1` | Integer Monotonic | DWT-DCT sub-band embedding and Reed-Solomon framing. |
| **Canonical Event** | `EVENT_SCHEMA_VERSION` | `1` | Integer Monotonic | RFC 8785 canonical JSON schema for `DecryptionEvent`.|
| **Evidence Proof** | `PROOF_FORMAT_VERSION` | `1` | Integer Monotonic | Cryptographic attribution proof bundle specification. |

---

## 2. Version Guarantees & Compatibility Rules

1. **Evidence Proof Invariance (`PROOF_FORMAT_VERSION`):**
   - Forensic evidence generated under `PROOF_FORMAT_VERSION = 1` must remain verifiable across all future versions of the standalone verifier.
   - Proof verification algorithms are append-only. New proof formats increment the version, while legacy verification routines remain intact.

2. **Ledger Immutability (`LEDGER_VERSION`):**
   - Ledger blocks committed to disk are permanent. A ledger format change requires a hard-fork activation block or an upgrade migration tool that preserves the original genesis block and cryptographic chain.

3. **Event Schema Stability (`EVENT_SCHEMA_VERSION`):**
   - `DecryptionEvent` fields are canonicalized using RFC 8785 (JCS) before signing with ML-DSA-65.
   - Field names, ordering, and encoding cannot be altered without an `EVENT_SCHEMA_VERSION` bump.

4. **Wire Protocol Compatibility (`PROTOCOL_VERSION`):**
   - Minor version updates ($1.0 \to 1.1$) support backwards-compatible wire communications.
   - Major version updates ($1.x \to 2.0$) require all validator nodes in the BFT cluster to upgrade before processing new consensus rounds.

---

## 3. Cross-Version Compatibility Matrix

| Client Version | Node Version | Ledger Version | Package (.tcdist) | Evidence Proof | Compatibility Status |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **1.0.0** | **1.0.0** | `1` | v1 | v1 | **Full Compatibility (Current Release)** |
| 1.0.0 | 1.1.0 | `1` | v1 | v1 | Backward Compatible (Node accepts v1.0 clients) |
| 1.1.0 | 1.0.0 | `1` | v1 | v1 | Forward Compatible (Client downgrades handshake) |
| 1.0.0 | 2.0.0 | `2` | v1 | v1 | Incompatible (Major protocol upgrade required) |

---

## 4. Upgrade & Migration Protocols

When upgrading between releases:
1. **Pre-Upgrade Snapshot:** Automated snapshot created in `data/backups/pre_upgrade_<timestamp>.tcbackup`.
2. **Schema Migration:** `DatabaseMigrationManager` applies transactional SQL scripts within a rollback transaction.
3. **Ledger Header Verification:** The upgrade manager verifies the cryptographic continuity of all block hashes up to `tip_height`.
4. **Post-Upgrade Verification:** An automated integrity check ensures all historical events and certificates remain decodable and signature-valid.
