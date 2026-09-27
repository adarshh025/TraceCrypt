# TraceCrypt System Architecture Specification

**Product:** TraceCrypt  
**Version:** 1.0.0  
**Environment:** Air-Gapped / Isolated Secure LAN  
**Cryptographic Suite:** NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65), AES-256-GCM, SHA3-256  

---

## 1. High-Level System Architecture

TraceCrypt is composed of five distinct operational environments that communicate strictly via file-based exchange (`.tcdist`, `.tcproof`, `.tcbackup`) or private, permissioned, air-gapped inter-validator TCP connections.

```
                      ┌─────────────────────────────────┐
                      │    OFFLINE ROOT CA AUTHORITY    │
                      │  - Master ML-DSA-65 Signing Key │
                      │  - Identity & Role Certificates │
                      │  - Offline Revocation Registry  │
                      └────────────────┬────────────────┘
                                       │ Certified Keys & CRLs
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────────┐
│SENDER WORKSTATION│         │RECIPIENT GATEWAY │         │ 4-NODE BFT CONSENSUS │
│- Document Source │         │- ML-KEM Decaps   │         │- Node 1 (127.0.0.1:9101)
│- SHA3-256 Hash   │         │- AES Decryption  │         │- Node 2 (127.0.0.1:9102)
│- CEK Generation  │         │- DWT-DCT Embed   │         │- Node 3 (127.0.0.1:9103)
│- ML-KEM-768 Wrap ├────────►│- Canonical Event ├────────►│- Node 4 (127.0.0.1:9104)
│- .tcdist Package │ .tcdist │- ML-DSA Signature│ Signed  │- Tendermint Consensus│
└──────────────────┘ Package │- Ledger Commit   │ Event   │- Binary Merkle Tree  │
                             │- Zeroization Gate│         │- Replicated SQLite   │
                             └────────┬─────────┘         └──────────┬───────────┘
                                      │                              │
                                      ▼ Exfiltration                 ▼ Proofs & State
                             ┌──────────────────┐         ┌──────────────────────┐
                             │ LEAKED ARTIFACT  │         │ INVESTIGATOR STATION │
                             │- PDF / Scan / Img│────────►│- Blind DWT-DCT Extr  │
                             │- Noise / Cropping│ Evidence│- Merkle Inclusion    │
                             └──────────────────┘         │- ML-DSA Verification │
                                                          │- 9-State Adjudication│
                                                          │- .tcproof & PDF Rep  │
                                                          └──────────────────────┘
```

---

## 2. Trust Boundaries & Security Enclaves

```mermaid
graph TD
    subgraph TB_CA ["Trust Boundary 1: Root CA Enclave (Air-Gapped Cold Storage)"]
        CA_Key["Master ML-DSA-65 Private Key"]
        CA_Engine["Offline CA Certificate Engine"]
    end

    subgraph TB_Sender ["Trust Boundary 2: Sender Enclave (Authoring Environment)"]
        Plain_Doc["Pristine Source Document"]
        CEK_Gen["Ephemeral 256-bit CEK"]
        KEM_Wrap["ML-KEM-768 Multi-Recipient Encapsulation"]
        Dist_Pkg[".tcdist Packaging Engine"]
    end

    subgraph TB_Recipient ["Trust Boundary 3: Recipient Enclave (Protected Decryption Gate)"]
        Decaps["ML-KEM-768 Decapsulation"]
        AES_Dec["AES-256-GCM In-Memory Decryption"]
        Secure_Buf["SecureDocumentBuffer (Zeroized on Exit)"]
        WM_Engine["DWT-DCT Forensic Watermark Embedder"]
        Event_Signer["ML-DSA-65 Decryption Event Signer"]
        Release_Gate["Atomic Document Release Gate"]
    end

    subgraph TB_Ledger ["Trust Boundary 4: BFT Consensus Enclave (Replicated DLT)"]
        Val_1["Validator Node 1"]
        Val_2["Validator Node 2"]
        Val_3["Validator Node 3"]
        Val_4["Validator Node 4"]
    end

    subgraph TB_Investigator ["Trust Boundary 5: Forensic Investigation Enclave"]
        Evidence_Ingest["Copy-on-Ingest Evidence Storage"]
        Blind_Extract["Blind DWT-DCT Extractor"]
        Proof_Verifier["Standalone Proof Verifier"]
        Adjudicator["Deterministic 9-Verdict Engine"]
    end

    TB_CA -->|Certified Public Keys| TB_Sender
    TB_CA -->|Certified Public Keys| TB_Recipient
    TB_CA -->|Consensus Certificates| TB_Ledger
    TB_Sender -->|.tcdist Envelopes| TB_Recipient
    TB_Recipient -->|Signed Canonical Decryption Events| TB_Ledger
    TB_Ledger -->|Merkle Inclusion Proofs| TB_Investigator
    TB_CA -->|Root Public Key Verification| TB_Investigator
```

---

## 3. Cryptographic Data Flow

### 3.1 Document Packaging & Distribution Flow
```mermaid
sequenceDiagram
    autonumber
    participant S as Sender Workstation
    participant R as Recipient Workstation
    participant L as BFT Ledger Cluster

    Note over S: 1. Ingest pristine PDF
    S->>S: Compute source document hash: SHA3-256(Document)
    S->>S: Generate ephemeral Content-Encryption Key (CEK): AES-256
    S->>S: Encrypt document payload: AES-256-GCM(CEK, Nonce, Doc)
    loop Each Authorized Recipient
        S->>S: ML-KEM-768 Encapsulate(Recipient_PK) -> (Ciphertext, SharedSecret)
        S->>S: HKDF-SHA256(SharedSecret) -> Key-Wrap Key (KWK)
        S->>S: AES-KeyWrap(KWK, CEK) -> Wrapped CEK Envelope
    end
    S->>S: Assemble TCDIST01 container with RFC 8785 canonical metadata
    S->>R: Transmit .tcdist package via physical optical/USB media

    Note over R: 2. Decapsulation & Attribution Gate
    R->>R: 17-point structural & cryptographic package validation
    R->>R: ML-KEM-768 Decapsulate(Recipient_SK, Ciphertext) -> SharedSecret
    R->>R: Unwrap CEK and decrypt AES-GCM document into SecureDocumentBuffer
    R->>R: Generate 128-bit SessionID & WatermarkID
    R->>R: DWT-DCT embed watermark with Reed-Solomon RS(32,16) ECC into all pages
    R->>R: Construct canonical RFC 8785 DecryptionEvent
    R->>R: Sign event with Recipient ML-DSA-65 Private Key
    R->>L: Submit SignedDecryptionEvent transaction
    L->>L: BFT Consensus commit (n=4, f=1, 3/4 Quorum)
    L-->>R: Transaction Receipt & Finalized Height confirmation
    R->>R: Authorize DocumentReleaseGate
    R->>R: Render watermarked PDF & zeroize ephemeral CEK + plaintext buffers
```

---

## 4. Key Management & Lifecycle Flow

```mermaid
graph LR
    subgraph CA ["Offline Root CA"]
        Root_SK["Root ML-DSA-65 SK"]
        Root_PK["Root ML-DSA-65 PK"]
    end

    subgraph Keys_Recip ["Recipient Workstation"]
        Recip_KEM_SK["Recipient ML-KEM-768 SK"]
        Recip_KEM_PK["Recipient ML-KEM-768 PK"]
        Recip_DSA_SK["Recipient ML-DSA-65 SK"]
        Recip_DSA_PK["Recipient ML-DSA-65 PK"]
        Keystore["Argon2id + AES-256-GCM Keystore"]
    end

    subgraph Keys_Val ["Validator Node"]
        Val_DSA_SK["Consensus ML-DSA-65 SK"]
        Val_DSA_PK["Consensus ML-DSA-65 PK"]
    end

    Root_SK -->|Sign KEM Cert| Cert_KEM["KEM Certificate (Purpose: ENCAPSULATION)"]
    Root_SK -->|Sign DSA Cert| Cert_DSA["DSA Certificate (Purpose: DIGITAL_SIGNATURE)"]
    Root_SK -->|Sign Val Cert| Cert_Val["Validator Certificate (Purpose: CONSENSUS)"]

    Recip_KEM_SK -.->|Protected by| Keystore
    Recip_DSA_SK -.->|Protected by| Keystore
```

---

## 5. Ledger Consensus & Merkle Commitment Flow

```mermaid
graph TD
    subgraph Consensus_Round ["Tendermint BFT Consensus Engine"]
        P["PROPOSE (Round-Robin Proposer)"] --> PV["PREVOTE (2f+1 Quorum)"]
        PV --> PC["PRECOMMIT (2f+1 Quorum)"]
        PC --> C["COMMIT & FINALIZE"]
    end

    subgraph Block_Structure ["Finalized Block (Height H)"]
        BH["Block Header"]
        BH --> PR["Previous Block Hash: SHA3-256"]
        BH --> TR["Transaction Root (Merkle Tree Root)"]
        BH --> SR["Canonical State Root: SHA3-256"]
        BH --> CC["Commit Certificate (3 ML-DSA Signatures)"]
    end

    subgraph Merkle_Tree ["Binary Merkle Inclusion Tree"]
        TR --> H12["Node Hash 1-2"]
        TR --> H34["Node Hash 3-4"]
        H12 --> Leaf1["Leaf 1: SHA3(Tx1)"]
        H12 --> Leaf2["Leaf 2: SHA3(Tx2)"]
        H34 --> Leaf3["Leaf 3: SHA3(Tx3)"]
        H34 --> Leaf4["Leaf 4: SHA3(Tx4)"]
    end

    C --> BH
```

---

## 6. Forensic Investigation & Adjudication Pipeline

When a leaked document artifact is imported, the investigator executes the deterministic 9-verdict adjudication pipeline:

```mermaid
flowchart TD
    Start["Leaked Artifact Ingested (PDF/Scan/Photo)"] --> H1["Compute Evidence SHA3-256 & Record Custody"]
    H1 --> N1["Forensic Normalization (Deskew, Channel Align)"]
    N1 --> W1["Blind 2D Haar DWT + 8x8 Block DCT Extraction"]
    W1 --> E1{"Watermark Signal Detected?"}
    E1 -- No --> V_NOT_FOUND["Verdict: NOT_FOUND"]
    E1 -- Yes --> E2["Reed-Solomon RS(32,16) Decoding & CRC Check"]
    E2 -- Corrupted --> V_CORRUPT["Verdict: CORRUPTED_WATERMARK"]
    E2 -- Conflict across pages --> V_AMBIG["Verdict: AMBIGUOUS (Splicing Detected)"]
    E2 -- Valid Payload --> L1["Query Ledger by WatermarkID"]
    L1 -- Not Found --> V_INVALID_WM["Verdict: INVALID_WATERMARK"]
    L1 -- Found Event --> M1["Verify Merkle Inclusion Proof against Block Header"]
    M1 -- Invalid Proof --> V_LEDGER_INV["Verdict: LEDGER_INVALID"]
    M1 -- Valid Merkle Proof --> S1["Verify NIST FIPS 204 ML-DSA-65 Signature & Cert"]
    S1 -- Invalid Signature --> V_SIG_INV["Verdict: SIGNATURE_INVALID"]
    S1 -- Valid Signature --> D1{"Document Hash Matches Leaked Binding?"}
    D1 -- Mismatch --> V_DOC_MISMATCH["Verdict: DOCUMENT_MISMATCH"]
    D1 -- Match --> V_VERIFIED["Verdict: VERIFIED (Positive Attribution)"]

    V_VERIFIED --> Export["Export .tcproof Bundle & Signed PDF Report"]
    Export --> Standalone["Independent Verification via StandaloneProofVerifier"]
```

---

## 7. Deterministic Nine-Verdict Reference Matrix

| Verdict | Forensic Meaning | Non-Repudiation Status | Admissibility |
|:---|:---|:---|:---|
| `VERIFIED` | Full cryptographic match: watermark, ledger, signature, and document binding clean. | Non-repudiated attribution | Fully Admissible |
| `DOCUMENT_MISMATCH` | Watermark valid and signed, but document hash differs from ledger event. | Document tampering detected | Inadmissible for source |
| `SIGNATURE_INVALID` | Event record modified or forged; ML-DSA signature failed verification. | Attribution forgery detected | Proof of tampering |
| `LEDGER_INVALID` | Merkle proof fails or block header hash diverges from consensus state. | Consensus state compromised | Inadmissible |
| `INVALID_WATERMARK` | Watermark decoded cleanly but was never committed to the ledger. | Counterfeit / unauthorized mark | Proof of forgery |
| `CORRUPTED_WATERMARK` | Signal detected but Reed-Solomon unrecoverable beyond error threshold. | Insufficient signal fidelity | Inconclusive |
| `AMBIGUOUS` | Conflicting valid watermarks detected across different document pages. | Document page splicing detected | Proof of splice |
| `UNVERIFIABLE` | Missing public keys, revoked Root CA, or incompatible protocol version. | Verification preconditions unmet | Inconclusive |
| `NOT_FOUND` | Zero watermark correlation detected across all document pages. | No TraceCrypt watermark present | Non-attributed |

---

## 8. Deployment Topology (Reference 4-Node Cluster)

| Node | Role | IP / Host | Port | Database Path | Key Location |
|:---|:---|:---|:---|:---|:---|
| `node-1` | Consensus Validator | `127.0.0.1` | `9101` | `cluster/node-1/ledger.db` | `cluster/node-1/validator_key.json` |
| `node-2` | Consensus Validator | `127.0.0.1` | `9102` | `cluster/node-2/ledger.db` | `cluster/node-2/validator_key.json` |
| `node-3` | Consensus Validator | `127.0.0.1` | `9103` | `cluster/node-3/ledger.db` | `cluster/node-3/validator_key.json` |
| `node-4` | Consensus Validator | `127.0.0.1` | `9104` | `cluster/node-4/ledger.db` | `cluster/node-4/validator_key.json` |
