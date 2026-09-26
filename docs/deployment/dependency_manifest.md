# TraceCrypt Offline Dependency Manifest

This manifest documents all third-party software dependencies, their versions, offline availability in the local environment, cryptographic relevance, and licensing information.

| Package Name | Installed Version | Runtime / Dev | Offline Status | Purpose & Cryptographic Relevance | Known License |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | 3.11.9 | Runtime | **Available** | Host execution environment | Python Software Foundation |
| **cryptography** | 50.0.1 | Runtime | **Available** | OpenSSL-backed primitives (AES-256-GCM, Argon2id, SHA3-256) | Apache-2.0 / BSD |
| **mlkem** (FIPS 203) | 0.0.3 | Runtime | **Available & Verified** | NIST FIPS 203 ML-KEM-768 post-quantum key encapsulation | MIT / Apache-2.0 |
| **dilithium-py** (FIPS 204) | 1.4.0 | Runtime | **Available & Verified** | NIST FIPS 204 ML-DSA-65 post-quantum digital signatures | MIT |
| **mldsa** | 1.0.1 | Runtime | **Available** | Secondary reference implementation for FIPS 204 | Apache-2.0 |
| **numpy** | 2.4.6 | Runtime | **Available** | Matrix computations for DWT/DCT frequency transforms | BSD-3-Clause |
| **scipy** | 1.17.1 | Runtime | **Available** | Discrete Wavelet and Cosine Transforms for invisible watermarking | BSD-3-Clause |
| **opencv-python** | 5.0.0.93 | Runtime | **Available** | Document image deskewing, normalization, and perspective correction | Apache-2.0 |
| **pillow** | 12.2.0 | Runtime | **Available** | High-fidelity 300 DPI rasterization and image manipulation | HPND |
| **fastapi** | 0.115.0 | Runtime | **Available** | Air-gapped local REST API framework | MIT |
| **uvicorn** | 0.34.0 | Runtime | **Available** | Asynchronous local ASGI web server | BSD-3-Clause |
| **pydantic** | 2.10.6 | Runtime | **Available** | Strongly-typed schema validation and domain models | MIT |
| **aiosqlite** | 0.22.1 | Runtime | **Available** | Asynchronous local SQLite storage bindings | MIT |
| **sqlalchemy** | 2.0.22 | Runtime | **Available** | Relational abstraction and schema management | MIT |
| **pdfminer.six** | 20260107 | Runtime | **Available** | PDF document DOM structure parsing and extraction | MIT |
| **reportlab** | 5.0.1 | Runtime | **Available** | PDF vector report generation | BSD |
| **pytest** | 9.1.1 | Dev | **Available** | Automated test execution framework | MIT |
| **httpx** | 0.28.1 | Dev | **Available** | In-process FastAPI test client | BSD-3-Clause |
| **flake8** | 7.3.0 | Dev | **Available** | Python static style and code hygiene linter | MIT |
| **RFC 8785 (JCS)** | N/A | Runtime | **Implemented In-Tree** | Native pure-Python implementation in `tracecrypt.event.canonicalizer` | In-Tree |

### Phase 3 Verification Status
All post-quantum dependencies (`mlkem`, `dilithium-py`, `cryptography` Argon2id/AES-GCM) are fully validated in the air-gapped environment. Deterministic KAT seed tests (FIPS 203 Section 6 and FIPS 204 Section 5) pass offline without remote network access.
