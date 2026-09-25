# TraceCrypt Offline Dependency Manifest

This manifest documents all third-party software dependencies, their versions, offline availability in the local environment, cryptographic relevance, and licensing information.

| Package Name | Installed Version | Runtime / Dev | Offline Status | Purpose & Cryptographic Relevance | Known License |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | 3.11.9 | Runtime | **Available** | Host execution environment | Python Software Foundation |
| **cryptography** | 50.0.1 | Runtime | **Available** | OpenSSL-backed classical primitives (AES-256-GCM, HKDF, SHA-256, Ed25519) | Apache-2.0 / BSD |
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
| **mlkem** (FIPS 203) | 0.0.3 | Runtime | **Dependency Gap** (Phase 2) | NIST FIPS 203 ML-KEM-768 post-quantum key encapsulation | Apache-2.0 |
| **mldsa** (FIPS 204) | 1.0.1 | Runtime | **Dependency Gap** (Phase 2) | NIST FIPS 204 ML-DSA-65 post-quantum digital signatures | Apache-2.0 |
| **RFC 8785 (JCS)** | N/A | Runtime | **Implemented In-Tree** | Native pure-Python implementation in `tracecrypt.event.canonicalizer` | In-Tree |

### Dependency Gap Resolution Plan (Phase 2)
In accordance with air-gap rules, no remote packages were downloaded in Phase 1. For Phase 2 (PQC Identity & Cryptography):
* Pre-built offline wheel archives for `mlkem` and `mldsa` will be copied directly into the local `offline-wheels/` folder via air-gapped media transfer.
* Alternatively, standard Rust crates (`fips203`, `fips204`) can be compiled locally via the installed offline Rust compiler (`rustc 1.96.0` / `cargo 1.96.0`).
