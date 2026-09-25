# TraceCrypt Architectural Overview

## Modular Boundaries
TraceCrypt is partitioned into isolated subsystems communicating through typed domain schemas:

1. **`tracecrypt.crypto`:** Post-quantum key encapsulation (ML-KEM-768), post-quantum digital signatures (ML-DSA-65), AES-256-GCM symmetric encryption, SHA-3 family hashing, CSPRNG randomness, and memory zeroization.
2. **`tracecrypt.identity`:** Offline Certificate Authority (Root CA & Registration Authority), X.509/CBOR identity certificates, and Argon2id encrypted keystores.
3. **`tracecrypt.document`:** PDF DOM structure parsing, 300 DPI rasterization, multi-recipient ML-KEM packaging, and canonical pre-watermark document hashing.
4. **`tracecrypt.watermark`:** 2D DWT (Haar) and block DCT frequency-domain transformations, Reed-Solomon RS(32,16) forward error correction, and blind correlation extraction.
5. **`tracecrypt.event`:** RFC 8785 JSON Canonicalization Scheme (JCS) serializer, canonical DecryptionEvent schema, and deterministic digest generation.
6. **`tracecrypt.ledger`:** Permissioned multi-node Byzantine Fault Tolerant (BFT) distributed ledger, anti-replay mempool, block DAG storage, and Merkle tree state proofs.
7. **`tracecrypt.forensics`:** Leaked document geometric normalization, blind watermark extraction, signature verification, and 9-state deterministic verdict engine.
8. **`tracecrypt.storage`:** Local hardened SQLite storage manager with WAL mode for client metadata caching and offline indexing.
9. **`tracecrypt.security`:** Socket-level air-gap enforcement guard and structured security audit logger with automated secret redaction.
10. **`tracecrypt.api` & `tracecrypt.ui`:** Air-gapped local REST API and self-contained web interface.
