# Watermark Payload & Error Correction Specification

## 1. 256-Bit Logical Payload Layout

The unencoded forensic watermark payload is exactly **256 bits (32 bytes)**.
It contains strictly cryptographic identifiers and zero plaintext Personally Identifiable Information (PII).

### 1.1 Binary Layout Table

| Field Name | Offset (Bytes) | Width (Bytes) | Width (Bits) | Type | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `version` | 0 | 1 | 8 | `uint8` | Watermark format version (`0x01`). |
| `watermark_id` | 1 | 16 | 128 | `bytes16` | 128-bit CSPRNG identifier (`wm-...`). |
| `session_tag` | 17 | 8 | 64 | `bytes8` | Truncated 64-bit cryptographic tag of `SessionID`. |
| `document_binding` | 25 | 5 | 40 | `bytes5` | SHA3-256 cryptographic binding token. |
| `checksum` | 30 | 2 | 16 | `uint16_be` | CRC-16-CCITT integrity checksum over bytes 0..29. |
| **Total** | | **32** | **256** | | **Exact 256-bit logical payload.** |

### 1.2 Serialization Rules
1. **Byte Order**: Big-endian (network byte order) for all numeric fields (`version`, `checksum`).
2. **Padding**: Prohibited; all 32 bytes are active data.
3. **Immutability**: Once constructed, payload fields are frozen and validated via Pydantic V2 schemas.

---

## 2. Cryptographic Identifiers & Bindings

### 2.1 WatermarkID (128 bits)
- Generated via cryptographically secure OS randomness (`os.urandom(16)` via `SecureRandom`).
- Formatted as `wm-<32 hex characters>`.
- Generated freshly at decryption time. Never derived from timestamps, usernames, or document metadata.

### 2.2 SessionID (128 bits)
- Identifies the ephemeral decryption runtime session (`ses-...`).
- The payload embeds the first 8 bytes (`session_tag`) to tie the watermark to the local decryption event.

### 2.3 Document Binding Token (40 bits)
The document binding cryptographically locks the watermark to the source document without storing the full 32-byte document hash inside the payload:

$$\text{Binding} = \text{SHA3-256}\Big(\text{"TraceCrypt-Watermark-Binding:"} \parallel \text{DocHash} \parallel \text{SessionID} \parallel \text{WatermarkID}\Big)\big[:5\big]$$

- If an attacker transplants a watermark into a different document, the verification check fails because the new document hash yields an invalid 40-bit binding token.

### 2.4 Integrity Checksum (CRC-16-CCITT)
- Polynomial: $x^{16} + x^{12} + x^5 + 1$ (`0x1021`).
- Initial value: `0xFFFF`.
- Computed over the first 30 bytes of the payload.
- Guarantees immediate detection of bit flips prior to cryptographic processing.

---

## 3. Reed-Solomon RS(32,16) Forward Error Correction

### 3.1 Galois Field $\text{GF}(2^8)$
- **Primitive Polynomial**: $p(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D` / decimal `285`).
- **Primitive Element**: $\alpha = 2$ (`0x02`), generating all 255 non-zero field elements.
- **Arithmetic**: Logarithmic and exponential precomputed lookup tables ($512$ bytes) enable constant-time multiplication and division.

### 3.2 RS(32,16) Codec Parameters
- **Codeword Length ($n$)**: 32 symbols (bytes).
- **Message Length ($k$)**: 16 symbols (bytes).
- **Parity Length ($2t$)**: 16 symbols (bytes).
- **Error Correction Capability ($t$)**: 8 symbol errors per 32-byte block.
- **Code Rate**: $R = k/n = 16/32 = 0.5$ (50% redundancy).
- **Generator Polynomial**:
  $$g(x) = \prod_{i=0}^{15} (x - \alpha^i)$$

### 3.3 Two-Block Interleaving
To prevent localized physical cropping, folding, or burst noise from wiping out an entire block, the 32-byte payload is encoded using **two-way symbol interleaving**:

```
Payload (32 bytes):  [D0,0 ... D0,15]  and  [D1,0 ... D1,15]
                            │                     │
                    RS(32,16) Block 0     RS(32,16) Block 1
                     (32 coded bytes)      (32 coded bytes)
                            │                     │
                            └──────────┬──────────┘
                                       ▼
                  Symbol Interleaver (64 bytes / 512 bits)
           [B0_0, B1_0, B0_1, B1_1, B0_2, B1_2, ..., B0_31, B1_31]
```

#### Properties of Interleaving:
1. **Total Codeword Size**: 64 bytes (512 bits).
2. **Burst Error Resistance**: A continuous burst of up to 16 consecutive corrupted bytes affects at most 8 symbols in Block 0 and 8 symbols in Block 1. Both blocks recover with 100% fidelity.
3. **Total Correction Capacity**: Corrects up to 16 symbol errors across the 64-byte stream.
