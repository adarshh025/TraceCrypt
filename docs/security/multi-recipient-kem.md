# Post-Quantum Multi-Recipient Key Encapsulation (ML-KEM-768)

## 1. Cryptographic Primitive: NIST FIPS 203 ML-KEM-768

TraceCrypt implements the Module-Lattice-Based Key-Encapsulation Mechanism (**ML-KEM-768**), standardized in **NIST FIPS 203**, operating at NIST Security Category 3 (equivalent to AES-192 against classical cryptanalysis and 128 bits against quantum cryptanalysis).

### Key Sizes
* **Public Key ($pk$):** 1,184 bytes
* **Private Key ($sk$):** 2,400 bytes
* **Ciphertext ($c$):** 1,088 bytes
* **Shared Secret ($ss$):** 32 bytes (256 bits)

---

## 2. Multi-Recipient Key Wrapping Architecture

To deliver the Content Encryption Key (CEK) to multiple recipients without duplicating the encrypted document:

```
                          Content Encryption Key (CEK)
                         [256 bits fresh random bytes]
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
     [Recipient A]              [Recipient B]              [Recipient C]
  ML-KEM-768 Encapsulate     ML-KEM-768 Encapsulate     ML-KEM-768 Encapsulate
       (with pk_A)                (with pk_B)                (with pk_C)
            │                          │                          │
            ├─► Ciphertext c_A         ├─► Ciphertext c_B         ├─► Ciphertext c_C
            └─► Shared Secret ss_A     └─► Shared Secret ss_B     └─► Shared Secret ss_C
            │                          │                          │
       HKDF-SHA256                HKDF-SHA256                HKDF-SHA256
       Context: A                 Context: B                 Context: C
            │                          │                          │
       Wrap Key KWK_A             Wrap Key KWK_B             Wrap Key KWK_C
            │                          │                          │
     AES-256-GCM Wrap           AES-256-GCM Wrap           AES-256-GCM Wrap
            │                          │                          │
            ▼                          ▼                          ▼
   Envelope Recipient A       Envelope Recipient B       Envelope Recipient C
```

---

## 3. Key Derivation & Domain Separation (HKDF-SHA256)

TraceCrypt strictly forbids using raw ML-KEM shared secrets directly as symmetric keys. Instead, the shared secret ($ss$) is fed as Input Keying Material ($IKM$) into **HKDF-SHA256** (RFC 5869):

### Derivation Construction
```python
info = f"TraceCrypt/DistributionKeyWrap/v1:{distribution_id}:{recipient_id}:{key_version}".encode("ascii")

kwk = hkdf_derive(
    ikm=shared_secret,  # 32 bytes
    salt=None,          # Defaults to 32 zero bytes per RFC 5869
    info=info,          # Strict context binding
    length=32           # 256 bits Key-Wrapping Key
)
```

### Purpose of Domain Separation
* **Distribution Isolation:** A shared secret derived in one distribution package cannot be repurposed for another.
* **Recipient Isolation:** Encapsulation intended for Recipient A cannot be translated to Recipient B.
* **Key Version Binding:** Re-wrapping with an older or rotated key version produces an invalid KWK.

---

## 4. CEK Wrapping with AES-256-GCM

Once the Key-Wrapping Key ($KWK$) is established:
1. Generate a fresh 96-bit random nonce ($nonce_{wrap}$).
2. Construct wrapping AAD:
   ```json
   {
       "recipient_id": "rcp-...",
       "distribution_id": "dst-...",
       "key_id": "key-..."
   }
   ```
3. Encrypt the 32-byte CEK using AES-256-GCM under $KWK$, yielding:
   * 32-byte wrapped CEK ciphertext
   * 16-byte authentication tag
4. Store in `RecipientEnvelope`:
   * `kem_ciphertext_b64` (1,088 bytes)
   * `wrapped_cek_nonce_b64` (12 bytes)
   * `wrapped_cek_tag_b64` (16 bytes)
   * `wrapped_cek_b64` (32 bytes)
   * `kdf_info`

---

## 5. Recipient Decapsulation & Recovery Flow

When authorized Recipient $R$ attempts decryption:
1. Verify $R$'s certificate is valid and issued by the offline Root CA.
2. Locate $R$'s envelope matching $R$'s `recipient_id`.
3. Invoke ML-KEM-768 decapsulate with $R$'s private key $sk_R$ and `kem_ciphertext`:
   $$ss = \text{Decapsulate}(sk_R, c)$$
4. Re-derive $KWK$ using identical HKDF-SHA256 parameters and `kdf_info`.
5. Authenticate and decrypt `wrapped_cek` under $KWK$ using AES-256-GCM:
   $$CEK = \text{AES-GCM-Decrypt}(KWK, nonce_{wrap}, wrapped\_cek, tag_{wrap}, AAD_{wrap})$$
6. If any step fails (wrong private key, modified ciphertext, tampered tag), fail closed immediately.
