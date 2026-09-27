"""Single-pass AES-256-GCM content encryption with RFC 8785 canonical AAD binding.

Security Invariants:
1. Every distribution package generates a fresh 256-bit random Content-Encryption Key (CEK).
2. The source document is encrypted exactly ONCE with AES-256-GCM.
3. Every encryption uses a fresh, non-repeating 96-bit (12-byte) random nonce.
4. Authenticated Associated Data (AAD) cryptographically binds all distribution header fields.
5. In-memory CEK buffers are zeroized upon completion.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import threading
from typing import ClassVar, Optional, Set

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import CryptographicError, ValidationError


class ContentEncryption:
    """Manages symmetric AES-256-GCM document encryption and authenticated decryption."""

    CEK_KEY_SIZE_BYTES = 32  # 256 bits
    NONCE_SIZE_BYTES = 12    # 96 bits
    TAG_SIZE_BYTES = 16      # 128 bits

    _used_nonces: ClassVar[Set[bytes]] = set()
    _nonce_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def reset_nonce_tracker(cls) -> None:
        """Reset the used nonces registry (for testing isolation)."""
        with cls._nonce_lock:
            cls._used_nonces.clear()

    @classmethod
    def generate_cek(cls) -> bytearray:
        """Generate a fresh cryptographically random 256-bit content-encryption key."""
        raw = SecureRandom.random_bytes(cls.CEK_KEY_SIZE_BYTES)
        return bytearray(raw)

    @classmethod
    def encrypt_document(
        cls,
        document_bytes: bytes,
        cek: bytes | bytearray,
        aad_bytes: bytes,
        override_nonce: Optional[bytes] = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt document payload once using AES-256-GCM.

        Args:
            document_bytes: Plaintext document bytes.
            cek: 32-byte AES key.
            aad_bytes: RFC 8785 canonical bytes for Authenticated Associated Data.
            override_nonce: Optional explicit nonce (for testing). Validated for uniqueness.

        Returns:
            tuple of (nonce_12b, auth_tag_16b, ciphertext_bytes)
        """
        if len(cek) != cls.CEK_KEY_SIZE_BYTES:
            raise ValidationError(
                f"Invalid CEK length: expected {cls.CEK_KEY_SIZE_BYTES} bytes, got {len(cek)}"
            )

        if override_nonce is not None:
            if len(override_nonce) != cls.NONCE_SIZE_BYTES:
                raise ValidationError(
                    f"Invalid AES-GCM nonce length: expected {cls.NONCE_SIZE_BYTES} bytes, got {len(override_nonce)}"
                )
            nonce = bytes(override_nonce)
        else:
            nonce = SecureRandom.random_bytes(cls.NONCE_SIZE_BYTES)

        with cls._nonce_lock:
            if nonce in cls._used_nonces:
                raise CryptographicError("CRITICAL SECURITY VIOLATION: AES-GCM nonce reuse detected!")
            cls._used_nonces.add(nonce)

        try:
            aesgcm = AESGCM(bytes(cek))
            # AESGCM.encrypt returns ciphertext + 16-byte tag appended
            encrypted_payload = aesgcm.encrypt(nonce, document_bytes, aad_bytes)
            ciphertext = encrypted_payload[:-cls.TAG_SIZE_BYTES]
            auth_tag = encrypted_payload[-cls.TAG_SIZE_BYTES:]
            return nonce, auth_tag, ciphertext
        except CryptographicError:
            raise
        except Exception as e:
            raise CryptographicError(f"AES-256-GCM document encryption failed: {e}") from e

    @classmethod
    def decrypt_document(
        cls,
        ciphertext: bytes,
        nonce: bytes,
        auth_tag: bytes,
        cek: bytes | bytearray,
        aad_bytes: bytes,
    ) -> bytearray:
        """Decrypt and authenticate document payload using AES-256-GCM.

        Args:
            ciphertext: Encrypted document bytes.
            nonce: 12-byte AES-GCM nonce.
            auth_tag: 16-byte AES-GCM authentication tag.
            cek: 32-byte AES key.
            aad_bytes: RFC 8785 canonical bytes for Authenticated Associated Data.

        Returns:
            bytearray: Mutable plaintext document buffer.
        """
        if len(cek) != cls.CEK_KEY_SIZE_BYTES:
            raise ValidationError(
                f"Invalid CEK length: expected {cls.CEK_KEY_SIZE_BYTES} bytes, got {len(cek)}"
            )
        if len(nonce) != cls.NONCE_SIZE_BYTES:
            raise ValidationError(
                f"Invalid AES-GCM nonce length: expected {cls.NONCE_SIZE_BYTES} bytes, got {len(nonce)}"
            )
        if len(auth_tag) != cls.TAG_SIZE_BYTES:
            raise ValidationError(
                f"Invalid AES-GCM tag length: expected {cls.TAG_SIZE_BYTES} bytes, got {len(auth_tag)}"
            )

        payload_to_decrypt = ciphertext + auth_tag
        try:
            aesgcm = AESGCM(bytes(cek))
            decrypted = aesgcm.decrypt(nonce, payload_to_decrypt, aad_bytes)
            return bytearray(decrypted)
        except Exception as e:
            raise CryptographicError(
                f"AES-256-GCM document decryption/authentication failed: {e}"
            ) from e
