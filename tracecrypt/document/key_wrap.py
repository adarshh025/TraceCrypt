"""Multi-recipient ML-KEM-768 Key Encapsulation and AES-256-GCM Key Wrapping.

Domain Separation:
Key Derivation Function (HKDF-SHA256):
- Salt: distribution_id UTF-8 bytes
- IKM: ML-KEM-768 32-byte shared secret
- Info: TraceCrypt/DistributionKeyWrap/v1:<distribution_id>:<recipient_id>:<key_version>
- Output: 256-bit Key-Wrapping Key (KWK)
"""

from __future__ import annotations

import base64
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tracecrypt.crypto.pqc_kem import decapsulate, encapsulate
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import MLKEMCiphertext, MLKEMPrivateKey, MLKEMPublicKey
from tracecrypt.document.types import RecipientEnvelope
from tracecrypt.errors import CryptographicError, ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.utils.identifiers import DistributionID, RecipientID


class KeyWrapEngine:
    """Encapsulates and wraps the Content-Encryption Key (CEK) per recipient."""

    WRAP_NONCE_SIZE_BYTES = 12
    WRAP_KEY_SIZE_BYTES = 32

    @classmethod
    def derive_wrapping_key(
        cls,
        shared_secret: bytes,
        distribution_id: DistributionID | str,
        recipient_id: RecipientID | str,
        key_version: int,
    ) -> tuple[bytearray, str]:
        """Derive a recipient-specific 256-bit Key-Wrapping Key (KWK) via HKDF-SHA256."""
        context_str = f"TraceCrypt/DistributionKeyWrap/v1:{distribution_id}:{recipient_id}:{key_version}"
        salt = str(distribution_id).encode("utf-8")
        info = context_str.encode("utf-8")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.WRAP_KEY_SIZE_BYTES,
            salt=salt,
            info=info,
        )
        kwk = hkdf.derive(shared_secret)
        return bytearray(kwk), context_str

    @classmethod
    def compute_wrap_aad(
        cls,
        distribution_id: DistributionID | str,
        recipient_id: RecipientID | str,
        key_id: str,
        key_version: int,
    ) -> bytes:
        """Produce deterministic AAD bytes for the wrapped key container."""
        wrap_aad_data: Dict[str, Any] = {
            "distribution_id": str(distribution_id),
            "recipient_id": str(recipient_id),
            "key_id": key_id,
            "key_version": key_version,
            "purpose": "CEK_WRAP",
        }
        return canonicalize(wrap_aad_data)

    @classmethod
    def wrap_cek_for_recipient(
        cls,
        cek: bytes | bytearray,
        recipient_pk: MLKEMPublicKey,
        distribution_id: DistributionID | str,
        recipient_id: RecipientID | str,
        key_id: str,
        certificate_serial: str,
        key_version: int = 1,
    ) -> RecipientEnvelope:
        """Encapsulate CEK for an individual recipient using ML-KEM-768 and AES-256-GCM.

        Returns:
            RecipientEnvelope: Populated envelope for the recipient.
        """
        if not isinstance(recipient_pk, MLKEMPublicKey):
            raise ValidationError(
                f"Expected MLKEMPublicKey for recipient encapsulation, got {type(recipient_pk).__name__}"
            )

        # 1. ML-KEM-768 Encapsulation
        shared_secret, kem_ciphertext = encapsulate(recipient_pk)

        # 2. Derive recipient-specific Key-Wrapping Key (KWK)
        kwk, context_str = cls.derive_wrapping_key(
            shared_secret=shared_secret,
            distribution_id=distribution_id,
            recipient_id=recipient_id,
            key_version=key_version,
        )

        # 3. Wrap CEK with AES-256-GCM using KWK
        wrap_nonce = SecureRandom.random_bytes(cls.WRAP_NONCE_SIZE_BYTES)
        wrap_aad = cls.compute_wrap_aad(distribution_id, recipient_id, key_id, key_version)

        try:
            aesgcm = AESGCM(bytes(kwk))
            wrapped_cek = aesgcm.encrypt(wrap_nonce, bytes(cek), wrap_aad)
        finally:
            # Zeroize intermediate wrapping key
            for i in range(len(kwk)):
                kwk[i] = 0

        return RecipientEnvelope(
            format_version="1.0.0",
            recipient_id=RecipientID(str(recipient_id)),
            key_id=key_id,
            certificate_serial=certificate_serial,
            kem_algorithm="ML-KEM-768",
            kem_parameter_set="ML-KEM-768",
            kem_ciphertext_b64=kem_ciphertext.to_b64(),
            derived_key_context=context_str,
            wrap_nonce_b64=base64.b64encode(wrap_nonce).decode("ascii"),
            wrapped_cek_b64=base64.b64encode(wrapped_cek).decode("ascii"),
            public_key_fingerprint=recipient_pk.fingerprint,
        )

    @classmethod
    def unwrap_cek_for_recipient(
        cls,
        envelope: RecipientEnvelope,
        recipient_sk: MLKEMPrivateKey,
        distribution_id: DistributionID | str,
        key_version: int = 1,
    ) -> bytearray:
        """Decapsulate and unwrap the CEK using recipient's private key.

        Returns:
            bytearray: Recovered 32-byte Content-Encryption Key (CEK).
        """
        if not isinstance(recipient_sk, MLKEMPrivateKey):
            raise ValidationError(
                f"Expected MLKEMPrivateKey for decapsulation, got {type(recipient_sk).__name__}"
            )

        # 1. Recover ML-KEM ciphertext
        raw_kem_ct = envelope.get_kem_ciphertext_bytes()
        kem_ct = MLKEMCiphertext(raw_kem_ct)

        # 2. Decapsulate shared secret
        shared_secret = decapsulate(recipient_sk, kem_ct)

        # 3. Derive KWK using matching context
        kwk, _ = cls.derive_wrapping_key(
            shared_secret=shared_secret,
            distribution_id=distribution_id,
            recipient_id=envelope.recipient_id,
            key_version=key_version,
        )

        # 4. Decrypt wrapped CEK
        wrap_nonce = envelope.get_wrap_nonce_bytes()
        wrapped_cek = envelope.get_wrapped_cek_bytes()
        wrap_aad = cls.compute_wrap_aad(
            distribution_id=distribution_id,
            recipient_id=envelope.recipient_id,
            key_id=envelope.key_id,
            key_version=key_version,
        )

        try:
            aesgcm = AESGCM(bytes(kwk))
            recovered_cek = aesgcm.decrypt(wrap_nonce, wrapped_cek, wrap_aad)
            return bytearray(recovered_cek)
        except Exception as e:
            raise CryptographicError(
                f"Failed to unwrap CEK for recipient '{envelope.recipient_id}': {e}"
            ) from e
        finally:
            # Zeroize intermediate wrapping key
            for i in range(len(kwk)):
                kwk[i] = 0
