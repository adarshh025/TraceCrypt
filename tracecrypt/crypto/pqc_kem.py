"""NIST FIPS 203: ML-KEM-768 Post-Quantum Key Encapsulation Provider.

Wraps the vetted offline ML-KEM-768 implementation with strict type checking,
input validation, key-purpose separation, and fail-closed error handling.
"""

from __future__ import annotations

from typing import Tuple, Union

from mlkem.ml_kem import ML_KEM, ML_KEM_768

from tracecrypt.crypto.types import MLKEMCiphertext, MLKEMPrivateKey, MLKEMPublicKey
from tracecrypt.errors import CryptographicError, ValidationError


class MLKEMProvider:
    """Production provider for NIST FIPS 203 ML-KEM-768 operations."""

    ALGORITHM: str = "ML-KEM-768"

    def __init__(self) -> None:
        self._kem = ML_KEM(ML_KEM_768)

    @property
    def algorithm_name(self) -> str:
        return self.ALGORITHM

    def generate_keypair(self) -> Tuple[MLKEMPublicKey, MLKEMPrivateKey]:
        """Generate a new ML-KEM-768 public and private key pair.

        Returns:
            Tuple of (MLKEMPublicKey, MLKEMPrivateKey)
        """
        try:
            ek_bytes, dk_bytes = self._kem.key_gen()
            return MLKEMPublicKey(ek_bytes), MLKEMPrivateKey(dk_bytes)
        except Exception as e:
            raise CryptographicError(f"ML-KEM-768 key generation failed: {e}") from e

    def encapsulate(self, public_key: Union[MLKEMPublicKey, bytes]) -> Tuple[bytes, MLKEMCiphertext]:
        """Encapsulate a random 256-bit shared secret to the recipient's public key.

        Args:
            public_key: Certified MLKEMPublicKey or valid 1184-byte array.

        Returns:
            Tuple of (shared_secret_32_bytes, MLKEMCiphertext)
        """
        if isinstance(public_key, bytes):
            pk_obj = MLKEMPublicKey(public_key)
        elif isinstance(public_key, MLKEMPublicKey):
            pk_obj = public_key
        else:
            raise ValidationError(f"public_key must be MLKEMPublicKey or bytes, got {type(public_key).__name__}")

        try:
            shared_secret, ct_bytes = self._kem.encaps(pk_obj.raw_bytes)
            if len(shared_secret) != 32:
                raise CryptographicError(f"Invalid ML-KEM shared secret length: {len(shared_secret)} != 32")
            return shared_secret, MLKEMCiphertext(ct_bytes)
        except (CryptographicError, ValidationError):
            raise
        except Exception as e:
            raise CryptographicError(f"ML-KEM-768 encapsulation failed: {e}") from e

    def decapsulate(
        self,
        private_key: Union[MLKEMPrivateKey, bytes],
        ciphertext: Union[MLKEMCiphertext, bytes],
    ) -> bytes:
        """Decapsulate an ML-KEM-768 ciphertext to recover the 256-bit shared secret.

        Args:
            private_key: Recipient's MLKEMPrivateKey or valid 2400-byte array.
            ciphertext: MLKEMCiphertext or valid 1088-byte array.

        Returns:
            32-byte shared secret.
        """
        if isinstance(private_key, bytes):
            sk_obj = MLKEMPrivateKey(private_key)
        elif isinstance(private_key, MLKEMPrivateKey):
            sk_obj = private_key
        else:
            raise ValidationError(f"private_key must be MLKEMPrivateKey or bytes, got {type(private_key).__name__}")

        if isinstance(ciphertext, bytes):
            ct_obj = MLKEMCiphertext(ciphertext)
        elif isinstance(ciphertext, MLKEMCiphertext):
            ct_obj = ciphertext
        else:
            raise ValidationError(f"ciphertext must be MLKEMCiphertext or bytes, got {type(ciphertext).__name__}")

        try:
            shared_secret = self._kem.decaps(sk_obj.raw_bytes, ct_obj.raw_bytes)
            if len(shared_secret) != 32:
                raise CryptographicError(f"Invalid decapsulated shared secret length: {len(shared_secret)} != 32")
            return shared_secret
        except (CryptographicError, ValidationError):
            raise
        except Exception as e:
            raise CryptographicError(f"ML-KEM-768 decapsulation failed: {e}") from e


# Default singleton instance
_GLOBAL_MLKEM = MLKEMProvider()


def generate_mlkem_keypair() -> Tuple[MLKEMPublicKey, MLKEMPrivateKey]:
    """Convenience helper to generate an ML-KEM-768 key pair."""
    return _GLOBAL_MLKEM.generate_keypair()


def encapsulate(public_key: Union[MLKEMPublicKey, bytes]) -> Tuple[bytes, MLKEMCiphertext]:
    """Convenience helper to encapsulate a shared secret."""
    return _GLOBAL_MLKEM.encapsulate(public_key)


def decapsulate(
    private_key: Union[MLKEMPrivateKey, bytes],
    ciphertext: Union[MLKEMCiphertext, bytes],
) -> bytes:
    """Convenience helper to decapsulate a shared secret."""
    return _GLOBAL_MLKEM.decapsulate(private_key, ciphertext)
