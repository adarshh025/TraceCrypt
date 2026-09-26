"""NIST FIPS 204: ML-DSA-65 Post-Quantum Digital Signature Provider.

Wraps the vetted offline ML-DSA-65 implementation with strict type checking,
input validation, key-purpose separation, and fail-closed deterministic verification.
"""

from __future__ import annotations

from typing import Tuple, Union

from dilithium_py.ml_dsa import ML_DSA_65

from tracecrypt.crypto.types import MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature
from tracecrypt.errors import CryptographicError, ValidationError


class MLDSAProvider:
    """Production provider for NIST FIPS 204 ML-DSA-65 operations."""

    ALGORITHM: str = "ML-DSA-65"

    @property
    def algorithm_name(self) -> str:
        return self.ALGORITHM

    def generate_keypair(self) -> Tuple[MLDSAPublicKey, MLDSAPrivateKey]:
        """Generate a new ML-DSA-65 public verification key and private signing key.

        Returns:
            Tuple of (MLDSAPublicKey, MLDSAPrivateKey)
        """
        try:
            pk_bytes, sk_bytes = ML_DSA_65.keygen()
            return MLDSAPublicKey(pk_bytes), MLDSAPrivateKey(sk_bytes)
        except Exception as e:
            raise CryptographicError(f"ML-DSA-65 key generation failed: {e}") from e

    def sign(self, private_key: Union[MLDSAPrivateKey, bytes], message: bytes) -> MLDSASignature:
        """Sign a message payload using the ML-DSA-65 private signing key.

        Args:
            private_key: Recipient's MLDSAPrivateKey or valid 4032-byte array.
            message: Raw bytes to sign (typically SHA3-256 canonical event digest).

        Returns:
            MLDSASignature (3309 bytes).
        """
        if isinstance(private_key, bytes):
            sk_obj = MLDSAPrivateKey(private_key)
        elif isinstance(private_key, MLDSAPrivateKey):
            sk_obj = private_key
        else:
            raise ValidationError(f"private_key must be MLDSAPrivateKey or bytes, got {type(private_key).__name__}")

        if not isinstance(message, (bytes, bytearray)):
            raise ValidationError(f"message must be bytes, got {type(message).__name__}")

        try:
            sig_bytes = ML_DSA_65.sign(sk_obj.raw_bytes, bytes(message))
            return MLDSASignature(sig_bytes)
        except (CryptographicError, ValidationError):
            raise
        except Exception as e:
            raise CryptographicError(f"ML-DSA-65 signing failed: {e}") from e

    def verify(
        self,
        public_key: Union[MLDSAPublicKey, bytes],
        message: bytes,
        signature: Union[MLDSASignature, bytes],
    ) -> bool:
        """Verify an ML-DSA-65 digital signature against a message and public key.

        Args:
            public_key: Certified MLDSAPublicKey or valid 1952-byte array.
            message: Raw bytes that were signed.
            signature: MLDSASignature or valid 3309-byte array.

        Returns:
            True if signature is mathematically valid; False otherwise.
        """
        try:
            if isinstance(public_key, bytes):
                pk_obj = MLDSAPublicKey(public_key)
            elif isinstance(public_key, MLDSAPublicKey):
                pk_obj = public_key
            else:
                return False

            if isinstance(signature, bytes):
                sig_obj = MLDSASignature(signature)
            elif isinstance(signature, MLDSASignature):
                sig_obj = signature
            else:
                return False

            if not isinstance(message, (bytes, bytearray)):
                return False

            return bool(ML_DSA_65.verify(pk_obj.raw_bytes, bytes(message), sig_obj.raw_bytes))
        except Exception:
            # Any malformed or corrupted key/signature bytes must fail closed
            return False


# Default singleton instance
_GLOBAL_MLDSA = MLDSAProvider()


def generate_mldsa_keypair() -> Tuple[MLDSAPublicKey, MLDSAPrivateKey]:
    """Convenience helper to generate an ML-DSA-65 key pair."""
    return _GLOBAL_MLDSA.generate_keypair()


def sign(private_key: Union[MLDSAPrivateKey, bytes], message: bytes) -> MLDSASignature:
    """Convenience helper to sign a message using ML-DSA-65."""
    return _GLOBAL_MLDSA.sign(private_key, message)


def verify(
    public_key: Union[MLDSAPublicKey, bytes],
    message: bytes,
    signature: Union[MLDSASignature, bytes],
) -> bool:
    """Convenience helper to verify an ML-DSA-65 signature."""
    return _GLOBAL_MLDSA.verify(public_key, message, signature)
