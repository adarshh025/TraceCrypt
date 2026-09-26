"""Cryptographically secure randomness abstraction backed strictly by the OS CSPRNG.

Enforces zero reliance on predictable pseudorandom number generators (random.random,
random.randint), timestamps, or MAC-based UUID1.
"""

from __future__ import annotations

import os
from typing import Final, Type, TypeVar

from tracecrypt.errors import CryptographicError, ValidationError
from tracecrypt.utils.identifiers import BaseID

T_ID = TypeVar("T_ID", bound=BaseID)


class SecureRandom:
    """Operating system CSPRNG abstraction (backed by os.urandom / secrets)."""

    MIN_ENTROPY_BYTES: Final[int] = 16  # 128 bits minimum

    @classmethod
    def random_bytes(cls, length: int) -> bytes:
        """Generate cryptographically secure random bytes of specified length.

        Args:
            length: Number of bytes to generate. Must be >= 1.
        """
        if not isinstance(length, int) or length < 1:
            raise ValidationError(f"Random byte length must be positive integer >= 1, got {length!r}")
        try:
            return os.urandom(length)
        except Exception as e:
            raise CryptographicError(f"Operating system CSPRNG failure: {e}") from e

    @classmethod
    def random_hex(cls, byte_length: int = 16) -> str:
        """Generate cryptographically secure random lowercase hex string.

        Args:
            byte_length: Number of entropy bytes (16 bytes = 32 hex characters).
        """
        return cls.random_bytes(byte_length).hex()

    @classmethod
    def random_nonce_128(cls) -> str:
        """Generate a 128-bit (16-byte) random hex nonce."""
        return cls.random_hex(16)

    @classmethod
    def random_nonce_256(cls) -> str:
        """Generate a 256-bit (32-byte) random hex nonce."""
        return cls.random_hex(32)

    @classmethod
    def generate_id(cls, id_cls: Type[T_ID]) -> T_ID:
        """Generate a typed identifier with 128 bits of CSPRNG entropy."""
        if not issubclass(id_cls, BaseID):
            raise ValidationError(f"Target class must inherit from BaseID, got {id_cls}")
        raw_hex = cls.random_nonce_128()
        return id_cls.from_raw_hex(raw_hex)

    @classmethod
    def generate_typed_id(cls, id_cls: Type[T_ID]) -> T_ID:
        """Alias for generate_id for backwards/forwards convenience."""
        return cls.generate_id(id_cls)
