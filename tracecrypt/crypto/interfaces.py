"""Cryptographic interfaces and protocols for TraceCrypt.

These protocols establish strict compile-time contracts for post-quantum key
encapsulation (ML-KEM), post-quantum digital signatures (ML-DSA), deterministic hashing,
secure randomness, and key derivation.

Key isolation is enforced: a key instance designed for encapsulation cannot be passed
to a signing provider.
"""

from __future__ import annotations

from typing import BinaryIO, Protocol, Tuple, runtime_checkable


@runtime_checkable
class RandomProvider(Protocol):
    """Protocol for secure, non-predictable cryptographic entropy generation."""

    def random_bytes(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes of specified length."""
        ...

    def random_hex(self, byte_length: int) -> str:
        """Generate cryptographically secure random lowercase hex string."""
        ...

    def random_nonce_128(self) -> str:
        """Generate a 128-bit (16-byte) random hex nonce."""
        ...


@runtime_checkable
class HashProvider(Protocol):
    """Protocol for cryptographic hashing operations."""

    def hash_bytes(self, data: bytes, algorithm: str = "sha3-256") -> str:
        """Compute formatted digest (e.g. 'sha3-256:<hex>') for arbitrary bytes."""
        ...

    def hash_file(self, file_obj: BinaryIO, algorithm: str = "sha3-256") -> str:
        """Compute formatted digest for a readable binary stream using chunking."""
        ...


@runtime_checkable
class KeyEncapsulationProvider(Protocol):
    """Protocol for Post-Quantum Key Encapsulation Mechanism (ML-KEM / FIPS 203)."""

    @property
    def algorithm_name(self) -> str:
        """Return standardized algorithm name (e.g., 'ML-KEM-768')."""
        ...

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate public and private key bytes for key encapsulation only."""
        ...

    def encapsulate(self, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate an ephemeral shared secret.

        Returns:
            (ciphertext_bytes, shared_secret_bytes)
        """
        ...

    def decapsulate(self, private_key_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
        """Decapsulate ciphertext to recover shared secret bytes."""
        ...


@runtime_checkable
class SignatureProvider(Protocol):
    """Protocol for Post-Quantum Digital Signatures (ML-DSA / FIPS 204)."""

    @property
    def algorithm_name(self) -> str:
        """Return standardized algorithm name (e.g., 'ML-DSA-65')."""
        ...

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate public and private key bytes for digital signatures only."""
        ...

    def sign(self, private_key_bytes: bytes, message: bytes) -> bytes:
        """Sign a message digest or byte payload using the private signing key."""
        ...

    def verify(self, public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
        """Verify the signature over a message using the certified public key."""
        ...


@runtime_checkable
class KeyDerivationProvider(Protocol):
    """Protocol for HKDF or Argon2id key derivation."""

    def derive_key(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        """Derive cryptographic key material using HKDF with specified parameters."""
        ...
