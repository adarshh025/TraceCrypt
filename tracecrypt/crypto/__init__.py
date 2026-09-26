"""Cryptographic foundation protocols, types, and PQC implementations for TraceCrypt."""

from tracecrypt.crypto.hashing import HashAlgorithm, HashDigest, Hasher
from tracecrypt.crypto.interfaces import (
    HashProvider,
    KeyDerivationProvider,
    KeyEncapsulationProvider,
    RandomProvider,
    SignatureProvider,
)
from tracecrypt.crypto.pqc_dsa import (
    MLDSAProvider,
    generate_mldsa_keypair,
    sign,
    verify,
)
from tracecrypt.crypto.pqc_kem import (
    MLKEMProvider,
    decapsulate,
    encapsulate,
    generate_mlkem_keypair,
)
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    KeyReference,
    KeyStatus,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    MLDSASignature,
    MLKEMCiphertext,
    MLKEMPrivateKey,
    MLKEMPublicKey,
)

__all__ = [
    "HashAlgorithm",
    "HashDigest",
    "Hasher",
    "HashProvider",
    "KeyDerivationProvider",
    "KeyEncapsulationProvider",
    "RandomProvider",
    "SignatureProvider",
    "SecureRandom",
    "KeyPurpose",
    "KeyStatus",
    "KeyMetadata",
    "KeyReference",
    "MLKEMPublicKey",
    "MLKEMPrivateKey",
    "MLKEMCiphertext",
    "MLDSAPublicKey",
    "MLDSAPrivateKey",
    "MLDSASignature",
    "MLKEMProvider",
    "generate_mlkem_keypair",
    "encapsulate",
    "decapsulate",
    "MLDSAProvider",
    "generate_mldsa_keypair",
    "sign",
    "verify",
]
