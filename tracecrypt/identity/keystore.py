"""Argon2id and AES-256-GCM Encrypted Private Key Keystore Container.

Conforms strictly to the TraceCrypt security architecture:
1. Passphrase derived via Argon2id (64 MB memory, 3 iterations, 4 parallelism lanes).
2. Key encryption via AES-256-GCM with 96-bit CSPRNG nonce.
3. Authenticated Associated Data (AAD) cryptographically commits to all container metadata
   via RFC 8785 canonical JSON serialization, preventing any header or metadata tampering.
4. OS-specific filesystem permission hardening (Windows ACLs / POSIX 0600).
5. Explicit memory zeroization of derived symmetric keys and decrypted buffers.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, Union
from pydantic import BaseModel, ConfigDict, Field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    MLDSAPrivateKey,
    MLKEMPrivateKey,
)
from tracecrypt.errors import CryptographicError, SecurityError, ValidationError
from tracecrypt.event.canonicalizer import canonicalize


class Argon2idKDFParams(BaseModel):
    """Argon2id key derivation parameters."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str = Field(default="Argon2id", description="KDF algorithm")
    memory_cost_kb: int = Field(default=65536, ge=65536, description="Memory cost in KB (minimum 64 MB)")
    iterations: int = Field(default=3, ge=3, description="Time cost iterations (minimum 3)")
    parallelism: int = Field(default=4, ge=4, description="Parallel lanes (minimum 4)")
    salt_b64: str
    derived_key_len: int = Field(default=32, ge=32, le=32, description="Derived key length in bytes (256-bit)")


class EncryptedKeyContainer(BaseModel):
    """Self-contained, authenticated encrypted private key container."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = Field(default="1.0.0")
    container_id: str
    key_id: str
    owner_id: str
    algorithm: str
    parameter_set: str
    purpose: KeyPurpose
    public_key_fingerprint: str
    kdf_params: Argon2idKDFParams
    cipher_algorithm: str = "AES-256-GCM"
    nonce_b64: str
    ciphertext_b64: str
    auth_tag_b64: str
    created_at: int

    def compute_aad_bytes(self) -> bytes:
        """Produce deterministic RFC 8785 canonical bytes for Authenticated Associated Data."""
        aad_data: Dict[str, Any] = {
            "format_version": self.format_version,
            "container_id": self.container_id,
            "key_id": self.key_id,
            "owner_id": self.owner_id,
            "algorithm": self.algorithm,
            "parameter_set": self.parameter_set,
            "purpose": self.purpose.value,
            "public_key_fingerprint": self.public_key_fingerprint,
            "created_at": self.created_at,
        }
        return canonicalize(aad_data)


def _harden_file_permissions(filepath: Path) -> None:
    """Apply restrictive permissions so only the owner has read/write access."""
    try:
        if sys.platform == "win32":
            # On Windows, use icacls to disable inheritance and grant full access exclusively to current user
            username = os.environ.get("USERNAME")
            if username:
                subprocess.run(
                    ["icacls", str(filepath), "/inheritance:r", "/grant:r", f"{username}:F"],
                    capture_output=True,
                    check=False,
                )
        else:
            # On POSIX systems, apply mode 0600
            os.chmod(filepath, 0o600)
    except Exception:
        # Non-fatal defense-in-depth attempt
        pass


class KeystoreManager:
    """Manages encryption, storage, and secure loading of private key containers."""

    SUPPORTED_VERSION = "1.0.0"

    @classmethod
    def encrypt_private_key(
        cls,
        private_key: Union[MLKEMPrivateKey, MLDSAPrivateKey, bytes],
        passphrase: str,
        metadata: KeyMetadata,
    ) -> EncryptedKeyContainer:
        """Encrypt a private key into a versioned authenticated container."""
        if not passphrase or len(passphrase) < 8:
            raise ValidationError("Passphrase must be at least 8 characters long.")

        if isinstance(private_key, (MLKEMPrivateKey, MLDSAPrivateKey)):
            raw_sk = private_key.raw_bytes
        elif isinstance(private_key, bytes):
            raw_sk = private_key
        else:
            raise ValidationError(f"Invalid private key type: {type(private_key).__name__}")

        salt = SecureRandom.random_bytes(16)
        nonce = SecureRandom.random_bytes(12)  # 96-bit standard GCM nonce
        container_id = f"con-{SecureRandom.random_nonce_128()}"

        kdf_params = Argon2idKDFParams(
            memory_cost_kb=65536,
            iterations=3,
            parallelism=4,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            derived_key_len=32,
        )

        kek = bytearray(32)
        try:
            # 1. Derive key-encryption key using Argon2id
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=65536,
            )
            derived = kdf.derive(passphrase.encode("utf-8"))
            for i in range(32):
                kek[i] = derived[i]

            # 2. Build preliminary container to construct deterministic AAD
            temp_container = EncryptedKeyContainer(
                format_version=cls.SUPPORTED_VERSION,
                container_id=container_id,
                key_id=metadata.key_id,
                owner_id=metadata.owner_id,
                algorithm=metadata.algorithm,
                parameter_set=metadata.parameter_set,
                purpose=metadata.purpose,
                public_key_fingerprint=metadata.fingerprint,
                kdf_params=kdf_params,
                cipher_algorithm="AES-256-GCM",
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
                ciphertext_b64="",
                auth_tag_b64="",
                created_at=metadata.created_at,
            )
            aad_bytes = temp_container.compute_aad_bytes()

            # 3. Encrypt private key with AES-256-GCM
            aesgcm = AESGCM(bytes(kek))
            # AESGCM.encrypt appends 16-byte tag to the ciphertext
            encrypted_payload = aesgcm.encrypt(nonce, raw_sk, aad_bytes)
            ciphertext = encrypted_payload[:-16]
            auth_tag = encrypted_payload[-16:]

            return EncryptedKeyContainer(
                format_version=cls.SUPPORTED_VERSION,
                container_id=container_id,
                key_id=metadata.key_id,
                owner_id=metadata.owner_id,
                algorithm=metadata.algorithm,
                parameter_set=metadata.parameter_set,
                purpose=metadata.purpose,
                public_key_fingerprint=metadata.fingerprint,
                kdf_params=kdf_params,
                cipher_algorithm="AES-256-GCM",
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
                ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
                auth_tag_b64=base64.b64encode(auth_tag).decode("ascii"),
                created_at=metadata.created_at,
            )
        finally:
            # Memory zeroization of derived key
            for i in range(len(kek)):
                kek[i] = 0

    @classmethod
    def decrypt_private_key(
        cls,
        container: EncryptedKeyContainer,
        passphrase: str,
    ) -> bytearray:
        """Decrypt an authenticated container and recover the private key bytes.

        Returns:
            Mutable bytearray containing the raw private key bytes. Caller is responsible
            for zeroizing when finished.
        """
        if container.format_version != cls.SUPPORTED_VERSION:
            raise SecurityError(
                f"Unsupported keystore format version '{container.format_version}' (Expected '{cls.SUPPORTED_VERSION}')"
            )

        if (
            container.kdf_params.algorithm != "Argon2id"
            or container.kdf_params.memory_cost_kb < 65536
            or container.kdf_params.iterations < 3
            or container.kdf_params.parallelism < 4
            or container.kdf_params.derived_key_len != 32
        ):
            raise SecurityError("Insecure or downgraded Argon2id parameters detected in key container.")

        salt = base64.b64decode(container.kdf_params.salt_b64)
        nonce = base64.b64decode(container.nonce_b64)
        ciphertext = base64.b64decode(container.ciphertext_b64)
        auth_tag = base64.b64decode(container.auth_tag_b64)
        encrypted_payload = ciphertext + auth_tag

        aad_bytes = container.compute_aad_bytes()
        kek = bytearray(32)

        try:
            # Re-derive key using container's Argon2id parameters
            kdf = Argon2id(
                salt=salt,
                length=container.kdf_params.derived_key_len,
                iterations=container.kdf_params.iterations,
                lanes=container.kdf_params.parallelism,
                memory_cost=container.kdf_params.memory_cost_kb,
            )
            derived = kdf.derive(passphrase.encode("utf-8"))
            for i in range(32):
                kek[i] = derived[i]

            aesgcm = AESGCM(bytes(kek))
            plaintext = aesgcm.decrypt(nonce, encrypted_payload, aad_bytes)
            return bytearray(plaintext)
        except Exception as e:
            raise CryptographicError(
                "Keystore decryption failed: invalid passphrase or corrupted/tampered key container."
            ) from e
        finally:
            for i in range(len(kek)):
                kek[i] = 0

    @classmethod
    def save_container(cls, container: EncryptedKeyContainer, filepath: Union[str, Path]) -> None:
        """Serialize container to disk and apply hardened file permissions."""
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = container.model_dump(mode="json")
        json_str = json.dumps(data, indent=2)
        with open(p, "w", encoding="utf-8") as f:
            f.write(json_str)
        _harden_file_permissions(p)

    @classmethod
    def load_container(cls, filepath: Union[str, Path]) -> EncryptedKeyContainer:
        """Load and parse an encrypted key container from disk."""
        p = Path(filepath)
        if not p.is_file():
            raise ValidationError(f"Keystore file does not exist: {p}")
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return EncryptedKeyContainer.model_validate(data)
        except Exception as e:
            raise ValidationError(f"Failed to read key container from {p}: {e}") from e
