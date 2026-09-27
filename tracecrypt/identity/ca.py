"""Offline Root Certificate Authority (Root CA) for TraceCrypt.

Operates exclusively in an air-gapped environment without cloud PKI or external services.
Generates NIST FIPS 204 ML-DSA-65 master signing keys and signs recipient/device certificates.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign as sign_mldsa
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    KeyStatus,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    MLKEMPublicKey,
)
from tracecrypt.errors import SecurityError
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.utils.timestamps import utc_now_micros


class OfflineRootCA:
    """Offline Certificate Authority anchored in an ML-DSA-65 master key pair."""

    def __init__(
        self,
        ca_id: str,
        public_key: MLDSAPublicKey,
        private_key: Optional[MLDSAPrivateKey] = None,
    ) -> None:
        self.ca_id = ca_id
        self.public_key = public_key
        self._private_key = private_key

    @property
    def fingerprint(self) -> str:
        return self.public_key.fingerprint

    @classmethod
    def initialize(cls, ca_id: Optional[str] = None) -> OfflineRootCA:
        """Initialize a new Offline Root CA with freshly generated ML-DSA-65 master keys."""
        root_id = ca_id or f"ca-root-{SecureRandom.random_nonce_128()}"
        pk, sk = generate_mldsa_keypair()
        return cls(ca_id=root_id, public_key=pk, private_key=sk)

    def issue_signing_certificate(
        self,
        subject_id: str,
        public_key: MLDSAPublicKey,
        organization: str,
        role: str,
        validity_days: int = 365,
        device_id: Optional[str] = None,
    ) -> PQCIdentityCertificate:
        """Issue an identity certificate for ML-DSA-65 digital signatures."""
        if self._private_key is None:
            raise SecurityError("Root CA cannot issue certificates without unlocked private key.")

        now = utc_now_micros()
        valid_until = now + (validity_days * 86_400 * 1_000_000)
        serial = f"crt-{SecureRandom.random_nonce_128()}"

        cert_proto = PQCIdentityCertificate(
            format_version=PQCIdentityCertificate.FORMAT_VERSION,
            serial_number=serial,
            issuer_ca_id=self.ca_id,
            subject_id=subject_id,
            device_id=device_id,
            organization=organization,
            role=role,
            key_purpose=KeyPurpose.DIGITAL_SIGNATURE,
            algorithm="ML-DSA-65",
            parameter_set="ML-DSA-65",
            public_key_b64=public_key.to_b64(),
            public_key_fingerprint=public_key.fingerprint,
            valid_from=now,
            valid_until=valid_until,
            signature_b64="",
        )

        signing_bytes = cert_proto.to_signing_bytes()
        sig = sign_mldsa(self._private_key, signing_bytes)

        return PQCIdentityCertificate(
            format_version=cert_proto.format_version,
            serial_number=cert_proto.serial_number,
            issuer_ca_id=cert_proto.issuer_ca_id,
            subject_id=cert_proto.subject_id,
            device_id=cert_proto.device_id,
            organization=cert_proto.organization,
            role=cert_proto.role,
            key_purpose=cert_proto.key_purpose,
            algorithm=cert_proto.algorithm,
            parameter_set=cert_proto.parameter_set,
            public_key_b64=cert_proto.public_key_b64,
            public_key_fingerprint=cert_proto.public_key_fingerprint,
            valid_from=cert_proto.valid_from,
            valid_until=cert_proto.valid_until,
            signature_b64=sig.to_b64(),
        )

    def issue_validator_certificate(
        self,
        subject_id: str,
        public_key: MLDSAPublicKey,
        organization: str = "TraceCrypt Consensus",
        role: str = "Validator",
        validity_days: int = 365,
        device_id: Optional[str] = None,
    ) -> PQCIdentityCertificate:
        """Issue an identity certificate for ML-DSA-65 consensus validation."""
        if self._private_key is None:
            raise SecurityError("Root CA cannot issue certificates without unlocked private key.")

        now = utc_now_micros()
        valid_until = now + (validity_days * 86_400 * 1_000_000)
        serial = f"crt-{SecureRandom.random_nonce_128()}"

        cert_proto = PQCIdentityCertificate(
            format_version=PQCIdentityCertificate.FORMAT_VERSION,
            serial_number=serial,
            issuer_ca_id=self.ca_id,
            subject_id=subject_id,
            device_id=device_id,
            organization=organization,
            role=role,
            key_purpose=KeyPurpose.CONSENSUS_VALIDATION,
            algorithm="ML-DSA-65",
            parameter_set="ML-DSA-65",
            public_key_b64=public_key.to_b64(),
            public_key_fingerprint=public_key.fingerprint,
            valid_from=now,
            valid_until=valid_until,
            signature_b64="",
        )

        signing_bytes = cert_proto.to_signing_bytes()
        sig = sign_mldsa(self._private_key, signing_bytes)

        return PQCIdentityCertificate(
            format_version=cert_proto.format_version,
            serial_number=cert_proto.serial_number,
            issuer_ca_id=cert_proto.issuer_ca_id,
            subject_id=cert_proto.subject_id,
            device_id=cert_proto.device_id,
            organization=cert_proto.organization,
            role=cert_proto.role,
            key_purpose=cert_proto.key_purpose,
            algorithm=cert_proto.algorithm,
            parameter_set=cert_proto.parameter_set,
            public_key_b64=cert_proto.public_key_b64,
            public_key_fingerprint=cert_proto.public_key_fingerprint,
            valid_from=cert_proto.valid_from,
            valid_until=cert_proto.valid_until,
            signature_b64=sig.to_b64(),
        )

    def issue_kem_certificate(
        self,
        subject_id: str,
        public_key: MLKEMPublicKey,
        organization: str,
        role: str,
        validity_days: int = 365,
        device_id: Optional[str] = None,
        valid_from: Optional[int] = None,
        valid_until: Optional[int] = None,
    ) -> PQCIdentityCertificate:
        """Issue an identity certificate for ML-KEM-768 key encapsulation."""
        if self._private_key is None:
            raise SecurityError("Root CA cannot issue certificates without unlocked private key.")

        now = utc_now_micros()
        v_from = valid_from if valid_from is not None else now
        v_until = valid_until if valid_until is not None else (v_from + (validity_days * 86_400 * 1_000_000))
        serial = f"crt-{SecureRandom.random_nonce_128()}"

        cert_proto = PQCIdentityCertificate(
            format_version=PQCIdentityCertificate.FORMAT_VERSION,
            serial_number=serial,
            issuer_ca_id=self.ca_id,
            subject_id=subject_id,
            device_id=device_id,
            organization=organization,
            role=role,
            key_purpose=KeyPurpose.KEY_ENCAPSULATION,
            algorithm="ML-KEM-768",
            parameter_set="ML-KEM-768",
            public_key_b64=public_key.to_b64(),
            public_key_fingerprint=public_key.fingerprint,
            valid_from=v_from,
            valid_until=v_until,
            signature_b64="",
        )

        signing_bytes = cert_proto.to_signing_bytes()
        sig = sign_mldsa(self._private_key, signing_bytes)

        return PQCIdentityCertificate(
            format_version=cert_proto.format_version,
            serial_number=cert_proto.serial_number,
            issuer_ca_id=cert_proto.issuer_ca_id,
            subject_id=cert_proto.subject_id,
            device_id=cert_proto.device_id,
            organization=cert_proto.organization,
            role=cert_proto.role,
            key_purpose=cert_proto.key_purpose,
            algorithm=cert_proto.algorithm,
            parameter_set=cert_proto.parameter_set,
            public_key_b64=cert_proto.public_key_b64,
            public_key_fingerprint=cert_proto.public_key_fingerprint,
            valid_from=cert_proto.valid_from,
            valid_until=cert_proto.valid_until,
            signature_b64=sig.to_b64(),
        )

    def save_to_keystore(self, keystore_path: Union[str, Path], passphrase: str) -> None:
        """Save Root CA encrypted with Argon2id and AES-256-GCM."""
        if self._private_key is None:
            raise SecurityError("Cannot save Root CA without private key.")
        metadata = KeyMetadata(
            key_id=f"key-root-{self.ca_id}",
            owner_id=self.ca_id,
            purpose=KeyPurpose.ROOT_AUTHORITY,
            algorithm="ML-DSA-65",
            parameter_set="ML-DSA-65",
            created_at=utc_now_micros(),
            status=KeyStatus.ACTIVE,
            version=1,
            fingerprint=self.fingerprint,
        )
        container = KeystoreManager.encrypt_private_key(self._private_key, passphrase, metadata)
        KeystoreManager.save_container(container, keystore_path)

    @classmethod
    def load_from_keystore(
        cls,
        keystore_path: Union[str, Path],
        passphrase: str,
        public_key_bytes: bytes,
    ) -> OfflineRootCA:
        """Load Root CA from encrypted keystore."""
        container = KeystoreManager.load_container(keystore_path)
        pk = MLDSAPublicKey(public_key_bytes)
        raw_sk = KeystoreManager.decrypt_private_key(container, passphrase)
        try:
            sk = MLDSAPrivateKey(bytes(raw_sk))
            return cls(ca_id=container.owner_id, public_key=pk, private_key=sk)
        finally:
            for i in range(len(raw_sk)):
                raw_sk[i] = 0
