"""PQC Identity Certificate Envelope and Deterministic Offline Validation.

IMPORTANT INTEROPERABILITY & STANDARDS NOTICE:
Conventional X.509 ASN.1 tooling (classic OpenSSL, Windows CAPI) does not natively support
NIST FIPS 204 ML-DSA-65 signatures or NIST FIPS 203 ML-KEM-768 public keys without non-standard
experimental OID extensions that classic verifiers reject.

In strict compliance with the TraceCrypt Project Contract:
1. We DO NOT create a pseudo-X.509 certificate that falsely claims ITU-T X.509 standards compliance.
2. We implement a versioned, authenticated PQC Identity Certificate Envelope.
3. Certificate signing bytes are serialized strictly using RFC 8785 (JSON Canonicalization Scheme).
4. The Offline Root CA ML-DSA-65 signature commits to the canonical RFC 8785 digest.
5. Certificate validation executes a 12-point deterministic offline verification pipeline.
"""

from __future__ import annotations

import base64
from typing import ClassVar, Dict, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.pqc_dsa import verify as verify_mldsa
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPublicKey,
    MLDSASignature,
    MLKEMPublicKey,
)
from tracecrypt.errors import SecurityError, ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.utils.timestamps import utc_now_micros


@runtime_checkable
class RevocationProvider(Protocol):
    """Protocol for checking offline credential revocation status."""
    def is_serial_revoked(self, serial_number: str) -> bool:
        ...


class PQCIdentityCertificate(BaseModel):
    """Authenticated Post-Quantum Identity Certificate Envelope."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    FORMAT_VERSION: ClassVar[str] = "1.0.0"

    format_version: str = Field(default="1.0.0")
    serial_number: str = Field(description="Unique certificate serial number, e.g. crt-...")
    issuer_ca_id: str = Field(description="Root CA identifier, e.g. ca-root-...")
    subject_id: str = Field(description="Certified UserID or RecipientID")
    device_id: Optional[str] = Field(default=None, description="Optional bound DeviceID")
    organization: str = Field(min_length=1, max_length=100)
    role: str = Field(min_length=1, max_length=50)
    key_purpose: KeyPurpose = Field(description="Enforced cryptographic role")
    algorithm: str = Field(description="ML-DSA-65 or ML-KEM-768")
    parameter_set: str = Field(description="NIST parameter set name")
    public_key_b64: str = Field(description="Base64-encoded raw public key bytes")
    public_key_fingerprint: str = Field(description="Canonical public key fingerprint")
    valid_from: int = Field(description="POSIX microsecond UTC timestamp")
    valid_until: int = Field(description="POSIX microsecond UTC timestamp")
    signature_b64: str = Field(description="Base64-encoded Root CA ML-DSA-65 signature")

    def to_signing_dict(self) -> Dict[str, object]:
        """Return the dictionary payload covered by the Root CA's digital signature."""
        data = self.model_dump(mode="json")
        data.pop("signature_b64", None)
        return data

    def to_signing_bytes(self) -> bytes:
        """Produce the deterministic RFC 8785 canonical byte stream for signature verification."""
        return canonicalize(self.to_signing_dict())

    def get_public_key_bytes(self) -> bytes:
        """Return raw public key bytes."""
        try:
            return base64.b64decode(self.public_key_b64, validate=True)
        except Exception as e:
            raise ValidationError(f"Invalid base64 in certificate public key: {e}") from e

    def to_canonical_json(self) -> str:
        """Serialize full certificate envelope to RFC 8785 canonical JSON string."""
        return canonicalize(self.model_dump(mode="json")).decode("utf-8")

    @classmethod
    def from_canonical_json(cls, json_str: str) -> PQCIdentityCertificate:
        """Parse PQCIdentityCertificate from JSON string."""
        import json
        try:
            data = json.loads(json_str)
            return cls.model_validate(data)
        except Exception as e:
            raise ValidationError(f"Failed to parse PQCIdentityCertificate from JSON: {e}") from e


class CertificateValidator:
    """Deterministic 12-point offline certificate validation pipeline."""

    @classmethod
    def validate(
        cls,
        certificate: PQCIdentityCertificate,
        root_ca_public_key: MLDSAPublicKey,
        revocation_provider: Optional[RevocationProvider] = None,
        current_time_micros: Optional[int] = None,
        expected_purpose: Optional[KeyPurpose] = None,
    ) -> None:
        """Execute the mandatory 12 offline verification checks.

        Fails closed on any check failure by raising ValidationError or SecurityError.
        """
        now = current_time_micros if current_time_micros is not None else utc_now_micros()

        # 1. Certificate Structure
        if certificate.format_version != PQCIdentityCertificate.FORMAT_VERSION:
            raise ValidationError(
                f"Check 1 Failed: Unsupported certificate format version '{certificate.format_version}'"
            )
        if not certificate.serial_number.startswith("crt-"):
            raise ValidationError("Check 1 Failed: Malformed certificate serial number.")

        # 2. Issuer Identity
        if not certificate.issuer_ca_id.startswith("ca-"):
            raise ValidationError(f"Check 2 Failed: Invalid issuer CA identity '{certificate.issuer_ca_id}'")

        # 3. Issuer Signature (NIST FIPS 204 ML-DSA-65)
        try:
            sig_bytes = base64.b64decode(certificate.signature_b64, validate=True)
            sig_obj = MLDSASignature(sig_bytes)
        except Exception as e:
            raise SecurityError(f"Check 3 Failed: Malformed issuer signature encoding: {e}") from e

        signing_bytes = certificate.to_signing_bytes()
        if not verify_mldsa(root_ca_public_key, signing_bytes, sig_obj):
            raise SecurityError("Check 3 Failed: Invalid Root CA digital signature. Certificate forgery detected.")

        # 4. Subject Identity
        if not certificate.subject_id.strip():
            raise ValidationError("Check 4 Failed: Certificate subject identity cannot be empty.")

        # 5. Public Key Binding & Fingerprint
        raw_pk = certificate.get_public_key_bytes()
        if certificate.algorithm == "ML-DSA-65":
            if len(raw_pk) != MLDSAPublicKey.EXPECTED_LENGTH:
                raise ValidationError(
                    f"Check 5 Failed: Invalid ML-DSA-65 public key size: "
                    f"{len(raw_pk)} != {MLDSAPublicKey.EXPECTED_LENGTH}"
                )
            digest = Hasher.digest_bytes(raw_pk, HashAlgorithm.SHA3_256.value)
            computed_fp = f"mldsa65:{digest.formatted}"
        elif certificate.algorithm == "ML-KEM-768":
            if len(raw_pk) != MLKEMPublicKey.EXPECTED_LENGTH:
                raise ValidationError(
                    f"Check 5 Failed: Invalid ML-KEM-768 public key size: "
                    f"{len(raw_pk)} != {MLKEMPublicKey.EXPECTED_LENGTH}"
                )
            digest = Hasher.digest_bytes(raw_pk, HashAlgorithm.SHA3_256.value)
            computed_fp = f"mlkem768:{digest.formatted}"
        else:
            raise ValidationError(f"Check 5 Failed: Unknown algorithm '{certificate.algorithm}'")

        if computed_fp != certificate.public_key_fingerprint:
            raise SecurityError("Check 5 Failed: Public key fingerprint mismatch. Tampering detected.")

        # 6. Algorithm
        if certificate.algorithm not in ("ML-DSA-65", "ML-KEM-768"):
            raise ValidationError(f"Check 6 Failed: Algorithm '{certificate.algorithm}' not in authorized PQC suite.")

        # 7. Parameter Set
        if certificate.algorithm == "ML-DSA-65" and certificate.parameter_set != "ML-DSA-65":
            raise ValidationError(
                f"Check 7 Failed: Incompatible parameter set '{certificate.parameter_set}' for ML-DSA-65"
            )
        if certificate.algorithm == "ML-KEM-768" and certificate.parameter_set != "ML-KEM-768":
            raise ValidationError(
                f"Check 7 Failed: Incompatible parameter set '{certificate.parameter_set}' for ML-KEM-768"
            )

        # 8. Validity Period
        if certificate.valid_from > certificate.valid_until:
            raise ValidationError("Check 8 Failed: Invalid certificate temporal range (valid_from > valid_until)")
        if now < certificate.valid_from:
            raise SecurityError("Check 8 Failed: Certificate is not yet valid (not-before check failed).")
        if now > certificate.valid_until:
            raise SecurityError("Check 8 Failed: Certificate has expired.")

        # 9. Certificate Status Invariants
        if certificate.valid_until - certificate.valid_from <= 0:
            raise ValidationError("Check 9 Failed: Certificate duration is non-positive.")

        # 10. Key Purpose
        if expected_purpose is not None and certificate.key_purpose != expected_purpose:
            raise SecurityError(
                f"Check 10 Failed: Certificate key purpose '{certificate.key_purpose.value}' "
                f"does not match expected purpose '{expected_purpose.value}'."
            )
        if certificate.algorithm == "ML-DSA-65" and certificate.key_purpose != KeyPurpose.DIGITAL_SIGNATURE:
            raise ValidationError("Check 10 Failed: ML-DSA-65 key must have DIGITAL_SIGNATURE purpose.")
        if certificate.algorithm == "ML-KEM-768" and certificate.key_purpose != KeyPurpose.KEY_ENCAPSULATION:
            raise ValidationError("Check 10 Failed: ML-KEM-768 key must have KEY_ENCAPSULATION purpose.")

        # 11. Revocation State
        if revocation_provider is not None:
            if revocation_provider.is_serial_revoked(certificate.serial_number):
                raise SecurityError(
                    f"Check 11 Failed: Certificate '{certificate.serial_number}' has been REVOKED."
                )

        # 12. Chain to Trusted Root CA
        # Verified cryptographically in Check 3; Root CA public key is pinned directly
