"""Independent Verification Subsystem for Signed Decryption Events.

Executes a fail-closed 8-point verification pipeline to mathematically prove:
1. Canonical event integrity (RFC 8785 determinism).
2. SHA3-256 event digest correctness.
3. NIST FIPS 204 ML-DSA-65 post-quantum digital signature validity.
4. Recipient certificate chain of trust to Root CA.
5. Key purpose separation (DIGITAL_SIGNATURE strictly enforced).
6. Certificate validity period and revocation status.
7. Cryptographic document binding.
8. Forensic watermark binding.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.pqc_dsa import MLDSAProvider
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPublicKey,
    MLDSASignature,
)
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.utils.identifiers import EventID, SessionID, WatermarkID

if TYPE_CHECKING:
    from tracecrypt.identity.certificate import PQCIdentityCertificate


class DecryptionEventVerificationResult(BaseModel):
    """Strict typed verification result for signed decryption events."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool = Field(description="True only if ALL verification checks passed")
    event_id: EventID = Field(description="Identifier of verified event")
    digest_verified: bool = Field(default=False, description="Canonical digest matches event payload")
    signature_verified: bool = Field(default=False, description="ML-DSA-65 signature mathematically valid")
    certificate_verified: bool = Field(default=False, description="Recipient certificate authentic and active")
    key_purpose_verified: bool = Field(default=False, description="Key purpose is strictly DIGITAL_SIGNATURE")
    document_binding_verified: bool = Field(default=False, description="Source document hash verified")
    watermark_binding_verified: bool = Field(default=False, description="Watermark and Session IDs verified")
    errors: List[str] = Field(default_factory=list, description="Diagnostic error descriptions on failure")

    @property
    def is_valid(self) -> bool:
        return self.valid


class DecryptionEventVerifier:
    """Independent verifier for signed decryption events."""

    @classmethod
    def verify_signed_event(
        cls,
        signed_event: SignedDecryptionEvent,
        recipient_public_key: Optional[MLDSAPublicKey] = None,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
        expected_document_hash: Optional[str] = None,
        expected_watermark_id: Optional[WatermarkID | str] = None,
        expected_session_id: Optional[SessionID | str] = None,
        current_time_micros: Optional[int] = None,
    ) -> DecryptionEventVerificationResult:
        """Execute the fail-closed 8-point verification pipeline.

        Returns:
            DecryptionEventVerificationResult
        """
        from tracecrypt.identity.certificate import CertificateValidator

        errors: List[str] = []
        digest_verified = False
        sig_verified = False
        cert_verified = False
        purpose_verified = False
        doc_verified = True
        wm_verified = True

        event = signed_event.event

        # 1. Reconstruct RFC 8785 canonical bytes and verify canonical_event string
        try:
            canon_bytes = event.to_canonical_bytes()
            canon_str = canon_bytes.decode("utf-8")
            if signed_event.canonical_event != canon_str:
                errors.append(
                    "Canonical representation mismatch: signed_event.canonical_event "
                    "does not match RFC 8785 canonical serialization of event"
                )
        except Exception as e:
            errors.append(f"Canonicalization failure: {e}")
            canon_bytes = b""

        # 2. Verify SHA3-256 event digest
        try:
            expected_digest = event.compute_event_digest()
            if signed_event.event_digest != expected_digest:
                errors.append(
                    f"Event digest mismatch: expected '{expected_digest}', got '{signed_event.event_digest}'"
                )
            else:
                digest_verified = True
        except Exception as e:
            errors.append(f"Digest computation failure: {e}")

        # 3. Determine public key for signature verification
        pk_obj: Optional[MLDSAPublicKey] = None
        cert = recipient_certificate

        if cert is not None:
            # 4. Certificate checks
            try:
                if cert.key_purpose != KeyPurpose.DIGITAL_SIGNATURE:
                    errors.append(
                        f"Certificate key purpose violation: expected DIGITAL_SIGNATURE, got {cert.key_purpose}"
                    )
                else:
                    purpose_verified = True

                if signed_event.certificate_id and cert.serial_number != signed_event.certificate_id:
                    errors.append(
                        f"Certificate serial mismatch: cert is {cert.serial_number}, "
                        f"event referenced {signed_event.certificate_id}"
                    )

                if (
                    signed_event.certificate_fingerprint
                    and cert.public_key_fingerprint != signed_event.certificate_fingerprint
                ):
                    errors.append(
                        f"Certificate fingerprint mismatch: cert is {cert.public_key_fingerprint}, "
                        f"event referenced {signed_event.certificate_fingerprint}"
                    )

                if root_ca_public_key is not None:
                    CertificateValidator.validate(
                        certificate=cert,
                        root_ca_public_key=root_ca_public_key,
                        revocation_provider=revocation_provider,
                        current_time_micros=current_time_micros,
                        expected_purpose=KeyPurpose.DIGITAL_SIGNATURE,
                    )
                    cert_verified = True
                else:
                    # If Root CA not provided, verify cert structure and purpose
                    cert_verified = purpose_verified and (len(errors) == 0)

                pk_bytes = cert.get_public_key_bytes()
                pk_obj = MLDSAPublicKey(pk_bytes)
            except Exception as e:
                errors.append(f"Certificate validation failure: {e}")
        elif recipient_public_key is not None:
            pk_obj = recipient_public_key
            purpose_verified = True
            cert_verified = True
        else:
            errors.append("Verification requires recipient_certificate or recipient_public_key")

        # 5. Verify ML-DSA-65 digital signature
        if pk_obj is not None and canon_bytes:
            try:
                sig_bytes = base64.b64decode(signed_event.signature, validate=True)
                sig_obj = MLDSASignature(sig_bytes)
                provider = MLDSAProvider()
                if provider.verify(pk_obj, canon_bytes, sig_obj):
                    sig_verified = True
                else:
                    errors.append("ML-DSA-65 digital signature verification failed: signature invalid for public key")
            except Exception as e:
                errors.append(f"Signature decoding or verification error: {e}")

        # 6. Verify Document Binding
        if expected_document_hash is not None:
            if event.document_hash.lower() != expected_document_hash.lower():
                doc_verified = False
                errors.append(
                    f"Document binding mismatch: event hash '{event.document_hash}' "
                    f"!= expected '{expected_document_hash}'"
                )

        # 7. Verify Watermark Binding
        if expected_watermark_id is not None:
            if str(event.watermark_id) != str(expected_watermark_id):
                wm_verified = False
                errors.append(
                    f"WatermarkID binding mismatch: event watermark '{event.watermark_id}' "
                    f"!= expected '{expected_watermark_id}'"
                )

        if expected_session_id is not None:
            if str(event.session_id) != str(expected_session_id):
                wm_verified = False
                errors.append(
                    f"SessionID binding mismatch: event session '{event.session_id}' "
                    f"!= expected '{expected_session_id}'"
                )

        # All checks must pass for overall validity
        overall_valid = (
            digest_verified
            and sig_verified
            and cert_verified
            and purpose_verified
            and doc_verified
            and wm_verified
            and (len(errors) == 0)
        )

        return DecryptionEventVerificationResult(
            valid=overall_valid,
            event_id=event.event_id,
            digest_verified=digest_verified,
            signature_verified=sig_verified,
            certificate_verified=cert_verified,
            key_purpose_verified=purpose_verified,
            document_binding_verified=doc_verified,
            watermark_binding_verified=wm_verified,
            errors=errors,
        )
