"""Recipient ML-DSA-65 Event Signing Engine.

Binds the recipient's post-quantum identity to the canonical DecryptionEvent
using NIST FIPS 204 ML-DSA-65 signatures over RFC 8785 canonical byte streams.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Optional, Union

from tracecrypt.crypto.pqc_dsa import MLDSAProvider
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPrivateKey,
    MLDSAPublicKey,
)
from tracecrypt.errors import (
    CryptographicError,
    SecurityError,
    ValidationError,
)
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.schema import DecryptionEvent
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.utils.timestamps import utc_now_micros

if TYPE_CHECKING:
    from tracecrypt.identity.certificate import PQCIdentityCertificate


class DecryptionEventSigner:
    """Signs canonical DecryptionEvents using certified recipient ML-DSA-65 keys."""

    @classmethod
    def sign_event(
        cls,
        event: DecryptionEvent,
        signing_key: Union[MLDSAPrivateKey, bytes],
        signing_cert: PQCIdentityCertificate,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
        signing_key_id: Optional[str] = None,
    ) -> SignedDecryptionEvent:
        """Sign a DecryptionEvent with recipient's ML-DSA-65 private key.

        Enforces:
        1. Recipient certificate purpose is DIGITAL_SIGNATURE.
        2. Recipient identity matches certificate subject.
        3. Root CA offline certificate validation (if root_ca_public_key provided).
        4. Private key matches certificate public key.
        5. RFC 8785 canonical byte serialization.
        6. SHA3-256 event digest computation.
        7. NIST FIPS 204 ML-DSA-65 digital signature.

        Returns:
            SignedDecryptionEvent
        """
        from tracecrypt.identity.certificate import CertificateValidator
        # 1. Enforce Key Purpose Separation
        if signing_cert.key_purpose != KeyPurpose.DIGITAL_SIGNATURE:
            raise SecurityError(
                f"Key purpose violation: Certificate {signing_cert.serial_number} has purpose "
                f"'{signing_cert.key_purpose}', but DIGITAL_SIGNATURE is strictly required for signing events."
            )

        if signing_cert.algorithm != "ML-DSA-65":
            raise SecurityError(
                f"Algorithm mismatch: Certificate specifies '{signing_cert.algorithm}', "
                f"but ML-DSA-65 is required for event signing."
            )

        # 2. Recipient Identity Binding
        if str(event.recipient_id) != str(signing_cert.subject_id):
            raise SecurityError(
                f"Identity binding mismatch: Event recipient '{event.recipient_id}' does not match "
                f"certificate subject '{signing_cert.subject_id}'."
            )

        # 3. Offline Certificate Validation against Root CA if available
        if root_ca_public_key is not None:
            CertificateValidator.validate(
                certificate=signing_cert,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=revocation_provider,
                expected_purpose=KeyPurpose.DIGITAL_SIGNATURE,
            )

        # 4. Wrap private key and verify it matches the certificate
        if isinstance(signing_key, bytes):
            sk_obj = MLDSAPrivateKey(signing_key)
        elif isinstance(signing_key, MLDSAPrivateKey):
            sk_obj = signing_key
        else:
            raise ValidationError(
                f"signing_key must be MLDSAPrivateKey or bytes, got {type(signing_key).__name__}"
            )

        provider = MLDSAProvider()
        cert_pk = MLDSAPublicKey(signing_cert.get_public_key_bytes())
        key_id = signing_key_id or f"key-{event.recipient_id}-dsa-v1"

        # Update event's optional recipient metadata if not set
        event_data = event.model_dump()
        if not event_data.get("recipient_key_id"):
            event_data["recipient_key_id"] = key_id
        if not event_data.get("recipient_certificate_id"):
            event_data["recipient_certificate_id"] = signing_cert.serial_number
        if not event_data.get("public_key_ref"):
            event_data["public_key_ref"] = signing_cert.public_key_fingerprint

        target_event = DecryptionEvent.model_validate(event_data)

        # 5. Canonicalize event using RFC 8785
        canonical_dict = target_event.to_canonical_dict()
        canonical_bytes = canonicalize(canonical_dict)
        canonical_str = canonical_bytes.decode("utf-8")

        # 6. Compute SHA3-256 event digest
        event_digest = target_event.compute_event_digest()

        # 7. Generate ML-DSA-65 signature over the canonical event bytes
        try:
            sig = provider.sign(sk_obj, canonical_bytes)
        except Exception as e:
            raise CryptographicError(f"ML-DSA-65 signature generation failed: {e}") from e

        # 8. Verify signature with certificate public key to ensure keypair alignment
        if not provider.verify(cert_pk, canonical_bytes, sig):
            raise SecurityError(
                "Cryptographic mismatch: Provided private key does not correspond to "
                "the public key in certificate " + signing_cert.serial_number
            )

        sig_b64 = base64.b64encode(sig.raw_bytes).decode("ascii")
        now = utc_now_micros()

        event_data_with_sig = target_event.model_dump()
        event_data_with_sig["signature"] = sig_b64
        final_event = DecryptionEvent.model_validate(event_data_with_sig)

        return SignedDecryptionEvent(
            event=final_event,
            canonical_event=canonical_str,
            event_digest=event_digest,
            signature=sig_b64,
            signing_key_id=key_id,
            certificate_id=signing_cert.serial_number,
            certificate_fingerprint=signing_cert.public_key_fingerprint,
            signed_at=now,
            ledger_transaction_id=None,
        )
