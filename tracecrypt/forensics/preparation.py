"""Forensic Preparation and Attribution Link Interface.

Provides the cryptographic bridge between an extracted watermark payload and
its corresponding signed decryption event on the ledger.

Investigator workflow preparation:
extracted watermark
      ↓
WatermarkID, SessionTag, DocumentBinding
      ↓
ledger lookup
      ↓
signed event
      ↓
certificate
      ↓
cryptographic verification
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.verifier import (
    DecryptionEventVerificationResult,
    DecryptionEventVerifier,
)
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.ledger.interface import DecryptionEventLedger
from tracecrypt.watermark.types import WatermarkPayload


class ForensicAttributionLink:
    """Prepares forensic lookup and cryptographic event verification."""

    @classmethod
    def locate_event(
        cls,
        watermark_payload: WatermarkPayload,
        ledger: DecryptionEventLedger,
    ) -> Optional[SignedDecryptionEvent]:
        """Locate the signed DecryptionEvent from an extracted watermark payload."""
        return ledger.lookup_by_watermark(watermark_payload.watermark_id)

    @classmethod
    def verify_attribution(
        cls,
        watermark_payload: WatermarkPayload,
        signed_event: SignedDecryptionEvent,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
    ) -> DecryptionEventVerificationResult:
        """Verify that an extracted watermark corresponds to a signed ledger event."""
        # 1. Verify that WatermarkID matches
        event = signed_event.event
        if event.watermark_id != watermark_payload.watermark_id:
            return DecryptionEventVerificationResult(
                valid=False,
                event_id=event.event_id,
                errors=[
                    f"WatermarkID mismatch: extracted '{watermark_payload.watermark_id}' "
                    f"!= event '{event.watermark_id}'"
                ],
            )

        # 2. Verify Session Tag
        expected_tag = WatermarkPayload.compute_session_tag(event.session_id)
        if watermark_payload.session_tag != expected_tag:
            return DecryptionEventVerificationResult(
                valid=False,
                event_id=event.event_id,
                errors=[
                    f"Session tag mismatch: extracted '{watermark_payload.session_tag.hex()}' "
                    f"!= event '{expected_tag.hex()}'"
                ],
            )

        # 3. Verify Document Binding
        if not watermark_payload.verify_document_binding(event.document_hash, event.session_id):
            return DecryptionEventVerificationResult(
                valid=False,
                event_id=event.event_id,
                errors=["Watermark document binding does not match event document hash and session."],
            )

        # 4. Execute full 8-point cryptographic event verification
        return DecryptionEventVerifier.verify_signed_event(
            signed_event=signed_event,
            recipient_certificate=recipient_certificate,
            root_ca_public_key=root_ca_public_key,
            revocation_provider=revocation_provider,
            expected_document_hash=event.document_hash,
            expected_watermark_id=watermark_payload.watermark_id,
            expected_session_id=event.session_id,
        )

    @classmethod
    def lookup_and_verify(
        cls,
        watermark_payload: WatermarkPayload,
        ledger: DecryptionEventLedger,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
    ) -> Tuple[Optional[SignedDecryptionEvent], Optional[DecryptionEventVerificationResult]]:
        """Find event on ledger and execute complete attribution verification."""
        signed_event = cls.locate_event(watermark_payload, ledger)
        if signed_event is None:
            return None, None

        result = cls.verify_attribution(
            watermark_payload=watermark_payload,
            signed_event=signed_event,
            recipient_certificate=recipient_certificate,
            root_ca_public_key=root_ca_public_key,
            revocation_provider=revocation_provider,
        )
        return signed_event, result
