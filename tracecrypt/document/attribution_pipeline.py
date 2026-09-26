"""Recipient-Side Atomic Attribution Decryption Pipeline for TraceCrypt.

Enforces the central security property:
DECRYPT
   ↓
CREATE SESSION
   ↓
CREATE UNIQUE WATERMARK
   ↓
EMBED WATERMARK
   ↓
BUILD CANONICAL EVENT
   ↓
SIGN EVENT WITH RECIPIENT ML-DSA-65
   ↓
PREPARE LEDGER TRANSACTION
   ↓
ONLY THEN RELEASE DOCUMENT

The decrypted document must NEVER be released as an ordinary unwatermarked document
during the production workflow. If watermark embedding, event signing, or ledger commitment
fails, document release is strictly denied and temporary sensitive plaintext is zeroized.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    MLKEMPrivateKey,
)
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.release_gate import DocumentReleaseGate
from tracecrypt.document.types import RecipientEnvelope
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import (
    CryptographicError,
    IntegrityError,
    SecurityError,
    ValidationError,
    WatermarkError,
)
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.ledger.interface import DecryptionEventLedger
from tracecrypt.ledger.types import LedgerTransactionReceipt
from tracecrypt.utils.identifiers import (
    DeviceID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.embedder import WatermarkEmbedder, WatermarkEmbeddingResult
from tracecrypt.watermark.types import FidelityMetrics, WatermarkParameters, WatermarkPayload


class RecipientCredentials:
    """Holds authorized recipient keys and certificates for decryption and attribution signing."""

    def __init__(
        self,
        recipient_id: RecipientID | str,
        kem_private_key: Union[MLKEMPrivateKey, bytes],
        kem_certificate: PQCIdentityCertificate,
        dsa_private_key: Union[MLDSAPrivateKey, bytes],
        dsa_certificate: PQCIdentityCertificate,
        device_id: Optional[DeviceID | str] = None,
    ) -> None:
        self.recipient_id = RecipientID(str(recipient_id))
        self.kem_private_key = (
            kem_private_key if isinstance(kem_private_key, MLKEMPrivateKey) else MLKEMPrivateKey(kem_private_key)
        )
        self.kem_certificate = kem_certificate
        self.dsa_private_key = (
            dsa_private_key if isinstance(dsa_private_key, MLDSAPrivateKey) else MLDSAPrivateKey(dsa_private_key)
        )
        self.dsa_certificate = dsa_certificate
        self.device_id = DeviceID(str(device_id)) if device_id else None

        # Verify key purposes
        if self.kem_certificate.key_purpose != KeyPurpose.KEY_ENCAPSULATION:
            raise ValidationError(
                f"KEM certificate has invalid purpose: {self.kem_certificate.key_purpose}"
            )
        if self.dsa_certificate.key_purpose != KeyPurpose.DIGITAL_SIGNATURE:
            raise ValidationError(
                f"DSA certificate has invalid purpose: {self.dsa_certificate.key_purpose}"
            )


class WatermarkedDocumentRelease(BaseModel):
    """The only authorized released artifact for a successful decryption event.

    Contains the watermarked PDF and cryptographic evidence of attribution.
    The original unwatermarked plaintext is NOT included and cannot be recovered from this object.
    """
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    watermarked_pdf: bytes = Field(description="Forensically watermarked document bytes")
    signed_event: SignedDecryptionEvent = Field(description="Committed and verified signed event")
    ledger_receipt: LedgerTransactionReceipt = Field(description="Receipt confirming ledger commitment")
    fidelity: FidelityMetrics = Field(description="Fidelity metrics of embedded watermark")
    session_id: SessionID = Field(description="Session identifier for this decryption event")
    watermark_id: WatermarkID = Field(description="Forensic watermark identifier")
    source_document_hash: str = Field(description="SHA3-256 hash of original unwatermarked document")
    rendered_watermarked_artifact_hash: str = Field(description="SHA3-256 hash of released watermarked PDF")

    def save(self, output_path: Path | str) -> Path:
        """Write the watermarked document to disk."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.watermarked_pdf)
        return target


class RecipientAttributionPipeline:
    """Production atomic pipeline for recipient decryption, watermarking, and event registration."""

    @classmethod
    def execute_decryption(
        cls,
        package_input: Union[DistributionPackage, bytes, Path, str],
        credentials: RecipientCredentials,
        ledger: DecryptionEventLedger,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
        watermark_params: Optional[WatermarkParameters] = None,
        device_id: Optional[DeviceID] = None,
    ) -> WatermarkedDocumentRelease:
        """Execute the atomic recipient decryption and attribution pipeline.

        Returns:
            WatermarkedDocumentRelease: Contains only the watermarked document and committed event.

        Raises:
            LedgerCommitRequiredError: If ledger transaction was rejected or commit not confirmed.
            ReleaseGateError: If release gate denies document release.
            SecurityError: If certificate, identity, or envelope checks fail.
            WatermarkError: If watermark embedding fails.
            IntegrityError: If document hash fails.
        """
        # 1. 17-Point Package Validation
        val_result = PackageValidator.validate(package_input)
        if not val_result.valid:
            raise CryptographicError(f"Package validation failed: {val_result.error}")

        if isinstance(package_input, DistributionPackage):
            pkg = package_input
        elif isinstance(package_input, (bytes, bytearray)):
            pkg = DistributionPackage.from_bytes(bytes(package_input))
        else:
            pkg = DistributionPackage.load(package_input)

        # 2. Validate Recipient KEM Certificate against Root CA if available
        if root_ca_public_key is not None:
            CertificateValidator.validate(
                certificate=credentials.kem_certificate,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=revocation_provider,
                expected_purpose=KeyPurpose.KEY_ENCAPSULATION,
            )

        # 3. Locate recipient envelope in package
        envelope: Optional[RecipientEnvelope] = None
        for env in pkg.header.recipient_envelopes:
            if env.recipient_id == credentials.recipient_id:
                envelope = env
                break

        if envelope is None:
            raise SecurityError(
                f"Access Denied: Recipient '{credentials.recipient_id}' is not an authorized recipient."
            )

        if envelope.certificate_serial != credentials.kem_certificate.serial_number:
            raise SecurityError(
                f"Certificate mismatch: Envelope references serial '{envelope.certificate_serial}', "
                f"which differs from recipient KEM certificate '{credentials.kem_certificate.serial_number}'."
            )

        # 4. Decapsulate CEK using recipient KEM private key
        recovered_cek = KeyWrapEngine.unwrap_cek_for_recipient(
            envelope=envelope,
            recipient_sk=credentials.kem_private_key,
            distribution_id=pkg.header.distribution_id,
            key_version=1,
        )

        # Controlled memory buffers for zeroization
        raw_plaintext_buffer: Optional[bytearray] = None
        wm_res: Optional[WatermarkEmbeddingResult] = None
        signed_event: Optional[SignedDecryptionEvent] = None
        receipt: Optional[LedgerTransactionReceipt] = None

        try:
            # 5. Decrypt document payload in memory with AES-256-GCM
            aad_bytes = pkg.header.compute_aad_bytes()
            decrypted_bytes = ContentEncryption.decrypt_document(
                ciphertext=pkg.ciphertext,
                nonce=pkg.nonce,
                auth_tag=pkg.auth_tag,
                cek=recovered_cek,
                aad_bytes=aad_bytes,
            )
            raw_plaintext_buffer = bytearray(decrypted_bytes)

            # 6. Verify Source Document SHA3-256 Hash
            source_doc_hash = DocumentHasher.hash_bytes(raw_plaintext_buffer)
            if source_doc_hash != pkg.header.source_document_hash:
                raise IntegrityError(
                    f"Plaintext hash mismatch: computed '{source_doc_hash}' != "
                    f"header '{pkg.header.source_document_hash}'"
                )

            # 7. Generate fresh, independent 128-bit SessionID and WatermarkID
            session_id = SecureRandom.generate_typed_id(SessionID)
            watermark_id = SecureRandom.generate_typed_id(WatermarkID)
            event_id = SecureRandom.generate_typed_id(EventID)
            anti_replay_nonce = SecureRandom.generate_nonce(16)
            now = utc_now_micros()

            # 8. Check pre-commit duplicate status with ledger
            if ledger.check_duplicate(event_id):
                raise SecurityError(f"Duplicate EventID detected: {event_id}")
            if ledger.check_session(session_id):
                raise SecurityError(f"Duplicate SessionID detected: {session_id}")
            if ledger.check_watermark(watermark_id):
                raise SecurityError(f"Duplicate WatermarkID detected: {watermark_id}")

            # 9. Construct 256-bit WatermarkPayload
            payload = WatermarkPayload.create(
                watermark_id=watermark_id,
                session_id=session_id,
                document_hash=source_doc_hash,
                version=1,
            )

            # 10. Embed forensic watermark into document (in memory)
            try:
                wm_res = WatermarkEmbedder.embed_document(
                    pdf_input=bytes(raw_plaintext_buffer),
                    payload=payload,
                    document_hash=source_doc_hash,
                    params=watermark_params,
                )
            except Exception as e:
                raise WatermarkError(f"Forensic watermark embedding failed: {e}") from e

            # Compute hash of the final rendered watermarked artifact
            rendered_artifact_hash = Hasher.digest_bytes(
                wm_res.watermarked_pdf, HashAlgorithm.SHA3_256.value
            ).formatted

            # 11. Construct canonical DecryptionEvent
            active_dev_id = device_id or credentials.device_id
            decryption_event = DecryptionEvent(
                event_version="1.0.0",
                schema_version="1.0.0",
                protocol_version="1.0.0",
                software_version="1.0.0",
                event_type="DECRYPTION_ATTRIBUTION",
                event_id=event_id,
                document_id=pkg.header.document_id,
                distribution_id=pkg.header.distribution_id,
                document_hash=source_doc_hash,
                recipient_id=credentials.recipient_id,
                recipient_key_id=f"key-{credentials.recipient_id}-dsa-v1",
                recipient_certificate_id=credentials.dsa_certificate.serial_number,
                device_id=active_dev_id,
                session_id=session_id,
                watermark_id=watermark_id,
                watermark_version=payload.version,
                anti_replay_nonce=anti_replay_nonce,
                timestamp=now,
                rendered_watermarked_artifact_hash=rendered_artifact_hash,
                pqc_algorithms=PQCAlgorithms(
                    kem="ML-KEM-768",
                    dsa="ML-DSA-65",
                    hash="SHA3-256",
                ),
            )

            # 12. Sign canonical event with recipient's ML-DSA-65 private key
            signed_event = DecryptionEventSigner.sign_event(
                event=decryption_event,
                signing_key=credentials.dsa_private_key,
                signing_cert=credentials.dsa_certificate,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=revocation_provider,
                signing_key_id=f"key-{credentials.recipient_id}-dsa-v1",
            )

            # 13. Submit signed event to ledger interface
            receipt = ledger.submit_event(signed_event)
            if receipt.is_committed and receipt.transaction_id:
                signed_event = signed_event.with_transaction_id(receipt.transaction_id)

            # 14. Centralized Release Gate Evaluation
            DocumentReleaseGate.assert_release_allowed(
                watermark_result=wm_res,
                signed_event=signed_event,
                ledger_receipt=receipt,
                recipient_certificate=credentials.dsa_certificate,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=revocation_provider,
                expected_document_hash=source_doc_hash,
            )

            # 15. Return ONLY the watermarked release container
            return WatermarkedDocumentRelease(
                watermarked_pdf=wm_res.watermarked_pdf,
                signed_event=signed_event,
                ledger_receipt=receipt,
                fidelity=wm_res.fidelity,
                session_id=session_id,
                watermark_id=watermark_id,
                source_document_hash=source_doc_hash,
                rendered_watermarked_artifact_hash=rendered_artifact_hash,
            )

        finally:
            # Zeroize recovered CEK
            for i in range(len(recovered_cek)):
                recovered_cek[i] = 0

            # Zeroize raw plaintext memory buffer
            if raw_plaintext_buffer is not None:
                for i in range(len(raw_plaintext_buffer)):
                    raw_plaintext_buffer[i] = 0
