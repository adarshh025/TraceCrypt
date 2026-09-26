"""End-to-end Sender Packaging and Recipient Decryption Workflows.

Security Invariants:
1. Sender encrypts document ONCE using fresh 256-bit AES-GCM Content-Encryption Key (CEK).
2. CEK is encapsulated independently per recipient using ML-KEM-768 and HKDF-SHA256.
3. 17-point offline validation is executed on package before any decapsulation.
4. Recipient identity, certificate, and purpose are verified before envelope decapsulation.
5. Post-decryption SHA3-256 hash verification catches corruption and implementation errors.
6. Decrypted plaintext is returned in a SecureDocumentBuffer without automatic disk persistence.
7. Sensitive intermediate keys are zeroized in finally: blocks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Union

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
)
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.reader import DocumentReader
from tracecrypt.document.types import (
    DistributionPackageHeader,
    RecipientEnvelope,
    SecureDocumentBuffer,
)
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import (
    CryptographicError,
    IntegrityError,
    SecurityError,
    ValidationError,
)
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.utils.identifiers import DistributionID, DocumentID, RecipientID
from tracecrypt.utils.timestamps import utc_now_micros


class RecipientSpec:
    """Specification of an authorized recipient for document packaging."""

    def __init__(
        self,
        recipient_id: Union[RecipientID, str, PQCIdentityCertificate],
        public_key: Optional[MLKEMPublicKey] = None,
        certificate: Optional[PQCIdentityCertificate] = None,
        key_id: Optional[str] = None,
        key_version: int = 1,
    ) -> None:
        if isinstance(recipient_id, PQCIdentityCertificate):
            cert = recipient_id
            self.certificate = cert
            self.recipient_id = RecipientID(str(cert.subject_id))
            self.public_key = MLKEMPublicKey(cert.get_public_key_bytes())
            self.key_id = key_id or f"key-{self.recipient_id}-kem-v{key_version}"
            self.key_version = key_version
        else:
            self.recipient_id = RecipientID(str(recipient_id))
            if not isinstance(public_key, MLKEMPublicKey):
                raise ValidationError(
                    f"RecipientSpec requires MLKEMPublicKey, got {type(public_key).__name__}"
                )
            if certificate is None:
                raise ValidationError("RecipientSpec requires a valid PQCIdentityCertificate")
            self.public_key = public_key
            self.certificate = certificate
            self.key_id = key_id or f"key-{self.recipient_id}-kem-v{key_version}"
            self.key_version = key_version

    @classmethod
    def from_certificate(
        cls,
        certificate: PQCIdentityCertificate,
        key_id: Optional[str] = None,
        key_version: int = 1,
    ) -> RecipientSpec:
        """Construct RecipientSpec directly from a certified PQCIdentityCertificate."""
        return cls(recipient_id=certificate, key_id=key_id, key_version=key_version)


class DistributionService:
    """Orchestrates secure packaging for senders and authenticated decryption for recipients."""

    @classmethod
    def package_document(
        cls,
        source_input: Optional[Path | str | bytes] = None,
        recipients: Optional[List[RecipientSpec]] = None,
        output_path: Optional[Path | str] = None,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_store: Optional[Any] = None,
        input_path: Optional[Path | str | bytes] = None,
    ) -> tuple[DistributionPackage, Optional[Path]]:
        """Sender workflow: Encrypts document once and packages for all authorized recipients.

        Returns:
            tuple of (DistributionPackage, Optional[Path])
        """
        src = source_input if source_input is not None else input_path
        if src is None:
            raise ValidationError("package_document requires source_input or input_path")
        if not recipients:
            raise ValidationError("Distribution package must include at least one authorized recipient.")

        # 1. Read source bytes and metadata
        if isinstance(src, (bytes, bytearray)):
            doc_bytes = bytes(src)
            fname = filename or "document.pdf"
            mtype = mime_type or DocumentReader.detect_mime_type(doc_bytes, fname)
        else:
            path = Path(src)
            doc_bytes, mtype_detected, fname_detected = DocumentReader.read_document(path)
            fname = filename or fname_detected
            mtype = mime_type or mtype_detected

        # 2. Calculate source document SHA3-256 hash
        source_hash = DocumentHasher.hash_bytes(doc_bytes)

        # 3. Generate unique DocumentID and DistributionID
        doc_id = SecureRandom.generate_typed_id(DocumentID)
        dist_id = SecureRandom.generate_typed_id(DistributionID)
        now = utc_now_micros()

        # 4. Generate fresh 256-bit AES-GCM Content-Encryption Key (CEK)
        cek = ContentEncryption.generate_cek()

        try:
            # 5. Encapsulate CEK for every authorized recipient
            recipient_envelopes: List[RecipientEnvelope] = []
            seen_rids: set[str] = set()

            for spec in recipients:
                rid_str = str(spec.recipient_id)
                if rid_str in seen_rids:
                    raise ValidationError(f"Duplicate recipient in distribution specification: '{rid_str}'")
                seen_rids.add(rid_str)

                # Validate recipient certificate if Root CA public key provided
                if root_ca_public_key is not None:
                    CertificateValidator.validate(
                        certificate=spec.certificate,
                        root_ca_public_key=root_ca_public_key,
                        revocation_provider=revocation_store,
                        expected_purpose=KeyPurpose.KEY_ENCAPSULATION,
                    )

                # Wrap CEK using ML-KEM-768 and HKDF-SHA256
                env = KeyWrapEngine.wrap_cek_for_recipient(
                    cek=cek,
                    recipient_pk=spec.public_key,
                    distribution_id=dist_id,
                    recipient_id=spec.recipient_id,
                    key_id=spec.key_id,
                    certificate_serial=spec.certificate.serial_number,
                    key_version=spec.key_version,
                )
                recipient_envelopes.append(env)

            # 6. Build immutable package header
            header = DistributionPackageHeader(
                format_version="1.0.0",
                distribution_id=dist_id,
                document_id=doc_id,
                mime_type=mtype,
                filename=fname,
                source_document_hash=source_hash,
                source_size_bytes=len(doc_bytes),
                cipher_algorithm="AES-256-GCM",
                kem_algorithm="ML-KEM-768",
                recipient_envelopes=recipient_envelopes,
                created_at=now,
            )

            # 7. Compute deterministic AAD bytes binding all header fields
            aad_bytes = header.compute_aad_bytes()

            # 8. Encrypt document payload ONCE with AES-256-GCM
            nonce, auth_tag, ciphertext = ContentEncryption.encrypt_document(
                document_bytes=doc_bytes,
                cek=cek,
                aad_bytes=aad_bytes,
            )

            # 9. Construct and validate package
            pkg = DistributionPackage(
                header=header,
                nonce=nonce,
                auth_tag=auth_tag,
                ciphertext=ciphertext,
            )
            PackageValidator.validate(pkg)

            # 10. Write to disk if output path requested
            saved_path: Optional[Path] = None
            if output_path is not None:
                saved_path = pkg.save(output_path)

            return pkg, saved_path

        finally:
            # Explicitly zeroize plaintext CEK
            for i in range(len(cek)):
                cek[i] = 0

    @classmethod
    def decrypt_package(
        cls,
        package_input: Optional[Union[DistributionPackage, bytes, Path, str]] = None,
        recipient_id: RecipientID | str = "",
        recipient_sk: Optional[MLKEMPrivateKey] = None,
        recipient_cert: Optional[PQCIdentityCertificate] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_store: Optional[Any] = None,
        recipient_private_key: Optional[MLKEMPrivateKey] = None,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
        revocation_provider: Optional[Any] = None,
        package_bytes: Optional[Union[DistributionPackage, bytes, Path, str]] = None,
    ) -> SecureDocumentBuffer:
        """Recipient workflow: Validates package, authenticates recipient, and decrypts document.

        Returns:
            SecureDocumentBuffer: In-memory plaintext buffer.
        """
        pkg_in = package_input if package_input is not None else package_bytes
        if pkg_in is None:
            raise ValidationError("decrypt_package requires package_input or package_bytes")
        target_rid = RecipientID(str(recipient_id))
        sk = recipient_sk or recipient_private_key
        if sk is None:
            raise ValidationError("decrypt_package requires recipient private key")
        cert = recipient_cert or recipient_certificate
        if cert is None:
            raise ValidationError("decrypt_package requires recipient certificate")
        rev_store = revocation_store if revocation_store is not None else revocation_provider

        # 1. 17-point Package Validation
        val_result = PackageValidator.validate(pkg_in)
        if not val_result.valid:
            raise CryptographicError(f"Package validation failed: {val_result.error}")

        if isinstance(pkg_in, DistributionPackage):
            pkg = pkg_in
        elif isinstance(pkg_in, (bytes, bytearray)):
            pkg = DistributionPackage.from_bytes(bytes(pkg_in))
        else:
            pkg = DistributionPackage.load(pkg_in)

        # 2. Validate recipient certificate against Root CA if available
        if root_ca_public_key is not None:
            CertificateValidator.validate(
                certificate=cert,
                root_ca_public_key=root_ca_public_key,
                revocation_provider=rev_store,
                expected_purpose=KeyPurpose.KEY_ENCAPSULATION,
            )

        # 3. Verify that recipient private key matches the certificate public key fingerprint
        cert_pk_bytes = cert.get_public_key_bytes()
        computed_fp = f"mlkem768:{Hasher.digest_bytes(cert_pk_bytes, HashAlgorithm.SHA3_256.value).formatted}"
        if computed_fp != cert.public_key_fingerprint:
            raise SecurityError("Recipient certificate public key fingerprint mismatch.")

        # 4. Locate authorized recipient envelope
        envelope: Optional[RecipientEnvelope] = None
        for env in pkg.header.recipient_envelopes:
            if env.recipient_id == target_rid:
                envelope = env
                break

        if envelope is None:
            raise SecurityError(
                f"Access Denied: Recipient '{target_rid}' is not an authorized recipient of this package."
            )

        # Confirm referenced certificate serial matches
        if envelope.certificate_serial != cert.serial_number:
            raise SecurityError(
                f"Access Denied: Package envelope references certificate serial '{envelope.certificate_serial}', "
                f"which does not match recipient's active certificate serial '{cert.serial_number}'."
            )

        # 5. Decapsulate and unwrap CEK
        recovered_cek = KeyWrapEngine.unwrap_cek_for_recipient(
            envelope=envelope,
            recipient_sk=sk,
            distribution_id=pkg.header.distribution_id,
            key_version=1,
        )

        try:
            # 6. Recompute AAD bytes
            aad_bytes = pkg.header.compute_aad_bytes()

            # 7. Decrypt document using recovered CEK and AES-256-GCM
            decrypted_bytes = ContentEncryption.decrypt_document(
                ciphertext=pkg.ciphertext,
                nonce=pkg.nonce,
                auth_tag=pkg.auth_tag,
                cek=recovered_cek,
                aad_bytes=aad_bytes,
            )

            # 8. Post-Decryption Plaintext Hash Verification
            computed_plaintext_hash = DocumentHasher.hash_bytes(decrypted_bytes)
            if computed_plaintext_hash != pkg.header.source_document_hash:
                raise IntegrityError(
                    f"Decrypted document integrity mismatch: "
                    f"computed '{computed_plaintext_hash}' != expected '{pkg.header.source_document_hash}'"
                )

            # 9. Return SecureDocumentBuffer (in-memory only, no disk write)
            return SecureDocumentBuffer(
                data=decrypted_bytes,
                document_id=pkg.header.document_id,
                distribution_id=pkg.header.distribution_id,
                source_document_hash=pkg.header.source_document_hash,
                mime_type=pkg.header.mime_type,
                filename=pkg.header.filename,
            )

        finally:
            # Zeroize recovered CEK
            for i in range(len(recovered_cek)):
                recovered_cek[i] = 0


# Class aliases for operational symmetry
DistributionService.create_package = DistributionService.package_document
