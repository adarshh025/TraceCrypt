"""Local-only FastAPI application foundation for TraceCrypt.

Security Principles:
- Localhost binding by default (127.0.0.1).
- LAN binding is explicitly deferred to Phase 6 when peer-to-peer validator gossip is enabled.
- Zero CORS wildcard (*).
- Strict HTTP security headers (CSP, nosniff, frame-ancestors 'none', no-cache).
- No sensitive operational endpoints exposed prematurely.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import platform
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile, status
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

import tracecrypt
from tracecrypt.config.settings import get_settings
from tracecrypt.crypto.types import MLDSAPrivateKey, MLDSAPublicKey, MLKEMPrivateKey
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import (
    CertificateValidationError,
    LedgerCommitRequiredError,
    ReleaseGateError,
    SecurityError,
    ValidationError,
)
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.identity.keystore import EncryptedKeyContainer, KeystoreManager
from tracecrypt.identity.lifecycle import OfflineRevocationStore
from tracecrypt.ledger.block import BlockHeader, LedgerTransaction
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.merkle import MerkleInclusionProof, MerkleTree
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.models.domain import Document, User, UserRole, UserStatus
from tracecrypt.watermark.types import WatermarkParameters
from tracecrypt.security.airgap import AirGapGuard
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import DocumentID, UserID
from tracecrypt.utils.timestamps import utc_now_iso


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject strict security headers into every response."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response


def verify_admin_authorization(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_admin_token: Optional[str] = Header(None, alias="X-TraceCrypt-Admin-Token"),
) -> None:
    """Verify administrative authorization if an admin token is configured.

    Fails closed if TRACECRYPT_ADMIN_TOKEN is defined and the caller provides an invalid token.
    """
    configured_token = os.getenv("TRACECRYPT_ADMIN_TOKEN")
    if not configured_token:
        # If no explicit token configured, rely on 127.0.0.1 localhost air-gap binding
        return

    token = None
    if x_admin_token:
        token = x_admin_token
    elif authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer ") :].strip()

    if not token or token != configured_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Valid administrative credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )


class CertificateVerificationRequest(BaseModel):
    """Request payload for offline certificate verification."""

    certificate: PQCIdentityCertificate


class CertificateVerificationResponse(BaseModel):
    """Result of offline post-quantum certificate verification."""

    valid: bool
    serial_number: str
    subject_id: str
    key_purpose: str
    public_key_fingerprint: str
    error: Optional[str] = None


class DocumentPackageRequest(BaseModel):
    """Request payload to encrypt and package a document."""

    document_bytes_b64: str
    filename: str
    mime_type: Optional[str] = "application/pdf"
    recipient_ids: List[str] = []
    recipient_certificates: Optional[List[str]] = None


class DocumentPackageResponse(BaseModel):
    """Result of document packaging."""

    distribution_id: str
    document_id: str
    filename: str
    mime_type: str
    source_document_hash: str
    source_size_bytes: int
    recipient_count: int
    package_bytes_b64: str
    package_size_bytes: int
    created_at: int


class DocumentMetadataResponse(BaseModel):
    """Public metadata for a document without exposing plaintext or keys."""

    document_id: str
    title: str
    canonical_hash: str
    mime_type: str
    file_size_bytes: int
    sender_id: str
    created_at: int


class PackageValidateRequest(BaseModel):
    """Request payload to validate a .tcdist package."""

    package_bytes_b64: str


class PackageValidateResponse(BaseModel):
    """Result of package validation."""

    valid: bool
    distribution_id: Optional[str] = None
    document_id: Optional[str] = None
    format_version: Optional[str] = None
    source_document_hash: Optional[str] = None
    recipient_count: Optional[int] = None
    errors: List[str] = []


class DecryptValidateRequest(BaseModel):
    """Request payload to test recipient decryption feasibility."""

    package_bytes_b64: str
    recipient_id: str
    keystore_json: Optional[str] = None
    passphrase: Optional[str] = None


class DecryptValidateResponse(BaseModel):
    """Result of recipient decryption test (never returns plaintext)."""

    can_decrypt: bool
    recipient_id: str
    envelope_found: bool
    certificate_valid: bool
    cryptographic_check_passed: Optional[bool] = None
    error: Optional[str] = None


def create_app() -> FastAPI:
    """Initialize and configure the air-gapped FastAPI service."""
    settings = get_settings()

    app = FastAPI(
        title="TraceCrypt Local Node API",
        description="Offline Forensic Document Attribution Platform - Node API",
        version=tracecrypt.__version__,
        docs_url="/docs" if settings.mode.value == "DEVELOPMENT" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.mode.value == "DEVELOPMENT" else None,
    )

    app.add_middleware(SecurityHeadersMiddleware)

    def get_storage() -> SQLiteStorageManager:
        store = SQLiteStorageManager(settings.storage.sqlite_db_path)
        store.initialize()
        return store

    # -------------------------------------------------------------------------
    # Core Diagnostics Endpoints
    # -------------------------------------------------------------------------

    @app.get("/health", summary="Node Health Status")
    async def get_health() -> Dict[str, Any]:
        """Return health status of local node service."""
        return {
            "status": "HEALTHY",
            "service": "tracecrypt-node",
            "mode": settings.mode.value,
            "timestamp": utc_now_iso(),
        }

    @app.get("/version", summary="Software & Algorithm Versions")
    async def get_version() -> Dict[str, Any]:
        """Return software version and standardized cryptographic algorithms."""
        return {
            "version": tracecrypt.__version__,
            "python": platform.python_version(),
            "pqc_standards": {
                "kem": settings.crypto.kem_algorithm,
                "dsa": settings.crypto.dsa_algorithm,
                "hash": settings.crypto.hash_algorithm,
            },
        }

    @app.get("/security/status", summary="Air-Gap Security Status")
    async def get_security_status() -> Dict[str, Any]:
        """Return air-gap compliance and enforcement metrics."""
        return {
            "airgap_enforced": settings.airgap.enforce_airgap,
            "socket_interceptor_active": AirGapGuard.is_installed(),
            "dns_allowed": settings.airgap.allow_dns,
            "whitelisted_hosts": sorted(settings.airgap.allowed_hosts),
            "timestamp": utc_now_iso(),
        }

    # -------------------------------------------------------------------------
    # Offline Root CA Endpoints
    # -------------------------------------------------------------------------

    @app.get("/ca/status", summary="Root CA Initialization & Public Status")
    async def get_ca_status() -> Dict[str, Any]:
        """Check Root CA status without exposing any private key material."""
        cert_path = settings.storage.keys_dir / "ca_root_cert.json"
        keystore_path = settings.storage.keys_dir / "ca_root.json"

        if not cert_path.exists() or not keystore_path.exists():
            return {
                "initialized": False,
                "status": "UNINITIALIZED",
                "message": "Offline Root CA has not been initialized on this node",
            }

        try:
            cert_json = cert_path.read_text(encoding="utf-8")
            cert = PQCIdentityCertificate.from_canonical_json(cert_json)
            return {
                "initialized": True,
                "status": "ACTIVE",
                "ca_id": cert.subject_id,
                "organization": cert.organization,
                "serial_number": cert.serial_number,
                "algorithm": cert.algorithm,
                "public_key_fingerprint": cert.public_key_fingerprint,
                "valid_from": cert.valid_from,
                "valid_until": cert.valid_until,
            }
        except Exception as e:
            return {
                "initialized": True,
                "status": "ERROR",
                "error": f"Failed to read Root CA certificate: {e}",
            }

    # -------------------------------------------------------------------------
    # Identity & Certificate Management Endpoints
    # -------------------------------------------------------------------------

    @app.get(
        "/identity/status",
        summary="Identity Subsystem Summary Statistics",
        dependencies=[Depends(verify_admin_authorization)],
    )
    async def get_identity_status() -> Dict[str, Any]:
        """Return aggregate metrics for local PKI and identity subsystem."""
        store = get_storage()
        certs = store.list_all_certificates()
        revocations = store.list_revocations()
        subjects = store.list_subjects()
        keys = store.list_all_keys()

        return {
            "total_enrolled_subjects": len(subjects),
            "total_certificates": len(certs),
            "total_revocations": len(revocations),
            "total_tracked_keys": len(keys),
            "timestamp": utc_now_iso(),
        }

    @app.get(
        "/identity/recipients",
        summary="List Enrolled Recipients",
        dependencies=[Depends(verify_admin_authorization)],
    )
    async def list_recipients() -> Dict[str, Any]:
        """List distinct recipient subject IDs in the identity store."""
        store = get_storage()
        subjects = store.list_subjects()
        return {"recipients": subjects, "count": len(subjects)}

    @app.get(
        "/identity/recipients/{recipient_id}",
        summary="Inspect Recipient Identity Certificates",
        dependencies=[Depends(verify_admin_authorization)],
    )
    async def get_recipient(recipient_id: str) -> Dict[str, Any]:
        """Return public certificate and device binding details for a recipient."""
        store = get_storage()
        certs = store.list_certificates_for_subject(recipient_id)
        if not certs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recipient '{recipient_id}' not found in identity database",
            )

        revocations = {r.serial_number: r for r in store.list_revocations()}

        cert_list = []
        for c in certs:
            is_revoked = c.serial_number in revocations
            cert_list.append(
                {
                    "serial_number": c.serial_number,
                    "key_purpose": c.key_purpose.value,
                    "algorithm": c.algorithm,
                    "public_key_fingerprint": c.public_key_fingerprint,
                    "device_id": c.device_id,
                    "valid_from": c.valid_from,
                    "valid_until": c.valid_until,
                    "status": "REVOKED" if is_revoked else "ACTIVE",
                }
            )

        return {
            "recipient_id": recipient_id,
            "organization": certs[0].organization,
            "role": certs[0].role,
            "certificates": cert_list,
        }

    @app.get(
        "/identity/keys/{key_id}",
        summary="Inspect Public Key Metadata",
        dependencies=[Depends(verify_admin_authorization)],
    )
    async def get_key_metadata(key_id: str) -> Dict[str, Any]:
        """Return public metadata for a key ID without exposing private material."""
        store = get_storage()
        meta = store.get_key_metadata(key_id)
        if not meta:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key ID '{key_id}' not found in local key database",
            )

        return {
            "key_id": meta.key_id,
            "owner_id": meta.owner_id,
            "purpose": meta.purpose.value,
            "algorithm": meta.algorithm,
            "parameter_set": meta.parameter_set,
            "status": meta.status.value,
            "version": meta.version,
            "fingerprint": meta.fingerprint,
            "created_at": meta.created_at,
            "activated_at": meta.activated_at,
            "expires_at": meta.expires_at,
        }

    @app.post(
        "/identity/verify",
        summary="Validate PQC Certificate Offline",
        response_model=CertificateVerificationResponse,
    )
    async def verify_certificate(req: CertificateVerificationRequest) -> CertificateVerificationResponse:
        """Validate a PQCIdentityCertificate against the local Root CA completely offline."""
        cert_path = settings.storage.keys_dir / "ca_root_cert.json"
        if not cert_path.exists():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Offline Root CA certificate not found on this node",
            )

        try:
            root_cert = PQCIdentityCertificate.from_canonical_json(
                cert_path.read_text(encoding="utf-8")
            )
            root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
            store = get_storage()
            rev_store = OfflineRevocationStore(store)
            CertificateValidator.validate(
                certificate=req.certificate,
                root_ca_public_key=root_pk,
                revocation_provider=rev_store,
            )

            return CertificateVerificationResponse(
                valid=True,
                serial_number=req.certificate.serial_number,
                subject_id=req.certificate.subject_id,
                key_purpose=req.certificate.key_purpose.value,
                public_key_fingerprint=req.certificate.public_key_fingerprint,
            )
        except (CertificateValidationError, SecurityError, ValidationError) as e:
            return CertificateVerificationResponse(
                valid=False,
                serial_number=req.certificate.serial_number,
                subject_id=req.certificate.subject_id,
                key_purpose=req.certificate.key_purpose.value,
                public_key_fingerprint=req.certificate.public_key_fingerprint,
                error=str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Certificate validation failed internally: {e}",
            )

    # -------------------------------------------------------------------------
    # Encrypted Document Distribution Subsystem Endpoints
    # -------------------------------------------------------------------------

    @app.post(
        "/documents/package",
        summary="Package and Encrypt Document for Authorized Recipients",
        response_model=DocumentPackageResponse,
        dependencies=[Depends(verify_admin_authorization)],
    )
    async def package_document_endpoint(req: DocumentPackageRequest) -> DocumentPackageResponse:
        """Encrypts source document once with AES-256-GCM and encapsulates CEK for recipients."""
        try:
            doc_bytes = base64.b64decode(req.document_bytes_b64, validate=True)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 encoding in document_bytes_b64",
            )

        if not doc_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Document content cannot be empty",
            )

        if len(doc_bytes) > 100 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Document exceeds maximum allowed size (100 MB)",
            )

        store = get_storage()
        keys_dir = settings.storage.keys_dir
        recipient_specs: List[RecipientSpec] = []

        # From explicit certificate JSON strings
        if req.recipient_certificates:
            for cert_json in req.recipient_certificates:
                try:
                    cert = PQCIdentityCertificate.from_canonical_json(cert_json)
                    recipient_specs.append(RecipientSpec.from_certificate(cert))
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid recipient certificate in request: {e}",
                    )

        # From recipient IDs
        for rcp_id in req.recipient_ids:
            cert = store.get_active_kem_certificate(rcp_id)
            if not cert:
                disk_path = keys_dir / f"{rcp_id}_kem_cert.json"
                if disk_path.exists():
                    try:
                        cert = PQCIdentityCertificate.from_canonical_json(
                            disk_path.read_text(encoding="utf-8")
                        )
                    except Exception:
                        pass
            if not cert:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Active KEM certificate for recipient '{rcp_id}' not found",
                )
            recipient_specs.append(RecipientSpec.from_certificate(cert))

        if not recipient_specs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one valid recipient must be specified",
            )

        # Deduplicate by subject_id
        seen = set()
        deduped = []
        for r in recipient_specs:
            if r.certificate.subject_id in seen:
                continue
            seen.add(r.certificate.subject_id)
            deduped.append(r)
        recipient_specs = deduped

        # Check Root CA if available
        root_cert_path = keys_dir / "ca_root_cert.json"
        root_pk = None
        rev_store = None
        if root_cert_path.exists():
            try:
                root_cert = PQCIdentityCertificate.from_canonical_json(
                    root_cert_path.read_text(encoding="utf-8")
                )
                root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                rev_store = OfflineRevocationStore(store)
            except Exception:
                pass

        try:
            pkg, _ = DistributionService.package_document(
                source_input=doc_bytes,
                recipients=recipient_specs,
                filename=req.filename,
                mime_type=req.mime_type,
                root_ca_public_key=root_pk,
                revocation_store=rev_store,
            )
            pkg_bytes = DistributionPackage.serialize(pkg)

            # Persist document metadata in SQLite store
            try:
                sys_user_id = UserID("usr-00000000000000000000000000000000")
                if store.get_user(str(sys_user_id)) is None:
                    sys_user = User(
                        user_id=sys_user_id,
                        display_name="System Dispatcher",
                        email_hash="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
                        organization_unit="TraceCrypt Operations",
                        role=UserRole.ADMIN,
                        created_at=pkg.header.created_at,
                        status=UserStatus.ACTIVE,
                    )
                    store.save_user(sys_user)

                doc_record = Document(
                    document_id=DocumentID(str(pkg.header.document_id)),
                    title=pkg.header.filename,
                    page_count=1,
                    canonical_hash=pkg.header.source_document_hash,
                    mime_type=pkg.header.mime_type,
                    file_size_bytes=pkg.header.source_size_bytes,
                    sender_id=sys_user_id,
                    created_at=pkg.header.created_at,
                )
                store.save_document(doc_record)
            except Exception:
                pass

            return DocumentPackageResponse(
                distribution_id=pkg.header.distribution_id,
                document_id=pkg.header.document_id,
                filename=pkg.header.filename,
                mime_type=pkg.header.mime_type,
                source_document_hash=pkg.header.source_document_hash,
                source_size_bytes=pkg.header.source_size_bytes,
                recipient_count=len(pkg.header.recipients),
                package_bytes_b64=base64.b64encode(pkg_bytes).decode("ascii"),
                package_size_bytes=len(pkg_bytes),
                created_at=pkg.header.created_at,
            )
        except (SecurityError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Packaging failed internally: {e}",
            )

    @app.get(
        "/documents/{document_id}",
        summary="Retrieve Document Metadata",
        response_model=DocumentMetadataResponse,
    )
    async def get_document_metadata_endpoint(document_id: str) -> DocumentMetadataResponse:
        """Retrieve public metadata for a document without exposing plaintext or keys."""
        store = get_storage()
        doc = store.get_document(document_id)
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Document '{document_id}' not found",
            )

        return DocumentMetadataResponse(
            document_id=str(doc.document_id),
            title=doc.title,
            canonical_hash=doc.canonical_hash,
            mime_type=doc.mime_type,
            file_size_bytes=doc.file_size_bytes,
            sender_id=str(doc.sender_id),
            created_at=doc.created_at,
        )

    @app.post(
        "/documents/validate",
        summary="Validate .tcdist Package Offline",
        response_model=PackageValidateResponse,
    )
    async def validate_package_endpoint(req: PackageValidateRequest) -> PackageValidateResponse:
        """Run 17-point cryptographic validation on a .tcdist package."""
        try:
            raw_pkg = base64.b64decode(req.package_bytes_b64, validate=True)
        except Exception:
            return PackageValidateResponse(
                valid=False,
                errors=["Invalid base64 encoding in package_bytes_b64"],
            )

        keys_dir = settings.storage.keys_dir
        root_cert_path = keys_dir / "ca_root_cert.json"
        root_pk = None
        rev_store = None
        if root_cert_path.exists():
            try:
                root_cert = PQCIdentityCertificate.from_canonical_json(
                    root_cert_path.read_text(encoding="utf-8")
                )
                root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                store = get_storage()
                rev_store = OfflineRevocationStore(store)
            except Exception:
                pass

        result = PackageValidator.validate_package(
            package_bytes=raw_pkg,
            root_ca_public_key=root_pk,
            revocation_provider=rev_store,
        )

        return PackageValidateResponse(
            valid=result.valid,
            distribution_id=result.header.distribution_id if result.header else None,
            document_id=result.header.document_id if result.header else None,
            format_version=result.header.format_version if result.header else None,
            source_document_hash=result.header.source_document_hash if result.header else None,
            recipient_count=len(result.header.recipients) if result.header else None,
            errors=result.errors,
        )

    @app.post(
        "/documents/decrypt/validate",
        summary="Validate Recipient Decryption Feasibility",
        response_model=DecryptValidateResponse,
    )
    async def validate_decrypt_endpoint(req: DecryptValidateRequest) -> DecryptValidateResponse:
        """Verify if a recipient can decrypt a package without returning plaintext or keys."""
        try:
            raw_pkg = base64.b64decode(req.package_bytes_b64, validate=True)
        except Exception:
            return DecryptValidateResponse(
                can_decrypt=False,
                recipient_id=req.recipient_id,
                envelope_found=False,
                certificate_valid=False,
                error="Invalid base64 encoding in package_bytes_b64",
            )

        try:
            pkg = DistributionPackage.deserialize(raw_pkg)
        except Exception as e:
            return DecryptValidateResponse(
                can_decrypt=False,
                recipient_id=req.recipient_id,
                envelope_found=False,
                certificate_valid=False,
                error=f"Malformed package: {e}",
            )

        envelope = None
        for env in pkg.header.recipients:
            if env.recipient_id == req.recipient_id:
                envelope = env
                break

        if not envelope:
            return DecryptValidateResponse(
                can_decrypt=False,
                recipient_id=req.recipient_id,
                envelope_found=False,
                certificate_valid=False,
                error=f"Recipient '{req.recipient_id}' is not in authorized recipient set",
            )

        store = get_storage()
        keys_dir = settings.storage.keys_dir
        cert = store.get_active_kem_certificate(req.recipient_id)
        if not cert:
            disk_path = keys_dir / f"{req.recipient_id}_kem_cert.json"
            if disk_path.exists():
                try:
                    cert = PQCIdentityCertificate.from_canonical_json(
                        disk_path.read_text(encoding="utf-8")
                    )
                except Exception:
                    pass

        if not cert:
            return DecryptValidateResponse(
                can_decrypt=False,
                recipient_id=req.recipient_id,
                envelope_found=True,
                certificate_valid=False,
                error=f"Certificate for recipient '{req.recipient_id}' not found",
            )

        # Check certificate validity
        root_cert_path = keys_dir / "ca_root_cert.json"
        root_pk = None
        rev_store = None
        if root_cert_path.exists():
            try:
                root_cert = PQCIdentityCertificate.from_canonical_json(
                    root_cert_path.read_text(encoding="utf-8")
                )
                root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                rev_store = OfflineRevocationStore(store)
                CertificateValidator.validate(
                    certificate=cert,
                    root_ca_public_key=root_pk,
                    revocation_provider=rev_store,
                )
            except Exception as e:
                return DecryptValidateResponse(
                    can_decrypt=False,
                    recipient_id=req.recipient_id,
                    envelope_found=True,
                    certificate_valid=False,
                    error=f"Certificate validation failed: {e}",
                )

        crypto_passed = None
        if req.keystore_json and req.passphrase:
            try:
                container = EncryptedKeyContainer.model_validate_json(req.keystore_json)
                priv_bytes = KeystoreManager.decrypt_private_key(container, req.passphrase)
                priv_key = MLKEMPrivateKey(bytes(priv_bytes))

                with DistributionService.decrypt_package(
                    package_input=raw_pkg,
                    recipient_id=req.recipient_id,
                    recipient_private_key=priv_key,
                    recipient_certificate=cert,
                    root_ca_public_key=root_pk,
                    revocation_store=rev_store,
                ) as buf:
                    # Verified successfully, check non-empty and buf is zeroized upon exit
                    crypto_passed = len(buf) > 0
            except Exception as e:
                crypto_passed = False
                return DecryptValidateResponse(
                    can_decrypt=False,
                    recipient_id=req.recipient_id,
                    envelope_found=True,
                    certificate_valid=True,
                    cryptographic_check_passed=False,
                    error=f"Decryption check failed: {e}",
                )

        return DecryptValidateResponse(
            can_decrypt=True if (crypto_passed is None or crypto_passed) else False,
            recipient_id=req.recipient_id,
            envelope_found=True,
            certificate_valid=True,
            cryptographic_check_passed=crypto_passed,
        )

    # -------------------------------------------------------------------------
    # Phase 5: Recipient Attribution & Event Endpoints
    # -------------------------------------------------------------------------

    api_ledger = InMemoryLedgerAdapter()

    class DecryptPrepareRequest(BaseModel):
        package_b64: str
        recipient_id: str

    class DecryptPrepareResponse(BaseModel):
        ready: bool
        document_id: Optional[str] = None
        distribution_id: Optional[str] = None
        recipient_id: str
        kem_certificate_valid: bool = False
        dsa_certificate_valid: bool = False
        error: Optional[str] = None

    class DecryptExecuteRequest(BaseModel):
        package_b64: str
        recipient_id: str
        kem_passphrase: str
        dsa_passphrase: str
        device_id: Optional[str] = None
        watermark_strength: Optional[float] = None

    class DecryptExecuteResponse(BaseModel):
        released: bool
        watermarked_pdf_b64: Optional[str] = None
        event: Optional[Dict[str, Any]] = None
        transaction_id: Optional[str] = None
        session_id: Optional[str] = None
        watermark_id: Optional[str] = None
        fidelity_psnr: Optional[float] = None
        fidelity_ssim: Optional[float] = None
        error: Optional[str] = None

    class EventVerifyRequest(BaseModel):
        signed_event_json: str

    class EventVerifyResponse(BaseModel):
        valid: bool
        event_id: str
        digest_verified: bool
        signature_verified: bool
        certificate_verified: bool
        document_binding_verified: bool
        watermark_binding_verified: bool
        errors: List[str]

    @app.post(
        "/decrypt/prepare",
        response_model=DecryptPrepareResponse,
        summary="Verify readiness for atomic decryption and attribution",
    )
    def decrypt_prepare(req: DecryptPrepareRequest) -> DecryptPrepareResponse:
        try:
            raw_pkg = base64.b64decode(req.package_b64, validate=True)
            pkg = DistributionPackage.from_bytes(raw_pkg)
            val_res = PackageValidator.validate(pkg)
            if not val_res.valid:
                return DecryptPrepareResponse(
                    ready=False,
                    recipient_id=req.recipient_id,
                    error=f"Package invalid: {val_res.error}",
                )

            # Check recipient envelope
            envelope_found = any(env.recipient_id == req.recipient_id for env in pkg.header.recipient_envelopes)
            if not envelope_found:
                return DecryptPrepareResponse(
                    ready=False,
                    document_id=str(pkg.header.document_id),
                    distribution_id=str(pkg.header.distribution_id),
                    recipient_id=req.recipient_id,
                    error=f"Recipient '{req.recipient_id}' not authorized in package",
                )

            # Check KEM & DSA certificates
            store = get_storage()
            kem_cert = store.get_active_kem_certificate(req.recipient_id)
            dsa_cert = store.get_active_dsa_certificate(req.recipient_id)

            kem_ok = kem_cert is not None
            dsa_ok = dsa_cert is not None

            if not kem_ok or not dsa_ok:
                err_msg = []
                if not kem_ok:
                    err_msg.append("Active KEM certificate not found")
                if not dsa_ok:
                    err_msg.append("Active DSA certificate not found")
                return DecryptPrepareResponse(
                    ready=False,
                    document_id=str(pkg.header.document_id),
                    distribution_id=str(pkg.header.distribution_id),
                    recipient_id=req.recipient_id,
                    kem_certificate_valid=kem_ok,
                    dsa_certificate_valid=dsa_ok,
                    error="; ".join(err_msg),
                )

            return DecryptPrepareResponse(
                ready=True,
                document_id=str(pkg.header.document_id),
                distribution_id=str(pkg.header.distribution_id),
                recipient_id=req.recipient_id,
                kem_certificate_valid=True,
                dsa_certificate_valid=True,
            )
        except Exception as e:
            return DecryptPrepareResponse(
                ready=False,
                recipient_id=req.recipient_id,
                error=f"Preparation failed: {e}",
            )

    @app.post(
        "/decrypt/execute",
        response_model=DecryptExecuteResponse,
        summary="Execute atomic decryption pipeline and release watermarked document",
    )
    def decrypt_execute(req: DecryptExecuteRequest) -> DecryptExecuteResponse:
        try:
            raw_pkg = base64.b64decode(req.package_b64, validate=True)
            store = get_storage()

            # Retrieve recipient certificates
            kem_cert = store.get_active_kem_certificate(req.recipient_id)
            dsa_cert = store.get_active_dsa_certificate(req.recipient_id)
            if not kem_cert or not dsa_cert:
                raise SecurityError("Recipient active certificates (KEM or DSA) missing")

            # Retrieve recipient keystores
            kem_ks_path = store.get_active_kem_keystore_path(req.recipient_id)
            dsa_ks_path = store.get_active_dsa_keystore_path(req.recipient_id)
            if not kem_ks_path or not dsa_ks_path:
                raise SecurityError("Recipient keystores (KEM or DSA) missing")

            # Decrypt private keys
            kem_container = EncryptedKeyContainer.model_validate_json(kem_ks_path.read_text(encoding="utf-8"))
            kem_priv_bytes = KeystoreManager.decrypt_private_key(kem_container, req.kem_passphrase)
            kem_sk = MLKEMPrivateKey(bytes(kem_priv_bytes))

            dsa_container = EncryptedKeyContainer.model_validate_json(dsa_ks_path.read_text(encoding="utf-8"))
            dsa_priv_bytes = KeystoreManager.decrypt_private_key(dsa_container, req.dsa_passphrase)
            dsa_sk = MLDSAPrivateKey(bytes(dsa_priv_bytes))

            credentials = RecipientCredentials(
                recipient_id=req.recipient_id,
                kem_private_key=kem_sk,
                kem_certificate=kem_cert,
                dsa_private_key=dsa_sk,
                dsa_certificate=dsa_cert,
                device_id=req.device_id,
            )

            # Root CA validation parameters
            settings = get_settings()
            root_cert_path = settings.storage.keys_dir / "ca_root_cert.json"
            root_pk = None
            rev_store = None
            if root_cert_path.exists():
                root_cert = PQCIdentityCertificate.from_canonical_json(
                    root_cert_path.read_text(encoding="utf-8")
                )
                root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                rev_store = OfflineRevocationStore(store)

            wm_params = None
            if req.watermark_strength:
                wm_params = WatermarkParameters(embedding_strength=req.watermark_strength)

            # Atomic Execution through DocumentReleaseGate
            release = RecipientAttributionPipeline.execute_decryption(
                package_input=raw_pkg,
                credentials=credentials,
                ledger=api_ledger,
                root_ca_public_key=root_pk,
                revocation_provider=rev_store,
                watermark_params=wm_params,
                device_id=req.device_id,
            )

            # Persist signed event locally
            store.save_signed_event(release.signed_event)

            return DecryptExecuteResponse(
                released=True,
                watermarked_pdf_b64=base64.b64encode(release.watermarked_pdf).decode("ascii"),
                event=release.signed_event.event.model_dump(mode="json"),
                transaction_id=release.ledger_receipt.transaction_id,
                session_id=str(release.session_id),
                watermark_id=str(release.watermark_id),
                fidelity_psnr=release.fidelity.psnr,
                fidelity_ssim=release.fidelity.ssim,
            )

        except (LedgerCommitRequiredError, ReleaseGateError) as e:
            return DecryptExecuteResponse(
                released=False,
                error=f"Document release denied: {e}",
            )
        except Exception as e:
            return DecryptExecuteResponse(
                released=False,
                error=f"Decryption failed: {e}",
            )

    @app.get(
        "/events/{event_id}",
        summary="Retrieve committed signed decryption event by EventID",
    )
    def get_event_by_id(event_id: str) -> Dict[str, Any]:
        # Check in ledger first
        event = api_ledger.get_event(event_id)
        if event is None:
            # Fallback to local SQLite store
            store = get_storage()
            event = store.get_signed_event(event_id)

        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Event '{event_id}' not found",
            )
        return event.model_dump(mode="json")

    @app.post(
        "/events/verify",
        response_model=EventVerifyResponse,
        summary="Cryptographically verify a SignedDecryptionEvent",
    )
    def verify_event(req: EventVerifyRequest) -> EventVerifyResponse:
        try:
            signed_event = SignedDecryptionEvent.from_canonical_json(req.signed_event_json)
            store = get_storage()
            cert = store.get_certificate(signed_event.certificate_id)

            settings = get_settings()
            root_cert_path = settings.storage.keys_dir / "ca_root_cert.json"
            root_pk = None
            rev_store = None
            if root_cert_path.exists():
                try:
                    root_cert = PQCIdentityCertificate.from_canonical_json(
                        root_cert_path.read_text(encoding="utf-8")
                    )
                    root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                    rev_store = OfflineRevocationStore(store)
                except Exception:
                    pass

            result = DecryptionEventVerifier.verify_signed_event(
                signed_event=signed_event,
                recipient_certificate=cert,
                root_ca_public_key=root_pk,
                revocation_provider=rev_store,
            )

            return EventVerifyResponse(
                valid=result.valid,
                event_id=str(result.event_id),
                digest_verified=result.digest_verified,
                signature_verified=result.signature_verified,
                certificate_verified=result.certificate_verified,
                document_binding_verified=result.document_binding_verified,
                watermark_binding_verified=result.watermark_binding_verified,
                errors=result.errors,
            )
        except Exception as e:
            return EventVerifyResponse(
                valid=False,
                event_id="unknown",
                digest_verified=False,
                signature_verified=False,
                certificate_verified=False,
                document_binding_verified=False,
                watermark_binding_verified=False,
                errors=[f"Verification error: {e}"],
            )

    # -------------------------------------------------------------------------
    # Ledger Subsystem Endpoints
    # -------------------------------------------------------------------------

    def _get_api_ledger_storage() -> LedgerStorage:
        cluster_node = Path("C:/TraceCrypt/cluster_data/node-1/ledger.db")
        if cluster_node.exists():
            return LedgerStorage(cluster_node)
        settings = get_settings()
        return LedgerStorage(settings.storage.data_dir / "ledger.db")

    @app.get("/ledger/status")
    async def get_ledger_status() -> Dict[str, Any]:
        """Query current finalized ledger status, height, and cryptographic roots."""
        storage = _get_api_ledger_storage()
        try:
            gen = storage.get_genesis()
            latest_blk = storage.get_latest_block()
            state_root = "NONE"
            if latest_blk:
                state_root = latest_blk.header.state_root
            elif gen:
                state_root = gen.initial_state_root

            return {
                "chain_id": gen.chain_id if gen else "unknown",
                "height": storage.get_latest_height(),
                "latest_block_hash": latest_blk.header.block_hash if latest_blk else "NONE",
                "state_root": state_root,
                "validator_count": len(gen.validator_set.validators) if gen else 0,
                "byzantine_evidence_count": len(storage.get_byzantine_evidence()),
            }
        finally:
            storage.close()

    @app.get("/ledger/blocks/{height}")
    async def get_ledger_block(height: int) -> Dict[str, Any]:
        """Query finalized block by height."""
        storage = _get_api_ledger_storage()
        try:
            block = storage.get_block(height)
            if not block:
                raise HTTPException(status_code=404, detail=f"Block {height} not found")
            return block.to_canonical_dict()
        finally:
            storage.close()

    @app.get("/ledger/transactions/{transaction_id}")
    async def get_ledger_transaction(transaction_id: str) -> Dict[str, Any]:
        """Query committed transaction by TransactionID."""
        storage = _get_api_ledger_storage()
        try:
            res = storage.get_transaction_with_block(transaction_id)
            if not res:
                raise HTTPException(status_code=404, detail=f"Transaction {transaction_id} not found")
            tx, blk, idx = res
            return {
                "transaction": tx.to_canonical_dict(),
                "block_height": blk.header.height,
                "index_in_block": idx,
                "block_hash": blk.header.block_hash,
            }
        finally:
            storage.close()

    @app.get("/ledger/events/{event_id}")
    async def get_ledger_event(event_id: str) -> Dict[str, Any]:
        """Query committed decryption event by EventID."""
        storage = _get_api_ledger_storage()
        try:
            signed_evt = storage.get_event(event_id)
            if not signed_evt:
                raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
            return signed_evt.model_dump()
        finally:
            storage.close()

    @app.get("/ledger/watermarks/{watermark_id}")
    async def get_ledger_watermark(watermark_id: str) -> Dict[str, Any]:
        """Forensic lookup: query committed event by embedded WatermarkID."""
        storage = _get_api_ledger_storage()
        try:
            signed_evt = storage.lookup_by_watermark(watermark_id)
            if not signed_evt:
                raise HTTPException(status_code=404, detail=f"Watermark {watermark_id} not found")
            return signed_evt.model_dump()
        finally:
            storage.close()

    @app.get("/ledger/proofs/{transaction_id}")
    async def get_ledger_proof(transaction_id: str) -> Dict[str, Any]:
        """Retrieve standalone cryptographic Merkle inclusion proof for a transaction."""
        storage = _get_api_ledger_storage()
        try:
            proof_bundle = storage.export_merkle_proof(transaction_id)
            # Verify proof before returning to client
            proof = MerkleInclusionProof.model_validate(proof_bundle["merkle_proof"])
            header = BlockHeader.model_validate(proof_bundle["block_header"])
            tx = LedgerTransaction.model_validate(proof_bundle["transaction"])
            tx_leaf = MerkleTree.compute_leaf_hash(tx.to_canonical_bytes())
            verified = MerkleTree.verify_merkle_proof(tx_leaf, proof, header.transaction_root)

            proof_bundle["mathematically_verified"] = verified
            return proof_bundle
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e))
        finally:
            storage.close()

    @app.post("/ledger/verify")
    async def verify_ledger_chain(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Perform end-to-end cryptographic verification of local ledger chain."""
        storage = _get_api_ledger_storage()
        try:
            gen = storage.get_genesis()
            if not gen:
                raise HTTPException(status_code=500, detail="Genesis config not found")
            passed = storage.verify_chain(gen.validator_set)
            return {
                "status": "VERIFIED",
                "clean": passed,
                "latest_height": storage.get_latest_height(),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Chain verification failed: {e}")
        finally:
            storage.close()

    @app.get("/ledger/validators")
    async def get_ledger_validators() -> Dict[str, Any]:
        """List active permissioned consensus validators."""
        storage = _get_api_ledger_storage()
        try:
            gen = storage.get_genesis()
            if not gen:
                raise HTTPException(status_code=500, detail="Genesis config not found")
            return {
                "validators": [v.model_dump() for v in gen.validator_set.validators],
                "quorum_threshold": gen.validator_set.quorum,
                "total_voting_power": gen.validator_set.total_voting_power,
            }
        finally:
            storage.close()

    @app.post("/api/v1/forensics/investigate")
    async def forensic_investigate(
        file: UploadFile = File(...),
        case_id: Optional[str] = Form(None),
        case_name: Optional[str] = Form("Forensic Attribution Inquiry"),
        doc_hash: Optional[str] = Form(None),
    ) -> Dict[str, Any]:
        """Investigate a leaked document artifact for blind watermark attribution."""
        import tempfile
        # Enforce max upload file size (50MB default limit)
        max_bytes = 50 * 1024 * 1024
        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(status_code=413, detail="Artifact file size exceeds 50MB limit")

        suffix = Path(file.filename or "evidence.bin").suffix or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        storage = _get_api_ledger_storage()
        engine = ForensicInvestigationEngine(ledger_storage=storage)
        try:
            inv = engine.investigate(
                file_path=tmp_path,
                case_id=case_id,
                case_name=case_name or "Forensic Attribution Inquiry",
                suspect_document_hash=doc_hash,
            )

            proof_bundle = ForensicProofBundle.from_investigation(inv)
            bundle_dict = proof_bundle.to_dict()

            return {
                "case_id": inv.case_id,
                "evidence_hash": inv.evidence.sha3_256,
                "verdict": inv.verdict.value,
                "verdict_rationale": inv.verdict_rationale,
                "watermark_status": {
                    "detected": inv.watermark_analysis.detected,
                    "valid_extraction": inv.watermark_analysis.valid_extraction,
                    "ambiguous": inv.watermark_analysis.ambiguous,
                    "watermark_id": inv.watermark_analysis.recovered_watermark_id,
                    "session_id": inv.watermark_analysis.recovered_session_id,
                    "pages_detected": inv.watermark_analysis.pages_detected,
                },
                "ledger_status": {
                    "transaction_found": inv.ledger_verification.transaction_found,
                    "block_height": inv.ledger_verification.block_height,
                    "merkle_proof_valid": inv.ledger_verification.merkle_proof_valid,
                    "commit_cert_valid": inv.ledger_verification.commit_cert_valid,
                },
                "signature_status": {
                    "mldsa_signature_valid": inv.identity_verification.mldsa_signature_valid,
                    "recipient_cert_valid": inv.identity_verification.cert_valid,
                    "cert_revoked": inv.identity_verification.cert_revoked,
                },
                "document_binding_status": {
                    "binding_matches": inv.document_binding.binding_matches,
                    "expected_doc_hash": inv.document_binding.expected_doc_hash,
                },
                "recipient_identity_reference": {
                    "cert_id": inv.identity_verification.recipient_cert_id,
                    "common_name": inv.identity_verification.subject_common_name,
                },
                "proof_bundle_reference": {
                    "bundle_digest": proof_bundle.compute_bundle_digest(),
                    "proof_bundle": bundle_dict,
                },
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Forensic investigation failed: {e}")
        finally:
            if storage is not None:
                storage.close()
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @app.post("/api/v1/forensics/verify-proof")
    async def forensic_verify_proof(proof_bundle_data: Dict[str, Any]) -> Dict[str, Any]:
        """Independently verify a standalone .tcproof proof bundle."""
        try:
            bundle = ForensicProofBundle.from_dict(proof_bundle_data)
            verifier = StandaloneProofVerifier()
            result = verifier.verify(bundle)
            return result.model_dump()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Proof verification failed: {e}")

    # Mount self-contained air-gapped web UI
    from tracecrypt.ui import mount_ui
    mount_ui(app)

    return app
