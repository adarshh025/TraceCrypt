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
import platform
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

import tracecrypt
from tracecrypt.config.settings import get_settings
from tracecrypt.crypto.types import MLDSAPublicKey, MLKEMPrivateKey
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import (
    CertificateValidationError,
    SecurityError,
    ValidationError,
)
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.identity.keystore import EncryptedKeyContainer, KeystoreManager
from tracecrypt.identity.lifecycle import OfflineRevocationStore
from tracecrypt.models.domain import Document, User, UserRole, UserStatus
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

    return app
