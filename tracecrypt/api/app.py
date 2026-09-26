"""Local-only FastAPI application foundation for TraceCrypt.

Security Principles:
- Localhost binding by default (127.0.0.1).
- LAN binding is explicitly deferred to Phase 6 when peer-to-peer validator gossip is enabled.
- Zero CORS wildcard (*).
- Strict HTTP security headers (CSP, nosniff, frame-ancestors 'none', no-cache).
- No sensitive operational endpoints exposed prematurely.
"""

from __future__ import annotations

import os
import platform
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

import tracecrypt
from tracecrypt.config.settings import get_settings
from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.errors import (
    CertificateValidationError,
    SecurityError,
    ValidationError,
)
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.identity.lifecycle import OfflineRevocationStore
from tracecrypt.security.airgap import AirGapGuard
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
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

    return app
