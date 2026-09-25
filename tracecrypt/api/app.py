"""Local-only FastAPI application foundation for TraceCrypt.

Security Principles:
- Localhost binding by default (127.0.0.1).
- LAN binding is explicitly deferred to Phase 6 when peer-to-peer validator gossip is enabled.
- Zero CORS wildcard (*).
- Strict HTTP security headers (CSP, nosniff, frame-ancestors 'none', no-cache).
- No sensitive operational endpoints exposed prematurely.
"""

from __future__ import annotations

import platform
from typing import Any, Dict

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

import tracecrypt
from tracecrypt.config.settings import get_settings
from tracecrypt.security.airgap import AirGapGuard
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


def create_app() -> FastAPI:
    """Initialize and configure the air-gapped FastAPI service."""
    settings = get_settings()

    app = FastAPI(
        title="TraceCrypt Local Node API",
        description="Offline Forensic Document Attribution Platform - Foundation Node API",
        version=tracecrypt.__version__,
        docs_url="/docs" if settings.mode.value == "DEVELOPMENT" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.mode.value == "DEVELOPMENT" else None,
    )

    app.add_middleware(SecurityHeadersMiddleware)

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

    return app
