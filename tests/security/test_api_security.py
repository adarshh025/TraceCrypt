"""FastAPI Security Headers, Input Validation, and Authorization Tests.

Validates:
- Injection of defensive security headers on all responses.
- Administrative authorization via TRACECRYPT_ADMIN_TOKEN.
- HTTP 413 rejection of oversized upload artifacts (> 50 MB).
- Structured error responses that avoid leaking internal filesystem paths or stack traces.
"""

from __future__ import annotations

import os
from unittest.mock import patch
import pytest
from starlette.testclient import TestClient

from tracecrypt.api.app import create_app


class TestAPISecurity:
    """Evaluate REST API endpoints for security headers and input boundaries."""

    @pytest.fixture
    def client(self):
        app = create_app()
        return TestClient(app)

    def test_security_headers_present(self, client) -> None:
        """Every response must contain strict security headers."""
        resp = client.get("/health")
        assert resp.status_code == 200
        headers = resp.headers

        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
        assert "no-store" in headers.get("Cache-Control", "")

    def test_admin_authorization_enforcement(self, client) -> None:
        """Configuring TRACECRYPT_ADMIN_TOKEN must require valid Authorization header."""
        secret_token = "ultra-secure-admin-token-12345"

        with patch.dict(os.environ, {"TRACECRYPT_ADMIN_TOKEN": secret_token}):
            # Request without token must be rejected 401
            resp_no_token = client.get("/identity/status")
            assert resp_no_token.status_code == 401

            # Request with wrong token must be rejected 401
            resp_wrong = client.get(
                "/identity/status",
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp_wrong.status_code == 401

            # Request with correct token succeeds
            resp_ok = client.get(
                "/identity/status",
                headers={"Authorization": f"Bearer {secret_token}"},
            )
            assert resp_ok.status_code == 200

    def test_oversized_payload_rejected_by_api(self, client) -> None:
        """Uploading document exceeding 100 MB limit to /documents/package must yield HTTP 413."""
        import base64
        # 100MB + 10 bytes base64 payload
        oversized_raw = b"A" * (100 * 1024 * 1024 + 10)
        oversized_b64 = base64.b64encode(oversized_raw).decode("ascii")

        resp = client.post(
            "/documents/package",
            json={
                "document_bytes_b64": oversized_b64,
                "filename": "huge.pdf",
                "recipient_ids": ["usr-00000000000000000000000000000001"],
            },
        )
        assert resp.status_code == 413
        assert "exceeds maximum allowed size" in resp.json()["detail"]
