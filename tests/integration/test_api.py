"""Integration tests for the local air-gapped FastAPI application."""

from fastapi.testclient import TestClient
import pytest

from tracecrypt.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.integration
def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "tracecrypt-node"
    assert "timestamp" in data
    # Verify security headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "no-store" in response.headers["Cache-Control"]


@pytest.mark.integration
def test_version_endpoint(client: TestClient):
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "0.1.0"
    assert data["pqc_standards"]["kem"] == "ML-KEM-768"
    assert data["pqc_standards"]["dsa"] == "ML-DSA-65"


@pytest.mark.integration
def test_security_status_endpoint(client: TestClient):
    response = client.get("/security/status")
    assert response.status_code == 200
    data = response.json()
    assert data["airgap_enforced"] is True
    assert "127.0.0.1" in data["whitelisted_hosts"]
