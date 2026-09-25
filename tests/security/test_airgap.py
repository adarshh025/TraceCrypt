"""Security tests for in-process Air-Gap Enforcement Guard."""

import socket
import pytest

from tracecrypt.errors import AirGapViolation
from tracecrypt.security.airgap import AirGapGuard, check_network_access


@pytest.fixture(autouse=True)
def airgap_lifecycle():
    """Ensure clean air-gap state before and after each test."""
    AirGapGuard.uninstall()
    AirGapGuard.set_allowed_hosts(["127.0.0.1", "localhost", "::1"])
    AirGapGuard.install()
    yield
    AirGapGuard.uninstall()


@pytest.mark.security
def test_outbound_connection_to_external_ip_blocked():
    """Verify that socket.connect to external IP is intercepted and raises AirGapViolation."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AirGapViolation, match="AIR-GAP POLICY VIOLATION"):
            s.connect(("8.8.8.8", 443))
    finally:
        s.close()


@pytest.mark.security
def test_external_dns_resolution_blocked():
    """Verify that getaddrinfo for external host raises AirGapViolation."""
    with pytest.raises(AirGapViolation, match="AIR-GAP POLICY VIOLATION"):
        socket.getaddrinfo("google.com", 443)


@pytest.mark.security
def test_whitelisted_localhost_allowed():
    """Verify that whitelisted local loopback connections are not blocked by the guard."""
    assert check_network_access("127.0.0.1", 8545) is True
    assert check_network_access("localhost", 8545) is True
    assert check_network_access("::1", 8545) is True
    # Non-whitelisted must fail
    assert check_network_access("192.168.1.100", 8545) is False
    assert check_network_access("api.cloud.com", 443) is False
