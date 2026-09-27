"""Air-gap enforcement mechanism for TraceCrypt.

Detects, intercepts, and blocks unauthorized outbound network socket connections,
DNS lookups, and cloud telemetry calls at the application process boundary.

LIMITATIONS:
Host-level socket interception provides software defense-in-depth against accidental
network calls by dependencies or rogue threads. It DOES NOT replace physical air-gapping,
unplugged network adapters, hardware diode switches, or OS-level packet filters (Windows
Filtering Platform / iptables).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable, List, Optional, Set

from tracecrypt.errors import AirGapViolation


class AirGapGuard:
    """Interception guard enforcing strict network boundaries within the Python process."""

    _installed: bool = False
    _original_connect: Optional[Callable[..., Any]] = None
    _original_getaddrinfo: Optional[Callable[..., Any]] = None
    _allowed_hosts: Set[str] = {"127.0.0.1", "localhost", "::1"}
    _allowed_subnets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]

    @classmethod
    def set_allowed_hosts(cls, hosts: List[str]) -> None:
        """Configure whitelisted hostnames or IP addresses."""
        cls._allowed_hosts = set(h.lower().strip() for h in hosts)

    @classmethod
    def set_allowed_subnets(cls, subnets: List[str]) -> None:
        """Configure whitelisted IP network subnets (e.g. ['10.0.0.0/24'])."""
        parsed: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for s in subnets:
            parsed.append(ipaddress.ip_network(s, strict=False))
        cls._allowed_subnets = parsed

    @classmethod
    def is_address_allowed(cls, host: str, port: Optional[int] = None) -> bool:
        """Check if target host is authorized for connection in air-gapped mode."""
        norm_host = host.lower().strip()
        if norm_host in cls._allowed_hosts:
            return True

        # Attempt IP network matching
        try:
            ip = ipaddress.ip_address(norm_host)
            for subnet in cls._allowed_subnets:
                if ip in subnet:
                    return True
        except ValueError:
            pass  # Hostname rather than direct IP

        return False

    @classmethod
    def install(cls) -> None:
        """Install socket hooks to block non-whitelisted outbound network connections."""
        if cls._installed:
            return

        cls._original_connect = socket.socket.connect
        cls._original_getaddrinfo = socket.getaddrinfo

        orig_connect = cls._original_connect
        orig_getaddrinfo = cls._original_getaddrinfo

        def guarded_connect(sock_self: socket.socket, address: Any) -> Any:
            target_host: Optional[str] = None
            target_port: Optional[int] = None

            if isinstance(address, tuple) and len(address) >= 2:
                target_host = str(address[0])
                target_port = int(address[1])
            elif isinstance(address, str):
                target_host = address

            if target_host is not None:
                if not cls.is_address_allowed(target_host, target_port):
                    raise AirGapViolation(
                        f"AIR-GAP POLICY VIOLATION: Unauthorized outbound connection blocked to "
                        f"'{target_host}:{target_port}'."
                    )
            return orig_connect(sock_self, address)

        def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            if host is not None:
                h_str = str(host).lower().strip()
                if not cls.is_address_allowed(h_str):
                    raise AirGapViolation(
                        f"AIR-GAP POLICY VIOLATION: Unauthorized DNS resolution blocked for host '{h_str}'."
                    )
            return orig_getaddrinfo(host, port, *args, **kwargs)

        socket.socket.connect = guarded_connect  # type: ignore[assignment]
        socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
        cls._installed = True

    @classmethod
    def uninstall(cls) -> None:
        """Restore original standard library socket functions."""
        if not cls._installed:
            return
        if cls._original_connect is not None:
            socket.socket.connect = cls._original_connect  # type: ignore[assignment]
        if cls._original_getaddrinfo is not None:
            socket.getaddrinfo = cls._original_getaddrinfo  # type: ignore[assignment]
        cls._installed = False

    @classmethod
    def is_installed(cls) -> bool:
        """Return True if air-gap socket guard is currently active."""
        return cls._installed

    def __enter__(self) -> AirGapGuard:
        self.install()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.uninstall()


def check_network_access(target_host: str, port: int = 443) -> bool:
    """Helper to verify if a given destination violates the air-gap policy."""
    return AirGapGuard.is_address_allowed(target_host, port)
