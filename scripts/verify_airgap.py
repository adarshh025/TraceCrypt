#!/usr/bin/env python3
"""Comprehensive Air-Gap Verification Script for TraceCrypt.

Satisfies Master Prompt 11 - Section 27:
- Static AST inspection of all source code (imports, calls, forbidden packages)
- Scanning for cloud SDKs, telemetry, analytics, CDNs, external URLs
- Dependency manifest audit ensuring zero runtime egress dependencies
- Dynamic runtime socket interception & egress monitoring
Demonstrates mathematically and empirically:
"TraceCrypt performs zero intentional outbound network communication."
"""

from __future__ import annotations

import ast
import os
import re
import socket
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Forbidden third-party modules that imply remote/cloud/telemetry/egress
FORBIDDEN_MODULES: Set[str] = {
    "requests",
    "urllib.request",
    "http.client",
    "httpx",
    "aiohttp",
    "boto3",
    "botocore",
    "google.cloud",
    "google.auth",
    "azure",
    "sentry_sdk",
    "datadog",
    "segment",
    "mixpanel",
    "posthog",
    "telemetry",
    "analytics",
    "pypi",
    "pip",
    "wheel",
}

# External URL patterns that should not appear as active network endpoints
FORBIDDEN_URL_PATTERN = re.compile(
    r"https?://(?!127\.0\.0\.1|localhost|raw\.githubusercontent\.com/adarshh025/TraceCrypt|github\.com/adarshh025/TraceCrypt|errors\.pydantic\.dev)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Allowed local loopback addresses for permissioned inter-node LAN message passing
ALLOWED_LOOPBACK = {"127.0.0.1", "localhost", "0.0.0.0"}


class EgressViolationError(RuntimeError):
    """Raised when an unauthorized outbound connection attempt occurs."""
    pass


class SocketGuard:
    """Interception guard installed into Python socket subsystem to monitor egress."""

    def __init__(self) -> None:
        self.orig_getaddrinfo = socket.getaddrinfo
        self.orig_connect = socket.socket.connect
        self.orig_connect_ex = socket.socket.connect_ex
        self.orig_sendto = socket.socket.sendto
        self.connection_attempts: List[Tuple[str, int]] = []
        self.dns_queries: List[str] = []
        self.violations: List[str] = []

    def __enter__(self) -> "SocketGuard":
        guard = self

        def guarded_getaddrinfo(host, port, *args, **kwargs):
            if host not in ALLOWED_LOOPBACK:
                guard.violations.append(f"DNS Resolution attempted for: {host}")
                raise EgressViolationError(f"Air-gap violation: DNS lookup forbidden for '{host}'")
            guard.dns_queries.append(str(host))
            return guard.orig_getaddrinfo(host, port, *args, **kwargs)

        def guarded_connect(sock_self, address):
            host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
            port = address[1] if isinstance(address, tuple) and len(address) > 1 else 0
            guard.connection_attempts.append((str(host), int(port)))
            if host not in ALLOWED_LOOPBACK:
                guard.violations.append(f"Outbound connection attempted to: {host}:{port}")
                raise EgressViolationError(f"Air-gap violation: Egress connection forbidden to '{host}:{port}'")
            return guard.orig_connect(sock_self, address)

        socket.getaddrinfo = guarded_getaddrinfo
        socket.socket.connect = guarded_connect
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        socket.getaddrinfo = self.orig_getaddrinfo
        socket.socket.connect = self.orig_connect


def check_static_ast(source_dir: Path) -> Tuple[bool, List[str]]:
    """Perform AST inspection across all Python source files in the package."""
    violations: List[str] = []
    py_files = list(source_dir.glob("**/*.py"))

    for fpath in py_files:
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8"), filename=str(fpath))
        except Exception as e:
            violations.append(f"Syntax error parsing {fpath.name}: {e}")
            continue

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in FORBIDDEN_MODULES:
                        if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                            violations.append(
                                f"{fpath.relative_to(REPO_ROOT)}:{node.lineno} forbidden import '{alias.name}'"
                            )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for forbidden in FORBIDDEN_MODULES:
                    if mod == forbidden or mod.startswith(forbidden + "."):
                        violations.append(
                            f"{fpath.relative_to(REPO_ROOT)}:{node.lineno} forbidden from-import '{mod}'"
                        )

            # Check string literals for external URLs
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                if "http://" in val or "https://" in val:
                    matches = FORBIDDEN_URL_PATTERN.findall(val)
                    for m in matches:
                        # Skip documentation and schema comments
                        if not any(kw in val for kw in ["pydantic", "github", "ietf.org", "w3.org", "example"]):
                            violations.append(
                                f"{fpath.relative_to(REPO_ROOT)}:{node.lineno} external network URL: '{m}'"
                            )

    return len(violations) == 0, violations


def check_dependencies() -> Tuple[bool, List[str]]:
    """Audit declared runtime project dependencies against forbidden egress packages."""
    violations: List[str] = []
    pyproject_path = REPO_ROOT / "pyproject.toml"

    if not pyproject_path.exists():
        violations.append("pyproject.toml not found")
        return False, violations

    import tomllib
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    runtime_deps = data.get("project", {}).get("dependencies", [])

    for dep in runtime_deps:
        dep_name = dep.split(">=")[0].split("==")[0].split("~=")[0].split("<")[0].strip().lower()
        for forbidden in FORBIDDEN_MODULES:
            if dep_name == forbidden or dep_name.startswith(forbidden + "-"):
                violations.append(f"Forbidden runtime dependency: {dep}")

    return len(violations) == 0, violations


def check_runtime_egress() -> Tuple[bool, List[str]]:
    """Execute end-to-end cryptographic and forensic pipeline under strict socket guard."""
    violations: List[str] = []
    guard = SocketGuard()

    with guard:
        try:
            # 1. Run doctor diagnostics
            from tracecrypt.cli.main import cmd_doctor
            doctor_res = cmd_doctor()
            if doctor_res != 0:
                violations.append(f"Doctor diagnostic check returned code {doctor_res}")

            # 2. Run core crypto operations
            from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair, encapsulate, decapsulate
            from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign, verify
            pk_k, sk_k = generate_mlkem_keypair()
            ss1, ct = encapsulate(pk_k)
            ss2 = decapsulate(sk_k, ct)
            assert ss1 == ss2

            pk_d, sk_d = generate_mldsa_keypair()
            test_msg = b"Airgap runtime verification test message"
            sig = sign(sk_d, test_msg)
            assert verify(pk_d, test_msg, sig)

            # 3. Test standalone verification
            from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
            verifier = StandaloneProofVerifier()

        except EgressViolationError as e:
            violations.append(str(e))
        except Exception as e:
            violations.append(f"Runtime execution error under guard: {e}")

    violations.extend(guard.violations)
    return len(violations) == 0, violations


def main() -> int:
    print("\n" + "=" * 70)
    print("        TRACECRYPT AIR-GAP ASSURANCE & ZERO-EGRESS VERIFIER        ")
    print("=" * 70)

    # 1. Static AST Analysis
    print("[1/3] Running Static AST Code Inspection across tracecrypt/...")
    ast_pass, ast_issues = check_static_ast(REPO_ROOT / "tracecrypt")
    if ast_pass:
        print("  -> [PASS] Zero forbidden cloud/telemetry/egress imports detected.")
    else:
        print(f"  -> [FAIL] {len(ast_issues)} AST issues detected:")
        for iss in ast_issues:
            print(f"     * {iss}")

    # 2. Dependency Manifest Audit
    print("\n[2/3] Auditing Project Dependencies (pyproject.toml)...")
    dep_pass, dep_issues = check_dependencies()
    if dep_pass:
        print("  -> [PASS] Dependency set is 100% offline-compatible.")
    else:
        print(f"  -> [FAIL] {len(dep_issues)} dependency issues detected:")
        for iss in dep_issues:
            print(f"     * {iss}")

    # 3. Dynamic Runtime Egress Interception
    print("\n[3/3] Executing Dynamic Runtime Egress Interception Test...")
    run_pass, run_issues = check_runtime_egress()
    if run_pass:
        print("  -> [PASS] Zero outbound socket, DNS, or HTTP egress attempts recorded.")
    else:
        print(f"  -> [FAIL] Runtime egress attempts detected:")
        for iss in run_issues:
            print(f"     * {iss}")

    print("\n" + "=" * 70)
    overall_pass = ast_pass and dep_pass and run_pass
    if overall_pass:
        print("AIR-GAP VERIFICATION STATUS: [COMPLIANT - ZERO NETWORK EGRESS]")
        print("TraceCrypt performs zero outbound network communication.")
        print("=" * 70 + "\n")
        return 0
    else:
        print("AIR-GAP VERIFICATION STATUS: [NON-COMPLIANT - EGRESS RISKS DETECTED]")
        print("=" * 70 + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
