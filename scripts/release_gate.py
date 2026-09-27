#!/usr/bin/env python3
"""TraceCrypt Release Gate.

Enforces strict compliance before release:
1. Environment & Doctor Diagnostics (Python, packages, SQLite, offline mode)
2. PQC & Classical Cryptographic Provider Sanity (ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA3)
3. Air-Gap Operational Security (Zero outbound network socket enforcement)
4. Full Automated Test Suite (Unit, Integration, Security, Forensics, Vectors)
5. Golden End-to-End Workflow & Standalone Proof Bundle Verification
6. Required Release Artifacts & Documentation Integrity

Zero tolerance for failed tests, missing dependencies, or compromised security.
Exits 0 on total pass; exits 1 on any gate failure.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class ReleaseGate:
    """Automated release validation gate."""

    def __init__(self) -> None:
        self.results: List[Tuple[str, str, str]] = []  # (Gate Name, Status, Details)
        self.failed = False

    def record(self, gate: str, passed: bool, details: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        if not passed:
            self.failed = True
        self.results.append((gate, status, details))
        mark = "[PASS]" if passed else "[FAIL]"
        print(f" {mark} {gate}: {details}")

    def check_environment(self) -> None:
        """Verify host environment, Python version, and core dependencies."""
        py_ver = sys.version_info
        valid_py = py_ver.major == 3 and py_ver.minor >= 11
        self.record("Environment: Python >= 3.11", valid_py, f"Python {platform.python_version()}")

        required_pkgs = [
            "cryptography",
            "pydantic",
            "dilithium_py",
            "mlkem",
            "scipy",
            "numpy",
            "cv2",
            "PIL",
            "pypdf",
            "reportlab",
            "sqlite3",
        ]
        missing = []
        for pkg in required_pkgs:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)

        self.record("Environment: Required Dependencies", len(missing) == 0, f"Missing: {missing}" if missing else "All 11 packages present")

    def check_crypto_primitives(self) -> None:
        """Validate ML-KEM-768, ML-DSA-65, and AES-256-GCM primitives."""
        try:
            from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
            from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
            from tracecrypt.document.encryption import ContentEncryption

            pk_kem, sk_kem = generate_mlkem_keypair()
            valid_kem = len(pk_kem.raw_bytes) == 1184 and len(sk_kem.raw_bytes) == 2400
            self.record("Crypto: ML-KEM-768 FIPS 203 Keypair", valid_kem, f"pk={len(pk_kem.raw_bytes)}B, sk={len(sk_kem.raw_bytes)}B")

            pk_dsa, sk_dsa = generate_mldsa_keypair()
            valid_dsa = len(pk_dsa.raw_bytes) == 1952 and len(sk_dsa.raw_bytes) == 4032
            self.record("Crypto: ML-DSA-65 FIPS 204 Keypair", valid_dsa, f"pk={len(pk_dsa.raw_bytes)}B, sk={len(sk_dsa.raw_bytes)}B")

            key = os.urandom(32)
            pt = b"Release Gate Crypto Sanity Check"
            aad = b"RFC8785-AAD-Release-Gate"
            nonce, tag, ct = ContentEncryption.encrypt_document(pt, key, aad)
            dec = ContentEncryption.decrypt_document(ct, nonce, tag, key, aad)
            self.record("Crypto: AES-256-GCM Authenticated Encryption", bytes(dec) == pt, "Encryption/Decryption validated")
        except Exception as e:
            self.record("Crypto: Cryptographic Primitives", False, str(e))

    def check_airgap_security(self) -> None:
        """Validate AirGapGuard socket interception."""
        try:
            import socket
            from tracecrypt.errors import AirGapViolation
            from tracecrypt.security.airgap import AirGapGuard

            with AirGapGuard():
                blocked = False
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(("8.8.8.8", 53))
                except AirGapViolation:
                    blocked = True
                except Exception:
                    blocked = True

            self.record("Air-Gap: Network Socket Interception", blocked, "Outbound sockets strictly prohibited")
        except Exception as e:
            self.record("Air-Gap: Network Socket Interception", False, str(e))

    def run_pytest_suite(self, suite_path: str, suite_name: str) -> None:
        """Execute a designated pytest test suite and record pass/fail."""
        cmd = [sys.executable, "-m", "pytest", suite_path, "-q"]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        passed = proc.returncode == 0
        details = proc.stdout.strip().splitlines()[-1] if proc.stdout else proc.stderr.strip()
        self.record(f"Test Suite: {suite_name}", passed, details)

    def check_golden_workflow(self) -> None:
        """Verify end-to-end golden workflow test."""
        self.run_pytest_suite("tests/forensics/test_end_to_end.py", "Golden End-to-End Forensic Workflow")

    def check_required_artifacts(self) -> None:
        """Verify presence of all mandatory documentation and release manifests."""
        required_files = [
            "pyproject.toml",
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "THIRD_PARTY_NOTICES",
            "docs/FINAL_REQUIREMENTS_TRACEABILITY.md",
            "docs/RELEASE_MANIFEST.md",
            "docs/RELEASE_READINESS.md",
            "docs/AIR_GAP_VALIDATION.md",
            "docs/CRYPTOGRAPHIC_CONFORMANCE.md",
            "docs/BENCHMARKS.md",
            "docs/SECURITY_BOUNDARIES.md",
            "docs/LIMITATIONS.md",
            "docs/DISASTER_RECOVERY.md",
            "docs/INSTALLATION.md",
            "docs/QUICKSTART.md",
        ]
        missing = [f for f in required_files if not (REPO_ROOT / f).exists()]
        self.record("Artifacts: Mandatory Documentation & Manifests", len(missing) == 0, f"Missing: {missing}" if missing else "All 16 artifacts present")

    def evaluate(self) -> int:
        """Run all gates in order and return exit status code."""
        print("=" * 70)
        print("TraceCrypt — Release Gate Automated Verification")
        print("=" * 70)

        self.check_environment()
        self.check_crypto_primitives()
        self.check_airgap_security()
        self.check_golden_workflow()
        self.run_pytest_suite("tests/unit", "Unit Tests (236 tests)")
        self.run_pytest_suite("tests/security", "Security & Adversarial Tests (134 tests)")
        self.run_pytest_suite("tests/integration", "Integration Tests (49 tests)")
        self.run_pytest_suite("tests/forensics", "Forensics Tests (75 tests)")
        self.run_pytest_suite("tests/vectors", "PQC Reference Vectors (2 tests)")
        self.check_required_artifacts()

        print("=" * 70)
        print("RELEASE GATE SUMMARY")
        print("=" * 70)
        for gate, status, details in self.results:
            print(f"[{status:4s}] {gate:45s} | {details}")
        print("=" * 70)

        if self.failed:
            print("OVERALL RESULT: RELEASE BLOCKED (One or more gates failed)")
            return 1
        else:
            print("OVERALL RESULT: RELEASE APPROVED (All gates passed)")
            return 0


def main() -> int:
    gate = ReleaseGate()
    return gate.evaluate()


if __name__ == "__main__":
    sys.exit(main())
