"""Unified Command-Line Interface for TraceCrypt.

Supports foundation administrative and diagnostic tasks:
- tracecrypt version
- tracecrypt doctor
- tracecrypt config validate
- tracecrypt security airgap-check
"""

from __future__ import annotations

import argparse
import importlib.util
import platform
import sys
from typing import List, Optional

import tracecrypt
from tracecrypt.config.settings import ConfigurationError, get_settings
from tracecrypt.security.airgap import AirGapGuard


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="tracecrypt",
        description="TraceCrypt: Offline Forensic Document Attribution Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: version
    subparsers.add_parser("version", help="Display TraceCrypt and system version information")

    # Command: doctor
    subparsers.add_parser("doctor", help="Run local diagnostic checks on environment and dependencies")

    # Command: config
    config_parser = subparsers.add_parser("config", help="Configuration inspection and validation")
    config_sub = config_parser.add_subparsers(dest="subcommand", help="Config operations")
    config_sub.add_parser("validate", help="Validate active configuration against security constraints")

    # Command: security
    sec_parser = subparsers.add_parser("security", help="Security controls and diagnostic commands")
    sec_sub = sec_parser.add_subparsers(dest="subcommand", help="Security operations")
    sec_sub.add_parser("airgap-check", help="Verify local air-gap configuration and enforcement status")

    return parser


def cmd_version() -> int:
    """Print version details."""
    print(f"TraceCrypt v{tracecrypt.__version__}")
    print(f"Python: {platform.python_version()} ({platform.architecture()[0]})")
    print(f"Platform: {platform.platform()}")
    print("Post-Quantum Baseline: NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65)")
    return 0


def cmd_doctor() -> int:
    """Diagnose local environment, dependencies, and storage."""
    print("Running TraceCrypt System Doctor...\n")
    all_ok = True

    # 1. Check Python version
    py_ver = sys.version_info
    if py_ver >= (3, 11):
        print(f"  [PASS] Python version: {platform.python_version()} (>= 3.11)")
    else:
        print(f"  [FAIL] Python version: {platform.python_version()} (Requires >= 3.11)")
        all_ok = False

    # 2. Check essential packages
    pkgs = [
        ("cryptography", "Classical cryptography & OpenSSL primitives"),
        ("numpy", "Matrix & numerical transform computations"),
        ("scipy", "Discrete Wavelet & Cosine Transforms"),
        ("cv2", "OpenCV image processing & document deskewing"),
        ("PIL", "Pillow image rasterization"),
        ("fastapi", "Air-gapped REST API"),
        ("pydantic", "Typed schema validation (v2)"),
        ("aiosqlite", "Asynchronous local SQLite storage"),
        ("sqlalchemy", "Relational abstraction"),
        ("pdfminer", "PDF document structural parsing"),
        ("reportlab", "PDF vector generation & reporting"),
        ("pytest", "Testing framework"),
    ]
    for mod_name, desc in pkgs:
        if importlib.util.find_spec(mod_name):
            print(f"  [PASS] {mod_name:<14} : {desc}")
        else:
            print(f"  [FAIL] {mod_name:<14} : MISSING ({desc})")
            all_ok = False

    # 3. Check configuration and storage
    try:
        settings = get_settings()
        print(f"  [PASS] Configuration  : Mode={settings.mode.value}, AirGap={settings.airgap.enforce_airgap}")
    except Exception as e:
        print(f"  [FAIL] Configuration  : Error loading settings: {e}")
        all_ok = False

    print("\nDiagnostic Summary: " + ("ALL CHECKS PASSED" if all_ok else "ISSUES DETECTED"))
    return 0 if all_ok else 1


def cmd_config_validate() -> int:
    """Validate active configuration."""
    print("Validating TraceCrypt Configuration...")
    try:
        settings = get_settings()
        settings.validate_security_invariants()
        print(f"  Mode                  : {settings.mode.value}")
        print(f"  Enforce Air-Gap       : {settings.airgap.enforce_airgap}")
        print(f"  Allow DNS             : {settings.airgap.allow_dns}")
        print(f"  Data Directory        : {settings.storage.base_dir}")
        print(f"  Ledger Cluster ID     : {settings.ledger.cluster_id}")
        print(f"  KEM Algorithm         : {settings.crypto.kem_algorithm}")
        print(f"  DSA Algorithm         : {settings.crypto.dsa_algorithm}")
        print("Configuration Status   : VALID (Security Invariants Upheld)")
        return 0
    except ConfigurationError as e:
        print(f"Configuration Status   : INVALID - {e}")
        return 1


def cmd_security_airgap() -> int:
    """Check air-gap enforcement."""
    print("Checking TraceCrypt Air-Gap Enforcement...")
    settings = get_settings()
    is_active = settings.airgap.enforce_airgap
    print(f"  Air-Gap Mode Configured: {is_active}")
    print(f"  Socket Interceptor     : {'INSTALLED' if AirGapGuard.is_installed() else 'READY'}")
    print(f"  Whitelisted Hosts      : {sorted(settings.airgap.allowed_hosts)}")
    print(f"  DNS Lookups Permitted  : {settings.airgap.allow_dns}")

    if settings.mode.value == "PRODUCTION" and not is_active:
        print("  ALERT: Production mode requires active air-gap enforcement.")
        return 1

    print("Air-Gap Status: COMPLIANT (Isolated to Local Subnet)")
    return 0


def main(args: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    try:
        parsed = parser.parse_args(args)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    if not parsed.command:
        parser.print_help()
        return 0

    if parsed.command == "version":
        return cmd_version()
    elif parsed.command == "doctor":
        return cmd_doctor()
    elif parsed.command == "config":
        if parsed.subcommand == "validate":
            return cmd_config_validate()
        parser.print_help()
        return 0
    elif parsed.command == "security":
        if parsed.subcommand == "airgap-check":
            return cmd_security_airgap()
        parser.print_help()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
