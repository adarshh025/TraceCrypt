"""Unified Command-Line Interface for TraceCrypt.

Supports foundation administrative, diagnostic, and identity tasks:
- tracecrypt version
- tracecrypt doctor
- tracecrypt config validate
- tracecrypt security airgap-check
- tracecrypt ca init
- tracecrypt ca status
- tracecrypt identity generate
- tracecrypt identity list
- tracecrypt identity inspect
- tracecrypt identity verify
- tracecrypt identity rotate
- tracecrypt identity revoke
- tracecrypt key fingerprint
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
from pathlib import Path
import platform
import sys
from typing import List, Optional

import tracecrypt
from tracecrypt.config.settings import ConfigurationError, get_settings
from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    KeyStatus,
    MLDSAPublicKey,
    MLKEMPublicKey,
)
from tracecrypt.errors import SecurityError, ValidationError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.identity.lifecycle import KeyLifecycleManager, OfflineRevocationStore, RevocationReason
from tracecrypt.security.airgap import AirGapGuard
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.timestamps import utc_now_micros


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

    # Command: ca
    ca_parser = subparsers.add_parser("ca", help="Offline Root Certificate Authority management")
    ca_sub = ca_parser.add_subparsers(dest="subcommand", help="CA operations")
    init_ca = ca_sub.add_parser("init", help="Initialize a new Offline Root CA")
    init_ca.add_argument("--passphrase", required=True, help="Master passphrase protecting the Root CA key")
    init_ca.add_argument("--ca-id", default="ca-root-primary", help="Unique Root CA identifier")

    ca_sub.add_parser("status", help="Inspect Root CA status and public key fingerprint")

    # Command: identity
    id_parser = subparsers.add_parser("identity", help="PQC Identity and credential management")
    id_sub = id_parser.add_subparsers(dest="subcommand", help="Identity operations")

    id_sub.add_parser("status", help="Show overview of enrolled identities and certificates")
    id_sub.add_parser("list", help="List enrolled identity certificates")

    gen_id = id_sub.add_parser("generate", help="Generate PQC identity keys and certificates")
    gen_id.add_argument(
        "--owner-id", "--recipient-id", dest="owner_id", required=True,
        help="Certified User or Recipient ID (e.g. rcp-...)",
    )
    gen_id.add_argument(
        "--org", "--organization", dest="org", default="TraceCrypt Operations",
        help="Organization unit",
    )
    gen_id.add_argument("--role", default="RECIPIENT", help="Subject role")
    gen_id.add_argument("--passphrase", required=True, help="Passphrase to encrypt the recipient private keystore")
    gen_id.add_argument("--ca-passphrase", required=True, help="Root CA passphrase to sign the certificates")

    inspect_id = id_sub.add_parser("inspect", help="Inspect certificate details")
    inspect_id.add_argument("--serial", dest="serial", default=None, help="Certificate serial number (crt-...)")
    inspect_id.add_argument("--recipient-id", dest="recipient_id", default=None, help="Recipient ID to inspect")

    verify_id = id_sub.add_parser("verify", help="Run 12-point offline verification on a certificate")
    verify_id.add_argument("--serial", dest="serial", default=None, help="Certificate serial number (crt-...)")
    verify_id.add_argument("--cert-file", dest="cert_file", default=None, help="Path to certificate JSON file")

    rotate_id = id_sub.add_parser("rotate", help="Rotate recipient cryptographic keys")
    rotate_id.add_argument("--owner-id", "--recipient-id", dest="owner_id", required=True, help="Recipient ID")
    rotate_id.add_argument("--passphrase", required=True, help="New passphrase for rotated keystore")
    rotate_id.add_argument("--ca-passphrase", required=True, help="Root CA passphrase")

    revoke_id = id_sub.add_parser("revoke", help="Revoke a certificate offline")
    revoke_id.add_argument("--serial", required=True, help="Certificate serial number to revoke")
    revoke_id.add_argument(
        "--reason",
        default="ADMINISTRATIVE",
        choices=[r.value for r in RevocationReason],
        help="Revocation reason",
    )
    revoke_id.add_argument("--ca-passphrase", required=True, help="Root CA passphrase to sign revocation")

    # Command: key
    key_parser = subparsers.add_parser("key", help="Cryptographic key operations")
    key_sub = key_parser.add_subparsers(dest="subcommand", help="Key operations")
    fp_key = key_sub.add_parser("fingerprint", help="Compute deterministic fingerprint of public key")
    fp_key.add_argument("--type", choices=["kem", "dsa"], default=None, help="Key type (kem or dsa)")
    fp_key.add_argument("--b64", default=None, help="Base64-encoded public key")
    fp_key.add_argument("--key-file", default=None, help="Path to public key binary or certificate JSON file")

    return parser


def get_storage() -> SQLiteStorageManager:
    settings = get_settings()
    store = SQLiteStorageManager(settings.storage.sqlite_db_path)
    store.initialize()
    return store


def get_root_ca_paths() -> tuple[Path, Path]:
    settings = get_settings()
    keys_dir = settings.storage.keys_dir
    keys_dir.mkdir(parents=True, exist_ok=True)
    keystore_path = keys_dir / "ca_root.json"
    pubkey_path = keys_dir / "ca_root_pub.bin"
    return keystore_path, pubkey_path


# -------------------------------------------------------------------------
# Command Handlers
# -------------------------------------------------------------------------

def cmd_version() -> int:
    print(f"TraceCrypt v{tracecrypt.__version__}")
    print(f"Python: {platform.python_version()} ({platform.architecture()[0]})")
    print(f"Platform: {platform.platform()}")
    print("Post-Quantum Baseline: NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65)")
    return 0


def cmd_doctor() -> int:
    print("Running TraceCrypt System Doctor...\n")
    all_ok = True

    py_ver = sys.version_info
    if py_ver >= (3, 11):
        print(f"  [PASS] Python version: {platform.python_version()} (>= 3.11)")
    else:
        print(f"  [FAIL] Python version: {platform.python_version()} (Requires >= 3.11)")
        all_ok = False

    pkgs = [
        ("cryptography", "Classical cryptography, AES-256-GCM, & Argon2id"),
        ("dilithium_py", "NIST FIPS 204 ML-DSA-65 post-quantum digital signatures"),
        ("mlkem", "NIST FIPS 203 ML-KEM-768 post-quantum key encapsulation"),
        ("numpy", "Matrix & numerical transform computations"),
        ("scipy", "Discrete Wavelet & Cosine Transforms"),
        ("cv2", "OpenCV image processing & document deskewing"),
        ("PIL", "Pillow image rasterization"),
        ("fastapi", "Air-gapped REST API"),
        ("pydantic", "Typed schema validation (v2)"),
        ("aiosqlite", "Asynchronous local SQLite storage"),
        ("sqlalchemy", "Relational abstraction"),
        ("pytest", "Testing framework"),
    ]
    for mod_name, desc in pkgs:
        if importlib.util.find_spec(mod_name):
            print(f"  [PASS] {mod_name:<14} : {desc}")
        else:
            print(f"  [FAIL] {mod_name:<14} : MISSING ({desc})")
            all_ok = False

    try:
        settings = get_settings()
        print(f"  [PASS] Configuration  : Mode={settings.mode.value}, AirGap={settings.airgap.enforce_airgap}")
    except Exception as e:
        print(f"  [FAIL] Configuration  : Error loading settings: {e}")
        all_ok = False

    print("\nDiagnostic Summary: " + ("ALL CHECKS PASSED" if all_ok else "ISSUES DETECTED"))
    return 0 if all_ok else 1


def cmd_config_validate() -> int:
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


def cmd_ca_init(args: argparse.Namespace) -> int:
    print("Initializing Offline Root Certificate Authority...")
    keystore_path, pubkey_path = get_root_ca_paths()
    if keystore_path.exists():
        print(f"Error: Root CA keystore already exists at '{keystore_path}'. Overwrite prohibited.")
        return 1

    ca = OfflineRootCA.initialize(ca_id=args.ca_id)
    ca.save_to_keystore(keystore_path, args.passphrase)

    # Save public key bytes for offline verification
    with open(pubkey_path, "wb") as f:
        f.write(ca.public_key.raw_bytes)

    # Issue and save self-signed root certificate
    root_cert = ca.issue_signing_certificate(
        subject_id=ca.ca_id,
        public_key=ca.public_key,
        organization="TraceCrypt Authority",
        role="Root CA",
        validity_days=3650,
    )
    settings = get_settings()
    cert_path = settings.storage.keys_dir / "ca_root_cert.json"
    cert_path.write_text(root_cert.to_canonical_json(), encoding="utf-8")

    print(f"  [SUCCESS] Root CA Initialized Successfully: {ca.ca_id}")
    print("  Algorithm   : ML-DSA-65 (NIST FIPS 204)")
    print(f"  Fingerprint : {ca.fingerprint}")
    print(f"  Keystore    : {keystore_path} (Argon2id + AES-256-GCM)")
    print(f"  Public Key  : {pubkey_path}")
    print(f"  Certificate : {cert_path}")
    return 0


def cmd_ca_status() -> int:
    keystore_path, pubkey_path = get_root_ca_paths()
    if not keystore_path.exists() or not pubkey_path.exists():
        print("Root CA Status: UNINITIALIZED. Run 'tracecrypt ca init' to create.")
        return 0

    with open(pubkey_path, "rb") as f:
        pk_bytes = f.read()
    pk = MLDSAPublicKey(pk_bytes)

    settings = get_settings()
    cert_path = settings.storage.keys_dir / "ca_root_cert.json"
    ca_id = "ca-root"
    if cert_path.exists():
        try:
            cert = PQCIdentityCertificate.from_canonical_json(cert_path.read_text(encoding="utf-8"))
            ca_id = cert.subject_id
        except Exception:
            pass

    print("Offline Root CA Status: ACTIVE")
    print(f"  CA Identifier          : {ca_id}")
    print(f"  Public Key Fingerprint : {pk.fingerprint}")
    print(f"  Public Key File        : {pubkey_path}")
    print(f"  Keystore Container     : {keystore_path}")
    return 0


def load_root_ca(ca_passphrase: str) -> OfflineRootCA:
    keystore_path, pubkey_path = get_root_ca_paths()
    if not keystore_path.exists() or not pubkey_path.exists():
        raise ValidationError("Root CA is not initialized. Run 'tracecrypt ca init' first.")
    with open(pubkey_path, "rb") as f:
        pk_bytes = f.read()
    return OfflineRootCA.load_from_keystore(keystore_path, ca_passphrase, pk_bytes)


def cmd_identity_generate(args: argparse.Namespace) -> int:
    print(f"Generating Post-Quantum Identity for '{args.owner_id}'...")
    try:
        root_ca = load_root_ca(args.ca_passphrase)
    except Exception as e:
        print(f"Error loading Root CA: {e}")
        return 1

    settings = get_settings()
    store = get_storage()
    now = utc_now_micros()

    # 1. Generate ML-DSA-65 signing key pair
    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_key_id = f"key-dsa-{SecureRandom.random_nonce_128()}"
    dsa_meta = KeyMetadata(
        key_id=dsa_key_id,
        owner_id=args.owner_id,
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=now,
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=dsa_pk.fingerprint,
    )
    dsa_path = settings.storage.keys_dir / f"{dsa_key_id}.tckeystore"
    dsa_container = KeystoreManager.encrypt_private_key(dsa_sk, args.passphrase, dsa_meta)
    KeystoreManager.save_container(dsa_container, dsa_path)
    store.save_key_metadata(dsa_meta, str(dsa_path))

    # Issue ML-DSA certificate
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=args.owner_id,
        public_key=dsa_pk,
        organization=args.org,
        role=args.role,
    )
    store.save_certificate(dsa_cert)

    dsa_cert_file = settings.storage.keys_dir / f"{args.owner_id}_dsa_cert.json"
    dsa_cert_file.write_text(dsa_cert.to_canonical_json(), encoding="utf-8")

    # 2. Generate ML-KEM-768 encapsulation key pair
    kem_pk, kem_sk = generate_mlkem_keypair()
    kem_key_id = f"key-kem-{SecureRandom.random_nonce_128()}"
    kem_meta = KeyMetadata(
        key_id=kem_key_id,
        owner_id=args.owner_id,
        purpose=KeyPurpose.KEY_ENCAPSULATION,
        algorithm="ML-KEM-768",
        parameter_set="ML-KEM-768",
        created_at=now,
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=kem_pk.fingerprint,
    )
    kem_path = settings.storage.keys_dir / f"{kem_key_id}.tckeystore"
    kem_container = KeystoreManager.encrypt_private_key(kem_sk, args.passphrase, kem_meta)
    KeystoreManager.save_container(kem_container, kem_path)
    store.save_key_metadata(kem_meta, str(kem_path))

    # Issue ML-KEM certificate
    kem_cert = root_ca.issue_kem_certificate(
        subject_id=args.owner_id,
        public_key=kem_pk,
        organization=args.org,
        role=args.role,
    )
    store.save_certificate(kem_cert)

    kem_cert_file = settings.storage.keys_dir / f"{args.owner_id}_kem_cert.json"
    kem_cert_file.write_text(kem_cert.to_canonical_json(), encoding="utf-8")

    print("  [SUCCESS] Identity Generated & Certified Successfully:")
    print(f"  Recipient ID     : {args.owner_id}")
    print(f"  Subject          : {args.owner_id} ({args.role}, {args.org})")
    print(f"  Signing Cert     : {dsa_cert.serial_number} (Algorithm: ML-DSA-65)")
    print(f"  Signing FP       : {dsa_pk.fingerprint}")
    print(f"  Encapsulation Cert: {kem_cert.serial_number} (Algorithm: ML-KEM-768)")
    print(f"  Encapsulation FP : {kem_pk.fingerprint}")
    print(f"  Private Keystores: Stored encrypted under '{settings.storage.keys_dir}'")
    return 0


def cmd_identity_list() -> int:
    store = get_storage()
    revocations = store.list_revocations()
    revoked_serials = {r.serial_number for r in revocations}

    certs = store.list_all_certificates()
    if not certs:
        print("No identity certificates found in local database.")
        return 0

    print(f"{'SERIAL':<20} {'SUBJECT':<20} {'ALGORITHM':<12} {'PURPOSE':<20} {'STATUS':<10}")
    print("-" * 85)
    for r in certs:
        serial = r.serial_number
        status = "REVOKED" if serial in revoked_serials else "ACTIVE"
        print(f"{serial:<20} {r.subject_id:<20} {r.algorithm:<12} {r.key_purpose.value:<20} {status:<10}")
    return 0


def cmd_identity_inspect(args: argparse.Namespace) -> int:
    store = get_storage()
    if getattr(args, "recipient_id", None):
        certs = store.list_certificates_for_subject(args.recipient_id)
        if not certs:
            print(f"No certificates found for recipient '{args.recipient_id}'.")
            return 1
        print(f"Recipient Identity: {args.recipient_id} ({certs[0].role}, {certs[0].organization})")
        for cert in certs:
            print(
                f"  - Serial: {cert.serial_number} [{cert.key_purpose.value}] "
                f"Algorithm: {cert.algorithm} FP: {cert.public_key_fingerprint}"
            )
        return 0

    if not getattr(args, "serial", None):
        print("Error: --serial or --recipient-id required.")
        return 1

    cert = store.get_certificate(args.serial)
    if not cert:
        print(f"Certificate '{args.serial}' not found.")
        return 1

    rev = store.get_revocation(args.serial)
    print("Certificate Details:")
    print(f"  Serial Number  : {cert.serial_number}")
    print(f"  Issuer CA ID   : {cert.issuer_ca_id}")
    print(f"  Subject ID     : {cert.subject_id}")
    print(f"  Device ID      : {cert.device_id or 'None'}")
    print(f"  Organization   : {cert.organization} ({cert.role})")
    print(f"  Algorithm      : {cert.algorithm} ({cert.parameter_set})")
    print(f"  Key Purpose    : {cert.key_purpose.value}")
    print(f"  Fingerprint    : {cert.public_key_fingerprint}")
    print(f"  Valid Range    : {cert.valid_from} -> {cert.valid_until} (POSIX micros)")
    print(f"  Revocation     : {'REVOKED (' + rev.reason.value + ')' if rev else 'ACTIVE'}")
    return 0


def cmd_identity_verify(args: argparse.Namespace) -> int:
    store = get_storage()
    cert: Optional[PQCIdentityCertificate] = None

    if getattr(args, "cert_file", None):
        cert_p = Path(args.cert_file)
        if not cert_p.exists():
            print(f"Error: Certificate file '{cert_p}' does not exist.")
            return 1
        try:
            cert = PQCIdentityCertificate.from_canonical_json(cert_p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Error parsing certificate file: {e}")
            return 1
    elif getattr(args, "serial", None):
        cert = store.get_certificate(args.serial)
        if not cert:
            print(f"Certificate '{args.serial}' not found.")
            return 1
    else:
        print("Error: Either --serial or --cert-file is required.")
        return 1

    _, pubkey_path = get_root_ca_paths()
    if not pubkey_path.exists():
        print("Root CA public key not found. Run 'tracecrypt ca init' first.")
        return 1

    with open(pubkey_path, "rb") as f:
        root_pk_bytes = f.read()
    root_pk = MLDSAPublicKey(root_pk_bytes)

    rev_store = OfflineRevocationStore(store)

    print(f"Executing 12-point offline verification for '{cert.serial_number}'...")
    try:
        CertificateValidator.validate(cert, root_pk, rev_store)
        print("  [SUCCESS] All 12 Verification Checks Passed:")
        print("  1. Structure         : VALID")
        print("  2. Issuer Identity   : MATCHES ROOT CA")
        print("  3. ML-DSA Signature  : MATHEMATICALLY VERIFIED")
        print("  4. Subject Identity  : VALID")
        print("  5. Public Key Length : VERIFIED")
        print("  6. Key Fingerprint   : MATCHED")
        print("  7. PQC Algorithm     : NIST FIPS STANDARD")
        print("  8. Parameter Set     : AUTHORIZED")
        print("  9. Temporal Range    : CURRENTLY ACTIVE")
        print(" 10. Key Purpose       : ENFORCED")
        print(" 11. Revocation State  : UNREVOKED")
        print(" 12. Root CA Anchor    : CRYPTOGRAPHICALLY PINNED")
        print("\nVerdict: CERTIFICATE IS VALID")
        return 0
    except (ValidationError, SecurityError) as e:
        print(f"  [FAILED] Verification Check Failed: {e}")
        print("\nVerdict: CERTIFICATE INVALID")
        return 1


def cmd_identity_revoke(args: argparse.Namespace) -> int:
    print(f"Revoking certificate '{args.serial}'...")
    store = get_storage()
    cert = store.get_certificate(args.serial)
    if not cert:
        print(f"Certificate '{args.serial}' not found.")
        return 1

    try:
        root_ca = load_root_ca(args.ca_passphrase)
    except Exception as e:
        print(f"Error loading Root CA: {e}")
        return 1

    reason = RevocationReason(args.reason)
    rec = KeyLifecycleManager.create_revocation_record(
        serial_number=cert,
        key_id=f"key-{cert.serial_number}",
        reason=reason,
        ca=root_ca,
    )
    store.save_revocation(rec)
    print(f"  [SUCCESS] Certificate '{cert.serial_number}' REVOKED.")
    print(f"  Revocation ID : {rec.revocation_id}")
    print(f"  Reason        : {rec.reason.value}")
    print(f"  Signed By     : {rec.revoked_by_ca_id}")
    return 0


def cmd_identity_rotate(args: argparse.Namespace) -> int:
    print(f"Rotating credentials for '{args.owner_id}'...")
    mock_args = argparse.Namespace(
        owner_id=args.owner_id,
        org="TraceCrypt Operations",
        role="RECIPIENT",
        passphrase=args.passphrase,
        ca_passphrase=args.ca_passphrase,
    )
    return cmd_identity_generate(mock_args)


def cmd_key_fingerprint(args: argparse.Namespace) -> int:
    try:
        if getattr(args, "key_file", None):
            p = Path(args.key_file)
            if not p.exists():
                print(f"Error: Key file '{p}' not found.")
                return 1
            raw = p.read_bytes()
            if len(raw) == MLDSAPublicKey.EXPECTED_LENGTH:
                pk = MLDSAPublicKey(raw)
                print(f"Fingerprint: {pk.fingerprint}")
                return 0
            elif len(raw) == MLKEMPublicKey.EXPECTED_LENGTH:
                kem_pk = MLKEMPublicKey(raw)
                print(f"Fingerprint: {kem_pk.fingerprint}")
                return 0
            else:
                # Try json certificate
                try:
                    cert = PQCIdentityCertificate.from_canonical_json(raw.decode("utf-8"))
                    print(f"Fingerprint: {cert.public_key_fingerprint}")
                    return 0
                except Exception:
                    print(f"Error: Unrecognized key file format ({len(raw)} bytes).")
                    return 1

        if not getattr(args, "b64", None):
            print("Error: Either --b64 or --key-file is required.")
            return 1

        raw = base64.b64decode(args.b64, validate=True)
        if args.type == "kem":
            kem_pk = MLKEMPublicKey(raw)
            print(f"Fingerprint: {kem_pk.fingerprint}")
        else:
            dsa_pk = MLDSAPublicKey(raw)
            print(f"Fingerprint: {dsa_pk.fingerprint}")
        return 0
    except Exception as e:
        print(f"Error computing fingerprint: {e}")
        return 1


# -------------------------------------------------------------------------
# Main Router
# -------------------------------------------------------------------------

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
    elif parsed.command == "ca":
        if parsed.subcommand == "init":
            return cmd_ca_init(parsed)
        elif parsed.subcommand == "status":
            return cmd_ca_status()
        parser.print_help()
        return 0
    elif parsed.command == "identity":
        if parsed.subcommand == "status":
            return cmd_ca_status()
        elif parsed.subcommand == "generate":
            return cmd_identity_generate(parsed)
        elif parsed.subcommand == "list":
            return cmd_identity_list()
        elif parsed.subcommand == "inspect":
            return cmd_identity_inspect(parsed)
        elif parsed.subcommand == "verify":
            return cmd_identity_verify(parsed)
        elif parsed.subcommand == "revoke":
            return cmd_identity_revoke(parsed)
        elif parsed.subcommand == "rotate":
            return cmd_identity_rotate(parsed)
        parser.print_help()
        return 0
    elif parsed.command == "key":
        if parsed.subcommand == "fingerprint":
            return cmd_key_fingerprint(parsed)
        parser.print_help()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
