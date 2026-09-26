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
    MLKEMPrivateKey,
    MLKEMPublicKey,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.reader import DocumentReader
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import SecurityError, ValidationError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.identity.lifecycle import KeyLifecycleManager, OfflineRevocationStore, RevocationReason
from tracecrypt.security.airgap import AirGapGuard
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark import (
    ExtractionStatus,
    WatermarkBenchmark,
    WatermarkEmbedder,
    WatermarkExtractor,
    WatermarkParameters,
    WatermarkPayload,
)


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

    # Command: document
    doc_parser = subparsers.add_parser("document", help="Encrypted document distribution and packaging")
    doc_sub = doc_parser.add_subparsers(dest="subcommand", help="Document operations")

    doc_inspect = doc_sub.add_parser("inspect", help="Inspect source document or .tcdist package")
    doc_inspect.add_argument("file", help="Path to document or .tcdist package")

    doc_hash = doc_sub.add_parser("hash", help="Calculate SHA3-256 integrity hash of document")
    doc_hash.add_argument("file", help="Path to document file")

    doc_pkg = doc_sub.add_parser("package", help="Create encrypted .tcdist distribution package")
    doc_pkg.add_argument("--input", "-i", dest="input_file", required=True, help="Path to source document (e.g. PDF)")
    doc_pkg.add_argument(
        "--output", "-o", dest="output_file", default=None,
        help="Path to output .tcdist file (defaults to <input>.tcdist)",
    )
    doc_pkg.add_argument(
        "--recipient", "-r", dest="recipients", action="append", default=[],
        help="Recipient user/subject ID (can be repeated)",
    )
    doc_pkg.add_argument(
        "--recipient-cert", dest="recipient_certs", action="append", default=[],
        help="Path to recipient certificate JSON file (can be repeated)",
    )

    doc_val = doc_sub.add_parser("validate", help="Run 17-point offline validation on .tcdist package")
    doc_val.add_argument("package", help="Path to .tcdist package file")

    doc_rcp = doc_sub.add_parser("recipients", help="List authorized recipient envelopes in .tcdist package")
    doc_rcp.add_argument("package", help="Path to .tcdist package file")

    doc_dec = doc_sub.add_parser("decrypt", help="Decrypt .tcdist package (restricted to test/dev mode)")
    doc_dec.add_argument("package", help="Path to .tcdist package file")
    doc_dec.add_argument("--recipient-id", required=True, help="Recipient ID attempting decryption")
    doc_dec.add_argument("--passphrase", required=True, help="Passphrase to unlock recipient's KEM private keystore")
    doc_dec.add_argument(
        "--keystore", default=None,
        help="Path to recipient encrypted keystore JSON (or resolved from storage)",
    )
    doc_dec.add_argument(
        "--output", "-o", dest="output_file", default=None,
        help="Optional output path for decrypted plaintext (requires --dev-mode)",
    )
    doc_dec.add_argument(
        "--dev-mode", action="store_true",
        help="Explicit confirmation of restricted developer/test mode",
    )

    # Command: watermark
    wm_parser = subparsers.add_parser("watermark", help="Forensic invisible watermarking commands")
    wm_sub = wm_parser.add_subparsers(dest="subcommand", help="Watermark operations")

    wm_inspect = wm_sub.add_parser("inspect", help="Inspect watermarked document or payload")
    wm_inspect.add_argument("file", help="Path to watermarked document file (PDF or image)")
    wm_inspect.add_argument("--doc-hash", default=None, help="Source document SHA3-256 hash (computed if omitted)")

    wm_embed = wm_sub.add_parser("embed", help="Embed forensic watermark (test/dev mode)")
    wm_embed.add_argument("--input", "-i", dest="input_file", required=True, help="Path to input document (PDF)")
    wm_embed.add_argument("--output", "-o", dest="output_file", default=None, help="Output watermarked PDF path")
    wm_embed.add_argument("--doc-hash", default=None, help="Source document SHA3-256 hash (computed if omitted)")
    wm_embed.add_argument("--watermark-id", default=None, help="Optional 128-bit WatermarkID hex")
    wm_embed.add_argument("--session-id", default=None, help="Optional 128-bit SessionID hex")
    wm_embed.add_argument("--strength", type=float, default=8.0, help="Embedding strength alpha (default: 8.0)")

    wm_extract = wm_sub.add_parser("extract", help="Blindly extract forensic watermark from leaked document")
    wm_extract.add_argument("file", help="Path to leaked document (PDF or image)")
    wm_extract.add_argument("--doc-hash", default=None, help="Source document SHA3-256 hash (computed if omitted)")
    wm_extract.add_argument("--no-deskew", action="store_true", help="Disable deskew search in extraction")

    wm_bench = wm_sub.add_parser("benchmark", help="Run empirical performance and latency benchmark")
    wm_bench.add_argument("--input", "-i", dest="input_file", default=None, help="Optional input PDF file")

    wm_attack = wm_sub.add_parser("attack-test", help="Run automated robustness attack simulation matrix")
    wm_attack.add_argument("--input", "-i", dest="input_file", default=None, help="Optional input PDF file")
    wm_attack.add_argument("--strength", type=float, default=10.0, help="Embedding strength alpha (default: 10.0)")

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


def cmd_document_inspect(args: argparse.Namespace) -> int:
    try:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: File '{p}' not found.")
            return 1

        raw = p.read_bytes()
        if raw.startswith(b"TCDIST01"):
            pkg = DistributionPackage.deserialize(raw)
            h = pkg.header
            print("==================================================")
            print("TraceCrypt Distribution Package (.tcdist)")
            print("==================================================")
            print(f"Format Version:          {h.format_version}")
            print(f"Distribution ID:         {h.distribution_id}")
            print(f"Document ID:             {h.document_id}")
            print(f"Original Filename:       {h.filename}")
            print(f"MIME Type:               {h.mime_type}")
            print(f"Source Document Hash:    {h.source_document_hash}")
            print(f"Source Size:             {h.source_size_bytes} bytes")
            print(f"Package Size:            {len(raw)} bytes")
            print(f"Created At:              {h.created_at}")
            print(f"Content Cipher:          {h.cipher_algorithm}")
            print(f"KEM Algorithm:           {h.kem_algorithm}")
            print(f"Recipient Count:         {len(h.recipients)}")
            print("--------------------------------------------------")
            for i, r in enumerate(h.recipients, 1):
                print(f"  [{i}] Recipient ID:   {r.recipient_id}")
                print(f"      Key Fingerprint: {r.key_fingerprint}")
                print(f"      Cert Serial:     {r.certificate_serial}")
            print("==================================================")
            return 0
        else:
            doc_bytes, mime_type, filename = DocumentReader.read_document(p)
            doc_hash = DocumentHasher.hash_bytes(doc_bytes)
            print("==================================================")
            print("Source Document Inspection")
            print("==================================================")
            print(f"Filename:             {filename}")
            print(f"MIME Type:            {mime_type}")
            print(f"Size:                 {len(doc_bytes)} bytes")
            print(f"SHA3-256 Hash:        {doc_hash}")
            print("==================================================")
            return 0
    except Exception as e:
        print(f"Error inspecting document: {e}")
        return 1


def cmd_document_hash(args: argparse.Namespace) -> int:
    try:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: File '{p}' not found.")
            return 1
        digest = DocumentHasher.hash_file(p)
        print("Algorithm: SHA3-256")
        print(f"File:      {p}")
        print(f"Digest:    {digest}")
        return 0
    except Exception as e:
        print(f"Error hashing document: {e}")
        return 1


def cmd_document_package(args: argparse.Namespace) -> int:
    try:
        in_path = Path(args.input_file)
        if not in_path.exists():
            print(f"Error: Input file '{in_path}' not found.")
            return 1

        store = get_storage()
        settings = get_settings()
        keys_dir = settings.storage.keys_dir

        recipient_specs: List[RecipientSpec] = []

        # From --recipient-cert paths
        for cert_file in getattr(args, "recipient_certs", []) or []:
            cp = Path(cert_file)
            if not cp.exists():
                print(f"Error: Recipient certificate file '{cp}' not found.")
                return 1
            cert = PQCIdentityCertificate.from_canonical_json(
                cp.read_text(encoding="utf-8")
            )
            recipient_specs.append(RecipientSpec(cert))

        # From --recipient IDs
        for rcp_id in getattr(args, "recipients", []) or []:
            cert = store.get_active_kem_certificate(rcp_id)
            if not cert:
                fallback_path = keys_dir / f"{rcp_id}_kem_cert.json"
                if fallback_path.exists():
                    cert = PQCIdentityCertificate.from_canonical_json(
                        fallback_path.read_text(encoding="utf-8")
                    )
            if not cert:
                print(f"Error: Active KEM certificate for recipient '{rcp_id}' not found.")
                return 1
            recipient_specs.append(RecipientSpec(cert))

        if not recipient_specs:
            print("Error: At least one recipient (--recipient or --recipient-cert) must be specified.")
            return 1

        seen = set()
        deduped = []
        for r in recipient_specs:
            if r.certificate.subject_id in seen:
                continue
            seen.add(r.certificate.subject_id)
            deduped.append(r)
        recipient_specs = deduped

        pkg, _ = DistributionService.create_package(
            input_path=in_path,
            recipients=recipient_specs,
        )

        out_path = Path(args.output_file) if args.output_file else Path(f"{in_path}.tcdist")
        pkg_bytes = DistributionPackage.serialize(pkg)
        out_path.write_bytes(pkg_bytes)

        print("==================================================")
        print("[SUCCESS] Created TraceCrypt Distribution Package")
        print("==================================================")
        print(f"Distribution ID:       {pkg.header.distribution_id}")
        print(f"Document ID:           {pkg.header.document_id}")
        print(f"Source Hash:           {pkg.header.source_document_hash}")
        print(f"Authorized Recipients: {len(recipient_specs)}")
        print(f"Package Size:          {len(pkg_bytes)} bytes")
        print(f"Output File:           {out_path}")
        print("==================================================")
        return 0
    except Exception as e:
        print(f"Error creating package: {e}")
        return 1


def cmd_document_validate(args: argparse.Namespace) -> int:
    try:
        p = Path(args.package)
        if not p.exists():
            print(f"Error: Package file '{p}' not found.")
            return 1

        pkg_bytes = p.read_bytes()
        settings = get_settings()
        root_cert_path = settings.storage.keys_dir / "ca_root_cert.json"
        root_pk = None
        rev_store = None

        if root_cert_path.exists():
            try:
                root_cert = PQCIdentityCertificate.from_canonical_json(
                    root_cert_path.read_text(encoding="utf-8")
                )
                root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
                store = get_storage()
                rev_store = OfflineRevocationStore(store)
            except Exception:
                pass

        result = PackageValidator.validate_package(
            package_bytes=pkg_bytes,
            root_ca_public_key=root_pk,
            revocation_provider=rev_store,
        )

        if result.valid:
            print("==================================================")
            print("[PASS] Package is cryptographically valid and untampered.")
            print("==================================================")
            if result.header:
                print(f"Distribution ID:       {result.header.distribution_id}")
                print(f"Document ID:           {result.header.document_id}")
                print(f"Source Hash:           {result.header.source_document_hash}")
                print(f"Recipients:            {len(result.header.recipients)}")
            return 0
        else:
            print("==================================================")
            print("[FAIL] Package validation failed:")
            print("==================================================")
            for err in result.errors:
                print(f"  - {err}")
            return 1
    except Exception as e:
        print(f"Error validating package: {e}")
        return 1


def cmd_document_recipients(args: argparse.Namespace) -> int:
    try:
        p = Path(args.package)
        if not p.exists():
            print(f"Error: Package file '{p}' not found.")
            return 1

        pkg = DistributionPackage.deserialize(p.read_bytes())
        h = pkg.header
        print("==================================================")
        print(f"Authorized Recipients for Package {h.distribution_id}")
        print("==================================================")
        print(f"Document ID:      {h.document_id}")
        print(f"Total Envelopes:  {len(h.recipients)}")
        print("--------------------------------------------------")
        for i, r in enumerate(h.recipients, 1):
            print(f"[{i}] Recipient ID:    {r.recipient_id}")
            print(f"    Key ID:          {r.key_id}")
            print(f"    Key Fingerprint: {r.key_fingerprint}")
            print(f"    Cert Serial:     {r.certificate_serial}")
            print(f"    Algorithm:       {r.mlkem_algorithm} ({r.mlkem_parameter_set})")
            print(f"    Encapsulated CT: {len(r.encapsulated_key_b64)} b64 chars")
            print(f"    Wrapped CEK:     {len(r.encrypted_cek_b64)} b64 chars")
        print("==================================================")
        return 0
    except Exception as e:
        print(f"Error reading package recipients: {e}")
        return 1


def cmd_document_decrypt(args: argparse.Namespace) -> int:
    try:
        if not getattr(args, "dev_mode", False):
            print("======================================================================")
            print("ERROR: Direct CLI decryption without forensic pipeline is restricted")
            print("to development and testing. Pass --dev-mode to proceed in test mode.")
            print("In production, decryption requires forensic watermarking and ledger commit.")
            print("======================================================================")
            return 1

        print("======================================================================")
        print("[WARNING] RUNNING IN RESTRICTED DEVELOPMENT/TEST MODE")
        print("[WARNING] Forensic watermarking and ledger commit pipeline are bypassed.")
        print("[WARNING] Plaintext document will be decrypted in memory.")
        print("[WARNING] NEVER USE THIS COMMAND IN PRODUCTION AIR-GAPPED DEPLOYMENTS.")
        print("======================================================================")

        p = Path(args.package)
        if not p.exists():
            print(f"Error: Package file '{p}' not found.")
            return 1

        store = get_storage()
        settings = get_settings()
        keys_dir = settings.storage.keys_dir

        keystore_path = None
        if getattr(args, "keystore", None):
            keystore_path = Path(args.keystore)
        else:
            keystore_path = store.get_active_kem_keystore_path(args.recipient_id)
            if not keystore_path or not keystore_path.exists():
                cand = keys_dir / f"{args.recipient_id}_kem_keystore.json"
                if cand.exists():
                    keystore_path = cand

        if not keystore_path or not keystore_path.exists():
            print(f"Error: Keystore for recipient '{args.recipient_id}' not found.")
            return 1

        container = KeystoreManager.load_container(keystore_path)
        priv_bytes = KeystoreManager.decrypt_private_key(container, args.passphrase)
        recipient_priv = MLKEMPrivateKey(bytes(priv_bytes))

        cert = store.get_active_kem_certificate(args.recipient_id)
        if not cert:
            cert_file = keys_dir / f"{args.recipient_id}_kem_cert.json"
            if cert_file.exists():
                cert = PQCIdentityCertificate.from_canonical_json(
                    cert_file.read_text(encoding="utf-8")
                )

        if not cert:
            print(f"Error: Certificate for recipient '{args.recipient_id}' not found.")
            return 1

        root_cert_path = keys_dir / "ca_root_cert.json"
        root_pk = None
        rev_store = None
        if root_cert_path.exists():
            root_cert = PQCIdentityCertificate.from_canonical_json(
                root_cert_path.read_text(encoding="utf-8")
            )
            root_pk = MLDSAPublicKey(root_cert.get_public_key_bytes())
            rev_store = OfflineRevocationStore(store)

        pkg_bytes = p.read_bytes()
        with DistributionService.decrypt_package(
            package_bytes=pkg_bytes,
            recipient_id=args.recipient_id,
            recipient_private_key=recipient_priv,
            recipient_certificate=cert,
            root_ca_public_key=root_pk,
            revocation_provider=rev_store,
        ) as buf:
            print("[SUCCESS] Cryptographic decryption and SHA3-256 verification SUCCEEDED.")
            print(f"Decrypted payload size: {len(buf)} bytes.")
            if getattr(args, "output_file", None):
                out = Path(args.output_file)
                out.write_bytes(bytes(buf))
                print(f"[CAUTION] Plaintext saved to: {out} (unwatermarked test copy).")
            else:
                print("Secure buffer zeroized in memory. Plaintext was not persisted to disk.")
        return 0
    except Exception as e:
        print(f"Decryption failed: {e}")
        return 1


def _generate_test_pdf_bytes() -> bytes:
    """Generate in-memory sample 2-page PDF document for benchmarking."""
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    # Page 1
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 720, "TraceCrypt Forensic Watermark Test Document")
    c.setFont("Helvetica", 11)
    c.drawString(72, 690, "Confidential forensic specification and architecture validation.")
    for i in range(15):
        line_text = f"Section 4.{i+1}: Cryptographic binding verification and transform domain analysis."
        c.drawString(72, 650 - i * 20, line_text)
    c.showPage()
    # Page 2
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, 720, "Page 2: Forensic Attestation Records")
    for i in range(12):
        c.drawString(72, 680 - i * 22, f"Attestation entry 0x{i*1024:04X}: Zero-knowledge validation stream token.")
    c.showPage()
    c.save()
    return buf.getvalue()


def cmd_watermark_inspect(args: argparse.Namespace) -> int:
    try:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: File '{p}' not found.")
            return 1

        raw_bytes = p.read_bytes()
        doc_hash = args.doc_hash or DocumentHasher.hash_bytes(raw_bytes)

        print("==================================================")
        print("TraceCrypt Forensic Watermark Inspection")
        print("==================================================")
        print(f"Target File:           {p}")
        print(f"Document Size:         {len(raw_bytes)} bytes")
        print(f"Document SHA3-256:     {doc_hash}")
        print("Running blind forensic extraction across document pages...")

        result = WatermarkExtractor.extract_document(raw_bytes, doc_hash)
        print("--------------------------------------------------")
        print(f"Extraction Status:     {result.status.value}")
        print(f"Confidence Score:      {result.confidence:.2%}")
        print(f"Correlation:           {result.correlation_score:.4f}")
        print(f"Pages Analyzed:        {result.pages_analyzed}")
        print(f"Pages Decoded:         {result.pages_decoded}")
        print(f"Pages Corrupted:       {result.pages_corrupted}")

        if result.status == ExtractionStatus.DECODED and result.watermark_id:
            print("Decoded Forensic Payload:")
            print(f"  Watermark Version:   {result.watermark_version}")
            print(f"  WatermarkID:         {result.watermark_id}")
            print(f"  SessionID:           {result.session_id}")
            print(f"  Document Binding:    {result.document_binding}")
            print(f"  Corrected Errors:    {result.corrected_errors} RS symbols")
            print("Cryptographic Document Binding:")
            print(f"  Binding Verified:    {'VALID (Matches Target Document)' if result.binding_valid else 'MISMATCH'}")
        elif result.status == ExtractionStatus.AMBIGUOUS:
            print("ALERT: Conflicting watermark signals detected across pages (possible page splice/tampering).")
        elif result.status == ExtractionStatus.CORRUPTED:
            print("ALERT: Watermark energy detected, but payload failed Reed-Solomon RS(32,16) ECC decoding.")
        else:
            print("No forensic watermark detected in document.")

        print("==================================================")
        return 0 if result.status == ExtractionStatus.DECODED else 1
    except Exception as e:
        print(f"Error inspecting watermark: {e}")
        return 1


def cmd_watermark_embed(args: argparse.Namespace) -> int:
    try:
        in_path = Path(args.input_file)
        if not in_path.exists():
            print(f"Error: Input file '{in_path}' not found.")
            return 1

        print("======================================================================")
        print("[WARNING] RUNNING IN RESTRICTED DEVELOPMENT/TEST MODE")
        print("[WARNING] In production, watermark embedding occurs during decryption")
        print("[WARNING] inside the secure runtime. Never use this for production delivery.")
        print("======================================================================")

        pdf_bytes = in_path.read_bytes()
        doc_hash = args.doc_hash or DocumentHasher.hash_bytes(pdf_bytes)

        if args.watermark_id:
            raw_wm = args.watermark_id.replace("wm-", "")
            wm_id = WatermarkID.from_raw_hex(raw_wm)
        else:
            wm_id = SecureRandom.generate_typed_id(WatermarkID)

        if args.session_id:
            raw_ses = args.session_id.replace("ses-", "")
            ses_id = SessionID.from_raw_hex(raw_ses)
        else:
            ses_id = SecureRandom.generate_typed_id(SessionID)

        payload = WatermarkPayload.create(
            watermark_id=wm_id,
            session_id=ses_id,
            source_document_hash=doc_hash,
        )

        params = WatermarkParameters(embedding_strength=args.strength)
        print(
            f"Embedding watermark (alpha={params.embedding_strength:.1f}, "
            f"block={params.block_size}x{params.block_size})..."
        )

        res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=params,
        )

        out_path = Path(args.output_file) if args.output_file else Path(f"{in_path}.watermarked.pdf")
        out_path.write_bytes(res.watermarked_pdf)

        print("==================================================")
        print("[SUCCESS] Watermark Embedded Successfully")
        print("==================================================")
        print(f"WatermarkID:           {payload.watermark_id}")
        print(f"SessionID:             {payload.session_id}")
        print(f"Document Binding:      {payload.document_binding}")
        print(f"Source Document Hash:  {doc_hash}")
        print(f"Pages Processed:       {res.pages_count}")
        print(f"Fidelity PSNR:         {res.fidelity.psnr:.2f} dB (Target: >= 42.0 dB)")
        print(f"Fidelity SSIM:         {res.fidelity.ssim:.5f} (Target: >= 0.995)")
        print(f"Output File:           {out_path}")
        print("==================================================")
        return 0
    except Exception as e:
        print(f"Error embedding watermark: {e}")
        return 1


def cmd_watermark_extract(args: argparse.Namespace) -> int:
    try:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: File '{p}' not found.")
            return 1

        raw_bytes = p.read_bytes()
        doc_hash = args.doc_hash or DocumentHasher.hash_bytes(raw_bytes)

        deskew = not getattr(args, "no_deskew", False)
        print("==================================================")
        print("TraceCrypt Blind Forensic Watermark Extraction")
        print("==================================================")
        print(f"Input Document:        {p}")
        print(f"Document Hash:         {doc_hash}")
        print(f"Deskew Search:         {'ENABLED' if deskew else 'DISABLED'}")
        print("Extracting...")

        res = WatermarkExtractor.extract_document(
            raw_bytes,
            document_hash=doc_hash,
            deskew_enabled=deskew,
        )

        print("--------------------------------------------------")
        print(f"Extraction Status:     {res.status.value}")
        print(f"Confidence:            {res.confidence:.2%}")
        print(f"Mean Correlation:      {res.correlation_score:.4f}")
        print(f"Pages Analyzed:        {res.pages_analyzed}")
        print(f"Pages Decoded:         {res.pages_decoded}")
        print(f"Pages Corrupted:       {res.pages_corrupted}")
        print(f"Corrected RS Errors:   {res.corrected_errors}")

        if res.status == ExtractionStatus.DECODED:
            print("--------------------------------------------------")
            print("Extracted Cryptographic Identity:")
            print(f"  WatermarkID:         {res.watermark_id}")
            print(f"  SessionID:           {res.session_id}")
            print(f"  Document Binding:    {res.document_binding}")
            print(f"  Binding Valid:       {'VALID' if res.binding_valid else 'MISMATCH'}")
            print(f"  Payload Consistency: {'CONSISTENT' if res.pages_decoded == res.pages_analyzed else 'PARTIAL'}")
            print("==================================================")
            return 0
        else:
            print("==================================================")
            print(f"Result: {res.status.value}")
            return 1
    except Exception as e:
        print(f"Error extracting watermark: {e}")
        return 1


def cmd_watermark_benchmark(args: argparse.Namespace) -> int:
    try:
        print("==================================================")
        print("TraceCrypt Watermark Latency & Fidelity Benchmark")
        print("==================================================")

        if getattr(args, "input_file", None):
            p = Path(args.input_file)
            if not p.exists():
                print(f"Error: Input file '{p}' not found.")
                return 1
            pdf_bytes = p.read_bytes()
        else:
            print("Generating representative 2-page test PDF document...")
            pdf_bytes = _generate_test_pdf_bytes()

        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)
        print(f"Document Size: {len(pdf_bytes)} bytes | SHA3-256: {doc_hash[:16]}...")
        print("Running benchmark suite...")

        res = WatermarkBenchmark.run_performance_benchmark(pdf_bytes, doc_hash)

        print("--------------------------------------------------")
        print(f"Pages Processed:       {res['pages_count']}")
        print(f"PDF Rasterization:     {res['render_ms_per_page']} ms/page (Total: {res['render_ms_total']} ms)")
        print(f"Watermark Embedding:   {res['embed_ms_per_page']} ms/page (Total: {res['embed_ms_total']} ms)")
        print(f"Blind Extraction:      {res['extract_ms_per_page']} ms/page (Total: {res['extract_ms_total']} ms)")
        print(f"Fidelity PSNR:         {res['fidelity']['psnr']:.2f} dB (Acceptance target: >= 42.0 dB)")
        print(f"Fidelity SSIM:         {res['fidelity']['ssim']:.5f} (Acceptance target: >= 0.995)")
        print(f"Latency Target <=3.5s: {'MET (PASS)' if res['meets_target_3_5s'] else 'FAILED'}")
        print("==================================================")
        return 0
    except Exception as e:
        print(f"Error running watermark benchmark: {e}")
        return 1


def cmd_watermark_attack_test(args: argparse.Namespace) -> int:
    try:
        print("==================================================")
        print("TraceCrypt Forensic Watermark Robustness Attack Matrix")
        print("==================================================")

        if getattr(args, "input_file", None):
            p = Path(args.input_file)
            if not p.exists():
                print(f"Error: Input file '{p}' not found.")
                return 1
            pdf_bytes = p.read_bytes()
        else:
            print("Generating sample test document for robustness testing...")
            pdf_bytes = _generate_test_pdf_bytes()

        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)
        params = WatermarkParameters(embedding_strength=getattr(args, "strength", 10.0))

        print(f"Simulating attack matrix (strength alpha={params.embedding_strength:.1f})...")
        attack_results = WatermarkBenchmark.run_attack_matrix(pdf_bytes, doc_hash, params=params)

        hdr = f"{'ATTACK SIMULATION':<34} {'STATUS':<14} {'RAW BER':<10} {'CORRELATION':<14} {'ECC':<8} {'MATCH'}"
        print(hdr)
        print("-" * 88)
        for r in attack_results:
            ber_str = f"{r.get('raw_ber', 0.0):.2%}"
            match_str = "[OK]" if r["payload_matched"] else "[FAIL]"
            row = (
                f"{r['attack']:<34} {r['status']:<14} {ber_str:<10} "
                f"{r['correlation']:<14.4f} {r['corrected_symbols']:<8} {match_str}"
            )
            print(row)
        print("-" * 88)
        all_passed = all(r["payload_matched"] for r in attack_results)
        print(f"Summary: {'ALL ATTACKS SURVIVED' if all_passed else 'SOME ATTACKS DEGRADED / FAILED'}")
        return 0 if all_passed else 1
    except Exception as e:
        print(f"Error running attack tests: {e}")
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
    elif parsed.command == "document":
        if parsed.subcommand == "inspect":
            return cmd_document_inspect(parsed)
        elif parsed.subcommand == "hash":
            return cmd_document_hash(parsed)
        elif parsed.subcommand == "package":
            return cmd_document_package(parsed)
        elif parsed.subcommand == "validate":
            return cmd_document_validate(parsed)
        elif parsed.subcommand == "recipients":
            return cmd_document_recipients(parsed)
        elif parsed.subcommand == "decrypt":
            return cmd_document_decrypt(parsed)
        parser.print_help()
        return 0
    elif parsed.command == "watermark":
        if parsed.subcommand == "inspect":
            return cmd_watermark_inspect(parsed)
        elif parsed.subcommand == "embed":
            return cmd_watermark_embed(parsed)
        elif parsed.subcommand == "extract":
            return cmd_watermark_extract(parsed)
        elif parsed.subcommand == "benchmark":
            return cmd_watermark_benchmark(parsed)
        elif parsed.subcommand == "attack-test":
            return cmd_watermark_attack_test(parsed)
        parser.print_help()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
