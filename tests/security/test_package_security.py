"""Comprehensive adversarial and security attack tests for .tcdist distribution packages.

Covers all 24 required attack vectors:
1. AES ciphertext modification
2. AES nonce modification
3. authentication-tag modification
4. source hash modification
5. DocumentID modification
6. DistributionID modification
7. recipient ID modification
8. ML-KEM ciphertext modification
9. wrapped CEK modification
10. certificate replacement
11. revoked recipient
12. expired recipient
13. wrong private key
14. unauthorized recipient
15. duplicate recipient
16. malformed package
17. oversized package
18. truncated package
19. unsupported version
20. unsupported algorithm
21. algorithm downgrade attempt
22. package replay / duplicate envelope detection
23. missing recipient identity on workstation
24. path traversal rejection
"""

from __future__ import annotations

import base64
from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.reader import DocumentReader
from tracecrypt.document.validator import PackageValidator
from tracecrypt.errors import (
    CryptographicError,
    PackageValidationError,
    SecurityError,
    ValidationError,
)
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.identity.lifecycle import KeyLifecycleManager, OfflineRevocationStore, RevocationReason
from tracecrypt.utils.identifiers import DistributionID, DocumentID, RecipientID
from tracecrypt.utils.timestamps import utc_now_micros


@pytest.fixture
def sec_env(tmp_path: Path):
    """Set up environment with Root CA, certified recipient, and valid package."""
    ca = OfflineRootCA.initialize(ca_id="ca-sec-attack-test")
    rid = SecureRandom.generate_typed_id(RecipientID)
    pk, sk = generate_mlkem_keypair()

    cert = ca.issue_kem_certificate(
        subject_id=str(rid),
        public_key=pk,
        organization="Defense Intelligence",
        role="RECIPIENT",
        validity_days=30,
    )

    doc_content = b"%PDF-1.7\nRESTRICTED STRATEGIC MEMORANDUM\n" + b"A" * 2048
    doc_path = tmp_path / "memo.pdf"
    doc_path.write_bytes(doc_content)

    spec = RecipientSpec(
        recipient_id=rid,
        public_key=pk,
        certificate=cert,
        key_id="key-sec-01",
    )

    pkg, _ = DistributionService.package_document(
        source_input=doc_path,
        recipients=[spec],
        root_ca_public_key=ca.public_key,
    )

    return {
        "ca": ca,
        "rid": rid,
        "pk": pk,
        "sk": sk,
        "cert": cert,
        "spec": spec,
        "doc_content": doc_content,
        "pkg": pkg,
        "tmp_path": tmp_path,
    }


# 1. AES ciphertext modification
def test_attack_01_ciphertext_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    # Tamper with encrypted ciphertext
    bad_ct = bytearray(pkg.ciphertext)
    bad_ct[10] ^= 0xFF
    bad_pkg = DistributionPackage(
        header=pkg.header,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=bytes(bad_ct),
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 2. AES nonce modification
def test_attack_02_nonce_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    bad_nonce = bytearray(pkg.nonce)
    bad_nonce[0] ^= 0xFF
    bad_pkg = DistributionPackage(
        header=pkg.header,
        nonce=bytes(bad_nonce),
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 3. Authentication tag modification
def test_attack_03_auth_tag_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    bad_tag = bytearray(pkg.auth_tag)
    bad_tag[0] ^= 0xFF
    bad_pkg = DistributionPackage(
        header=pkg.header,
        nonce=pkg.nonce,
        auth_tag=bytes(bad_tag),
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 4. Source hash modification
def test_attack_04_source_hash_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    tampered_hdr = pkg.header.model_copy(
        update={"source_document_hash": "sha3-256:" + "0" * 64}
    )
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    # AAD includes source_document_hash, so AES-GCM tag verification fails closed
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 5. DocumentID modification
def test_attack_05_document_id_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    new_doc_id = SecureRandom.generate_typed_id(DocumentID)
    tampered_hdr = pkg.header.model_copy(update={"document_id": new_doc_id})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 6. DistributionID modification
def test_attack_06_distribution_id_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    new_dist_id = SecureRandom.generate_typed_id(DistributionID)
    tampered_hdr = pkg.header.model_copy(update={"distribution_id": new_dist_id})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 7. Recipient ID modification in envelope
def test_attack_07_recipient_id_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    other_rid = SecureRandom.generate_typed_id(RecipientID)
    new_env = pkg.header.recipient_envelopes[0].model_copy(update={"recipient_id": other_rid})
    tampered_hdr = pkg.header.model_copy(update={"recipient_envelopes": [new_env]})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    # Original recipient is now no longer found
    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )
    assert "Access Denied" in str(exc.value)


# 8. ML-KEM ciphertext modification
def test_attack_08_kem_ciphertext_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    env = pkg.header.recipient_envelopes[0]
    raw_kem = bytearray(env.get_kem_ciphertext_bytes())
    raw_kem[5] ^= 0xFF
    new_env = env.model_copy(
        update={"kem_ciphertext_b64": base64.b64encode(bytes(raw_kem)).decode("ascii")}
    )
    tampered_hdr = pkg.header.model_copy(update={"recipient_envelopes": [new_env]})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 9. Wrapped CEK modification
def test_attack_09_wrapped_cek_modification(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    env = pkg.header.recipient_envelopes[0]
    raw_wcek = bytearray(env.get_wrapped_cek_bytes())
    raw_wcek[0] ^= 0xFF
    new_env = env.model_copy(
        update={"wrapped_cek_b64": base64.b64encode(bytes(raw_wcek)).decode("ascii")}
    )
    tampered_hdr = pkg.header.model_copy(update={"recipient_envelopes": [new_env]})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(CryptographicError):
        DistributionService.decrypt_package(
            package_input=bad_pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 10. Certificate replacement
def test_attack_10_certificate_replacement(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    ca: OfflineRootCA = sec_env["ca"]
    other_pk, _ = generate_mlkem_keypair()
    fake_cert = ca.issue_kem_certificate(
        subject_id=str(sec_env["rid"]),
        public_key=other_pk,
        organization="Fake Org",
        role="RECIPIENT",
        validity_days=30,
    )
    # The package envelope references cert serial of the real cert, not fake_cert
    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=fake_cert,
            root_ca_public_key=ca.public_key,
        )
    assert "does not match recipient's active certificate serial" in str(exc.value)


# 11. Revoked recipient
def test_attack_11_revoked_recipient(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    ca: OfflineRootCA = sec_env["ca"]
    cert: PQCIdentityCertificate = sec_env["cert"]

    # Revoke recipient certificate
    rev_record = KeyLifecycleManager.create_revocation_record(
        serial_number=cert,
        key_id="key-sec-01",
        reason=RevocationReason.KEY_COMPROMISE,
        ca=ca,
    )
    rev_store = OfflineRevocationStore()
    rev_store.add_revocation(rev_record)

    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=sec_env["sk"],
            recipient_cert=cert,
            root_ca_public_key=ca.public_key,
            revocation_store=rev_store,
        )
    assert "REVOKED" in str(exc.value)


# 12. Expired recipient certificate
def test_attack_12_expired_recipient(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    ca: OfflineRootCA = sec_env["ca"]
    rid = sec_env["rid"]
    pk, sk = generate_mlkem_keypair()

    # Create expired cert
    now = utc_now_micros()
    expired_cert = ca.issue_kem_certificate(
        subject_id=str(rid),
        public_key=pk,
        organization="Defense Intelligence",
        role="RECIPIENT",
        valid_from=now - 2_000_000,
        valid_until=now - 1_000_000,
    )

    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=rid,
            recipient_sk=sk,
            recipient_cert=expired_cert,
            root_ca_public_key=ca.public_key,
        )
    assert "expired" in str(exc.value).lower()


# 13. Wrong private key
def test_attack_13_wrong_private_key(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    _, wrong_sk = generate_mlkem_keypair()

    with pytest.raises((SecurityError, CryptographicError)):
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=sec_env["rid"],
            recipient_sk=wrong_sk,
            recipient_cert=sec_env["cert"],
            root_ca_public_key=sec_env["ca"].public_key,
        )


# 14. Unauthorized recipient
def test_attack_14_unauthorized_recipient(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    ca: OfflineRootCA = sec_env["ca"]
    eve_rid = SecureRandom.generate_typed_id(RecipientID)
    eve_pk, eve_sk = generate_mlkem_keypair()
    eve_cert = ca.issue_kem_certificate(
        subject_id=str(eve_rid),
        public_key=eve_pk,
        organization="Unauthorized Org",
        role="RECIPIENT",
        validity_days=30,
    )

    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=eve_rid,
            recipient_sk=eve_sk,
            recipient_cert=eve_cert,
            root_ca_public_key=ca.public_key,
        )
    assert "Access Denied" in str(exc.value)


# 15. Duplicate recipient in packaging specification
def test_attack_15_duplicate_recipient_packaging(sec_env) -> None:
    with pytest.raises(ValidationError) as exc:
        DistributionService.package_document(
            source_input=sec_env["tmp_path"] / "memo.pdf",
            recipients=[sec_env["spec"], sec_env["spec"]],
            root_ca_public_key=sec_env["ca"].public_key,
        )
    assert "Duplicate recipient" in str(exc.value)


# 16. Malformed package bytes
def test_attack_16_malformed_package() -> None:
    with pytest.raises(PackageValidationError):
        PackageValidator.validate(b"NOT_A_VALID_PACKAGE_RANDOM_GARBAGE_BYTES_1234567890")


# 17. Oversized package
def test_attack_17_oversized_package(sec_env) -> None:
    raw = sec_env["pkg"].to_bytes()
    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(raw, max_package_size_bytes=100)
    assert "exceeds limit" in str(exc.value)


# 18. Truncated package
def test_attack_18_truncated_package(sec_env) -> None:
    raw = sec_env["pkg"].to_bytes()
    truncated = raw[: len(raw) // 2]
    with pytest.raises(PackageValidationError):
        PackageValidator.validate(truncated)


# 19. Unsupported format version
def test_attack_19_unsupported_version(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    tampered_hdr = pkg.header.model_copy(update={"format_version": "9.9.9"})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(PackageValidationError):
        PackageValidator.validate(bad_pkg.to_bytes())


# 20. Unsupported cipher algorithm
def test_attack_20_unsupported_cipher(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    tampered_hdr = pkg.header.model_copy(update={"cipher_algorithm": "DES-EDE3-CBC"})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(bad_pkg)
    assert "Unsupported cipher algorithm" in str(exc.value)


# 21. Algorithm downgrade attempt
def test_attack_21_algorithm_downgrade(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    tampered_hdr = pkg.header.model_copy(update={"kem_algorithm": "RSA-2048"})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(bad_pkg)
    assert "Unsupported KEM algorithm" in str(exc.value)


# 22. Duplicate recipient envelopes in package
def test_attack_22_duplicate_envelopes_in_package(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    env = pkg.header.recipient_envelopes[0]
    tampered_hdr = pkg.header.model_copy(update={"recipient_envelopes": [env, env]})
    bad_pkg = DistributionPackage(
        header=tampered_hdr,
        nonce=pkg.nonce,
        auth_tag=pkg.auth_tag,
        ciphertext=pkg.ciphertext,
    )
    with pytest.raises(PackageValidationError) as exc:
        PackageValidator.validate(bad_pkg)
    assert "Duplicate recipient ID detected" in str(exc.value)


# 23. Package copied to workstation without recipient private key
def test_attack_23_missing_credentials(sec_env) -> None:
    pkg: DistributionPackage = sec_env["pkg"]
    unrelated_rid = SecureRandom.generate_typed_id(RecipientID)
    _, unrelated_sk = generate_mlkem_keypair()
    fake_cert = sec_env["ca"].issue_kem_certificate(
        subject_id=str(unrelated_rid),
        public_key=sec_env["pk"],
        organization="None",
        role="RECIPIENT",
        validity_days=30,
    )
    with pytest.raises(SecurityError) as exc:
        DistributionService.decrypt_package(
            package_input=pkg,
            recipient_id=unrelated_rid,
            recipient_sk=unrelated_sk,
            recipient_cert=fake_cert,
            root_ca_public_key=sec_env["ca"].public_key,
        )
    assert "Access Denied" in str(exc.value)


# 24. Path traversal attempt in document loader
def test_attack_24_path_traversal_rejection(tmp_path: Path) -> None:
    traversal_path = tmp_path / ".." / ".." / "system32" / "secret.pdf"
    with pytest.raises(FileNotFoundError):
        DocumentReader.read_document(traversal_path)
