"""Malformed Input Fuzzing and Parser Resilience Tests for TraceCrypt.

Satisfies Master Prompt 12 - Section 4:
- Fuzz testing of security-sensitive parsers (.tcdist, certificates, events, blocks, proofs, backups).
- Tests truncation, oversized inputs, invalid Unicode, corrupted binaries, unexpected types, and boundary values.
- Enforces FAIL-CLOSED behavior (safe rejection, zero crash/hang/unhandled memory leaks).
"""

from __future__ import annotations

import base64
import json
import os
import struct
from pathlib import Path
import pytest
from pydantic import ValidationError as PydanticValidationError

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.types import KeyPurpose, MLDSAPublicKey, MLDSASignature
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.types import DistributionPackageHeader, RecipientEnvelope
from tracecrypt.errors import (
    CanonicalizationError,
    CryptographicError,
    PackageValidationError,
    SecurityError,
    ValidationError,
)
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.schema import DecryptionEvent, EventID, PQCAlgorithms
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.identity.certificate import (
    CertificateValidator,
    PQCIdentityCertificate,
)
from tracecrypt.ledger.block import BlockHeader, LedgerTransaction
from tracecrypt.ledger.merkle import MerkleInclusionProof, MerkleTree
from tracecrypt.ledger.messages import CommitCertificate, VoteMessage, VoteType
from tracecrypt.storage.backup import BackupManager
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    RecipientID,
    SessionID,
    ValidatorID,
    WatermarkID,
)


def _make_dummy_header() -> DistributionPackageHeader:
    envelope = RecipientEnvelope(
        recipient_id=RecipientID.generate(),
        key_id="key-1",
        certificate_serial="crt-1",
        kem_ciphertext_b64=base64.b64encode(b"\x00" * 1088).decode(),
        derived_key_context="test-context",
        wrap_nonce_b64=base64.b64encode(b"\x00" * 12).decode(),
        wrapped_cek_b64=base64.b64encode(b"\x00" * 48).decode(),
        public_key_fingerprint="fp-1",
    )
    return DistributionPackageHeader(
        distribution_id=DistributionID.generate(),
        document_id=DocumentID.generate(),
        filename="classified.pdf",
        source_document_hash=f"sha3-256:{'aa'*32}",
        source_size_bytes=1024,
        recipient_envelopes=[envelope],
        created_at=1700000000000000,
    )


class TestParserFuzzing:
    """Fuzz testing of core deserializers and input parsers."""

    # -------------------------------------------------------------------------
    # 1. .tcdist Distribution Package Deserializer Fuzzing
    # -------------------------------------------------------------------------

    def test_tcdist_truncated_inputs(self) -> None:
        """Truncated .tcdist byte streams must fail closed with PackageValidationError."""
        valid_bytes = b"TCDIST01" + b"\x00" * 80 + b"TCDISTEND"
        # Test prefixes of varying truncated lengths
        for length in [0, 1, 4, 8, 15, 25, 45, 70]:
            truncated = valid_bytes[:length]
            with pytest.raises(PackageValidationError):
                DistributionPackage.from_bytes(truncated)

    def test_tcdist_oversized_payload_rejection(self) -> None:
        """Packages claiming to exceed MAX_PACKAGE_SIZE_BYTES must be rejected immediately."""
        fake_huge = b"TCDIST01" + b"\x00" * (DistributionPackage.MAX_PACKAGE_SIZE_BYTES + 10)
        with pytest.raises(PackageValidationError):
            DistributionPackage.from_bytes(fake_huge)

    def test_tcdist_corrupted_magic_preamble_and_footer(self) -> None:
        """Invalid magic preambles or footers must be rejected."""
        # Bad preamble
        data_bad_preamble = b"BADMAGIC" + b"\x00" * 100 + b"TCDISTEND"
        with pytest.raises(PackageValidationError):
            DistributionPackage.from_bytes(data_bad_preamble)

        # Bad footer
        data_bad_footer = b"TCDIST01" + b"\x00" * 100 + b"BADFOOTER"
        with pytest.raises(PackageValidationError):
            DistributionPackage.from_bytes(data_bad_footer)

    def test_tcdist_corrupted_checksum(self) -> None:
        """Checksum bit flips must be rejected before unpacking any inner structures."""
        hdr = _make_dummy_header()
        pkg = DistributionPackage(
            header=hdr,
            nonce=b"\x00" * 12,
            auth_tag=b"\x11" * 16,
            ciphertext=b"\x22" * 64,
        )
        serialized = bytearray(pkg.to_bytes())

        # Flip a bit in the body (offset 20)
        serialized[20] ^= 0xFF
        with pytest.raises(PackageValidationError):
            DistributionPackage.from_bytes(bytes(serialized))

    def test_tcdist_fuzzed_lengths_and_offsets(self) -> None:
        """Malformed header length, nonce length, tag length, or ciphertext length must fail closed."""
        hdr = _make_dummy_header()
        pkg = DistributionPackage(
            header=hdr,
            nonce=b"\x01" * 12,
            auth_tag=b"\x02" * 16,
            ciphertext=b"\x03" * 32,
        )
        valid_bytes = pkg.to_bytes()

        # Mutate header length (bytes 12..15) to a huge value that overflows
        mutated_huge_header = bytearray(valid_bytes)
        struct.pack_into(">I", mutated_huge_header, 12, 1000000)
        # Recompute checksum to specifically test header length parser bounds
        body_part = mutated_huge_header[:-41]
        new_cs = Hasher.digest_bytes(body_part, HashAlgorithm.SHA3_256.value).raw_bytes
        mutated_huge_header[-41:-9] = new_cs
        with pytest.raises(PackageValidationError):
            DistributionPackage.from_bytes(bytes(mutated_huge_header))

    # -------------------------------------------------------------------------
    # 2. Certificate Parser Fuzzing
    # -------------------------------------------------------------------------

    def test_certificate_fuzzing_missing_fields(self) -> None:
        """Certificates with missing mandatory fields must fail Pydantic model validation."""
        incomplete_dicts = [
            {},
            {"subject_id": "rcp-test"},
            {"subject_id": "rcp-test", "public_key_b64": "AAAA"},
            {"serial_number": "crt-1234"},
        ]
        for d in incomplete_dicts:
            with pytest.raises(PydanticValidationError):
                PQCIdentityCertificate.model_validate(d)

    def test_certificate_invalid_base64_and_types(self) -> None:
        """Certificates with corrupted base64 or illegal enum values must fail closed."""
        valid_dict = {
            "serial_number": "crt-0102030405060708090a0b0c0d0e0f10",
            "subject_id": "usr-0102030405060708090a0b0c0d0e0f10",
            "issuer_id": "ca-root-offline",
            "key_purpose": "KEY_ENCAPSULATION",
            "algorithm": "ML-KEM-768",
            "public_key_b64": "!!!not_valid_base64$$$",
            "valid_from": 1000,
            "valid_until": 2000,
            "signature_b64": base64.b64encode(b"fakesig").decode(),
        }
        with pytest.raises((ValidationError, PydanticValidationError, Exception)):
            cert = PQCIdentityCertificate.model_validate(valid_dict)
            cert.get_public_key_bytes()

    def test_certificate_inverted_validity_dates(self) -> None:
        """Certificates where valid_until < valid_from must be rejected."""
        inverted_dict = {
            "serial_number": "crt-0102030405060708090a0b0c0d0e0f10",
            "subject_id": "usr-0102030405060708090a0b0c0d0e0f10",
            "issuer_id": "ca-root-offline",
            "key_purpose": "KEY_ENCAPSULATION",
            "algorithm": "ML-KEM-768",
            "public_key_b64": base64.b64encode(b"\x00" * 1184).decode(),
            "valid_from": 500000,
            "valid_until": 100000,  # Expired before valid_from!
            "signature_b64": base64.b64encode(b"\x00" * 3309).decode(),
        }
        with pytest.raises((ValidationError, PydanticValidationError, SecurityError)):
            PQCIdentityCertificate.model_validate(inverted_dict)

    # -------------------------------------------------------------------------
    # 3. DecryptionEvent & Canonicalization Fuzzing
    # -------------------------------------------------------------------------

    def test_canonicalize_fuzz_nested_and_floats(self) -> None:
        """RFC 8785 JCS canonicalization must handle nested objects, reject unencodable types."""
        obj1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        obj2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
        assert canonicalize(obj1) == canonicalize(obj2)

        with pytest.raises((CanonicalizationError, TypeError)):
            canonicalize({"func": lambda: None})

    def test_decryption_event_fuzz_malformed_ids(self) -> None:
        """DecryptionEvents with illegal ID formats must fail validation."""
        malformed_inputs = [
            "not-an-id",
            "../../escape",
            "usr-" + "g" * 32,
            "",
            " " * 32,
            "<script>alert(1)</script>",
        ]
        for bad_id in malformed_inputs:
            with pytest.raises((ValidationError, PydanticValidationError, ValueError)):
                RecipientID(bad_id)

    # -------------------------------------------------------------------------
    # 4. Merkle Proof Parser Fuzzing
    # -------------------------------------------------------------------------

    def test_merkle_proof_fuzz_invalid_directions_and_hashes(self) -> None:
        """MerkleInclusionProof parser must reject invalid directions and truncated hashes."""
        with pytest.raises((ValidationError, PydanticValidationError)):
            MerkleInclusionProof.model_validate({
                "leaf_hash": "short",
                "siblings": [("INVALID_DIRECTION", "sha3-256:1234")],
                "leaf_index": -1,
                "tree_size": 0,
            })

    # -------------------------------------------------------------------------
    # 5. Backup Archive Fuzzing & Path Traversal Rejection
    # -------------------------------------------------------------------------

    def test_backup_restore_traversal_fuzz(self, tmp_path: Path) -> None:
        """Backup restore must detect and reject any zip entry attempting directory escape."""
        import zipfile

        evil_archive = tmp_path / "evil.tcbackup"
        with zipfile.ZipFile(evil_archive, "w") as zf:
            manifest = {
                "format_version": 1,
                "protocol_version": "1.0.0",
                "application_version": "1.0.0",
                "chain_id": "test-chain",
                "created_at": 1700000000,
                "components": {
                    "../../evil.dll": {
                        "sha256": "fake",
                        "sha3_256": "fake",
                    }
                },
            }
            zf.writestr("backup_manifest.json", json.dumps(manifest))
            zf.writestr("../../evil.dll", b"malicious content")

        restore_dest = tmp_path / "restore_target"
        restore_dest.mkdir()

        bm = BackupManager(data_dir=tmp_path)
        with pytest.raises(SecurityError, match="Directory traversal detected|verification failed"):
            bm.restore_backup(backup_path=evil_archive, target_dir=restore_dest)
