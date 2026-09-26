"""Binary container serialization and deserialization for .tcdist distribution packages.

Binary Format Specification:
- 0x00..0x07 : MAGIC_START (8 bytes: b"TCDIST01")
- 0x08..0x0B : FORMAT_VERSION (4 bytes uint32-be: 1)
- 0x0C..0x0F : HEADER_LEN (4 bytes uint32-be)
- 0x10..[0x10+H_LEN-1] : HEADER_JSON (RFC 8785 canonical UTF-8 bytes)
- Offset 1 : NONCE_LEN (2 bytes uint16-be: 12)
- Offset 2 : NONCE_BYTES (12 bytes)
- Offset 3 : TAG_LEN (2 bytes uint16-be: 16)
- Offset 4 : TAG_BYTES (16 bytes)
- Offset 5 : CIPHERTEXT_LEN (8 bytes uint64-be)
- Offset 6 : CIPHERTEXT_BYTES (N bytes)
- Offset 7 : CHECKSUM (32 bytes SHA3-256 of all preceding bytes)
- Offset 8 : MAGIC_END (9 bytes: b"TCDISTEND")
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any, Dict

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.document.types import DistributionPackageHeader
from tracecrypt.errors import PackageValidationError, ValidationError


class DistributionPackage:
    """In-memory representation of an encrypted .tcdist package."""

    MAGIC_START = b"TCDIST01"
    MAGIC_END = b"TCDISTEND"
    CURRENT_VERSION = 1
    MAX_HEADER_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB limit for metadata
    MAX_PACKAGE_SIZE_BYTES = 150 * 1024 * 1024  # 150 MB total limit

    def __init__(
        self,
        header: DistributionPackageHeader,
        nonce: bytes,
        auth_tag: bytes,
        ciphertext: bytes,
    ) -> None:
        if len(nonce) != 12:
            raise ValidationError(f"Invalid nonce length: {len(nonce)} != 12")
        if len(auth_tag) != 16:
            raise ValidationError(f"Invalid auth tag length: {len(auth_tag)} != 16")
        if len(ciphertext) == 0:
            raise ValidationError("Ciphertext cannot be empty.")

        self.header = header
        self.nonce = bytes(nonce)
        self.auth_tag = bytes(auth_tag)
        self.ciphertext = bytes(ciphertext)

    def to_bytes(self) -> bytes:
        """Serialize complete .tcdist package into deterministic binary bytes."""
        header_bytes = self.header.to_canonical_bytes()
        header_len = len(header_bytes)

        # 1. Pack preamble and header
        preamble = struct.pack(
            ">8sII",
            self.MAGIC_START,
            self.CURRENT_VERSION,
            header_len,
        )

        # 2. Pack payload sections
        payload_meta = struct.pack(
            ">H12sH16sQ",
            len(self.nonce),
            self.nonce,
            len(self.auth_tag),
            self.auth_tag,
            len(self.ciphertext),
        )

        body = preamble + header_bytes + payload_meta + self.ciphertext

        # 3. Compute checksum over all preceding body bytes
        checksum_digest = Hasher.digest_bytes(body, HashAlgorithm.SHA3_256.value)
        checksum_bytes = checksum_digest.raw_bytes

        # 4. Finalize with checksum and magic end
        footer = checksum_bytes + self.MAGIC_END
        return body + footer

    def save(self, filepath: Path | str) -> Path:
        """Write package to the specified .tcdist file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw_bytes = self.to_bytes()
        path.write_bytes(raw_bytes)
        return path

    @classmethod
    def serialize(cls, package: DistributionPackage) -> bytes:
        """Serialize complete .tcdist package into deterministic binary bytes."""
        return package.to_bytes()

    @classmethod
    def deserialize(cls, data: bytes) -> DistributionPackage:
        """Parse and validate binary .tcdist package bytes."""
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> DistributionPackage:
        """Parse and validate binary .tcdist package bytes."""
        total_len = len(data)
        min_len = 8 + 4 + 4 + 2 + 2 + 12 + 2 + 16 + 8 + 1 + 32 + 9  # minimal possible envelope
        if total_len < min_len:
            raise PackageValidationError("Package truncated: data too short for .tcdist container.")

        if total_len > cls.MAX_PACKAGE_SIZE_BYTES:
            raise PackageValidationError(
                f"Package exceeds maximum size limit ({total_len} > {cls.MAX_PACKAGE_SIZE_BYTES} bytes)"
            )

        # Verify Magic Start
        magic_start = data[:8]
        if magic_start != cls.MAGIC_START:
            raise PackageValidationError(
                f"Invalid package header magic: expected {cls.MAGIC_START!r}, got {magic_start!r}"
            )

        # Verify Magic End
        magic_end = data[-9:]
        if magic_end != cls.MAGIC_END:
            raise PackageValidationError(
                f"Invalid package footer magic: expected {cls.MAGIC_END!r}, got {magic_end!r}"
            )

        # Verify Checksum
        body_bytes = data[:-41]  # all bytes before (32-byte checksum + 9-byte footer)
        stored_checksum = data[-41:-9]
        computed_checksum = Hasher.digest_bytes(body_bytes, HashAlgorithm.SHA3_256.value).raw_bytes
        if stored_checksum != computed_checksum:
            raise PackageValidationError(
                "Package checksum verification failed. Container has been corrupted or tampered."
            )

        # Unpack Version and Header Length
        version, header_len = struct.unpack_from(">II", data, 8)
        if version != cls.CURRENT_VERSION:
            raise PackageValidationError(f"Unsupported package container version: {version}")

        if header_len > cls.MAX_HEADER_SIZE_BYTES:
            raise PackageValidationError(
                f"Header length ({header_len}) exceeds safety limit ({cls.MAX_HEADER_SIZE_BYTES})"
            )

        offset = 16
        if offset + header_len > len(body_bytes):
            raise PackageValidationError("Package header length overflows payload bounds.")

        header_bytes = data[offset : offset + header_len]
        offset += header_len

        # Parse Header JSON
        try:
            header_dict: Dict[str, Any] = json.loads(header_bytes.decode("utf-8"))
            header = DistributionPackageHeader.model_validate(header_dict)
        except Exception as e:
            raise PackageValidationError(f"Failed to parse package header: {e}") from e

        # Unpack Nonce
        if offset + 2 > len(body_bytes):
            raise PackageValidationError("Package truncated before nonce length.")
        (nonce_len,) = struct.unpack_from(">H", data, offset)
        offset += 2
        if nonce_len != 12:
            raise PackageValidationError(f"Invalid nonce length: {nonce_len} != 12")
        nonce = data[offset : offset + 12]
        offset += 12

        # Unpack Auth Tag
        if offset + 2 > len(body_bytes):
            raise PackageValidationError("Package truncated before auth tag length.")
        (tag_len,) = struct.unpack_from(">H", data, offset)
        offset += 2
        if tag_len != 16:
            raise PackageValidationError(f"Invalid tag length: {tag_len} != 16")
        auth_tag = data[offset : offset + 16]
        offset += 16

        # Unpack Ciphertext
        if offset + 8 > len(body_bytes):
            raise PackageValidationError("Package truncated before ciphertext length.")
        (ciphertext_len,) = struct.unpack_from(">Q", data, offset)
        offset += 8
        if offset + ciphertext_len != len(body_bytes):
            raise PackageValidationError(
                f"Ciphertext length mismatch: declared {ciphertext_len}, actual remaining {len(body_bytes) - offset}"
            )
        ciphertext = data[offset : offset + ciphertext_len]

        return cls(
            header=header,
            nonce=nonce,
            auth_tag=auth_tag,
            ciphertext=ciphertext,
        )

    @classmethod
    def load(cls, filepath: Path | str) -> DistributionPackage:
        """Read and parse .tcdist package from filesystem."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Package file not found: {path}")
        data = path.read_bytes()
        return cls.from_bytes(data)
