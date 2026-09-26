"""Typed models and definitions for the TraceCrypt Watermark Subsystem.

Defines:
- 256-bit (32-byte) WatermarkPayload format
- ExtractionStatus enumeration
- WatermarkExtractionResult model
- FidelityMetrics model
- WatermarkParameters configuration
"""

from __future__ import annotations

from enum import Enum
import struct
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import ValidationError
from tracecrypt.utils.identifiers import SessionID, WatermarkID


class ExtractionStatus(str, Enum):
    """Status of blind forensic watermark extraction."""
    NOT_DETECTED = "NOT_DETECTED"  # No watermark signal detected above threshold
    DETECTED = "DETECTED"          # Raw correlation detected, but bitstream unrecoverable
    DECODED = "DECODED"            # ECC successfully decoded and checksum verified
    CORRUPTED = "CORRUPTED"        # Signal detected, but ECC or checksum unrecoverable
    AMBIGUOUS = "AMBIGUOUS"        # Multiple conflicting valid watermarks detected across pages
    INVALID = "INVALID"            # Structurally invalid or forged payload


class WatermarkPayload(BaseModel):
    """256-bit (32-byte) logical watermark payload before error correction.

    Bit layout:
    - version:          1 byte  (8 bits)
    - watermark_id:    16 bytes (128 bits) - 128-bit CSPRNG value
    - session_tag:      8 bytes (64 bits)  - cryptographic 64-bit truncation of SessionID
    - document_binding: 5 bytes (40 bits)  - SHA3-256("TraceCrypt-Watermark-Binding"||doc_hash||ses||wm)[:5]
    - checksum:         2 bytes (16 bits)  - CRC-16-CCITT over the preceding 30 bytes
    Total:             32 bytes (256 bits)
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1, le=255)
    watermark_id: WatermarkID
    session_tag: bytes = Field(min_length=8, max_length=8)
    document_binding: bytes = Field(min_length=5, max_length=5)
    checksum: int = Field(ge=0, le=0xFFFF)

    @classmethod
    def compute_document_binding(
        cls,
        document_hash: str,
        session_id: SessionID | str,
        watermark_id: WatermarkID | str,
    ) -> bytes:
        """Derive 5-byte (40-bit) document binding from cryptographic context."""
        ctx = (
            b"TraceCrypt-Watermark-Binding:"
            + document_hash.lower().encode("ascii")
            + b":"
            + str(session_id).encode("ascii")
            + b":"
            + str(watermark_id).encode("ascii")
        )
        full_hash = Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).hex_digest
        return bytes.fromhex(full_hash[:10])  # 10 hex chars = 5 bytes

    @classmethod
    def compute_session_tag(cls, session_id: SessionID | str) -> bytes:
        """Derive 8-byte (64-bit) session tag from SessionID."""
        # Use first 8 bytes of the raw 16-byte random SessionID
        clean = str(session_id).replace("ses-", "")
        return bytes.fromhex(clean[:16])

    @classmethod
    def compute_crc16(cls, data: bytes) -> int:
        """Compute CRC-16-CCITT (poly 0x1021, init 0xFFFF)."""
        crc = 0xFFFF
        for b in data:
            crc ^= (b << 8) & 0xFFFF
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    @classmethod
    def create(
        cls,
        watermark_id: WatermarkID,
        session_id: SessionID,
        document_hash: str,
        version: int = 1,
    ) -> WatermarkPayload:
        """Construct a new authenticated 256-bit WatermarkPayload."""
        session_tag = cls.compute_session_tag(session_id)
        doc_binding = cls.compute_document_binding(document_hash, session_id, watermark_id)

        # Build first 30 bytes for checksum calculation
        wm_bytes = bytes.fromhex(str(watermark_id).replace("wm-", ""))
        pre_checksum = struct.pack(">B", version) + wm_bytes + session_tag + doc_binding

        crc = cls.compute_crc16(pre_checksum)

        return cls(
            version=version,
            watermark_id=watermark_id,
            session_tag=session_tag,
            document_binding=doc_binding,
            checksum=crc,
        )

    def to_bytes(self) -> bytes:
        """Serialize exactly to 32 bytes (256 bits)."""
        wm_bytes = bytes.fromhex(str(self.watermark_id).replace("wm-", ""))
        payload = (
            struct.pack(">B", self.version)
            + wm_bytes
            + self.session_tag
            + self.document_binding
            + struct.pack(">H", self.checksum)
        )
        if len(payload) != 32:
            raise ValidationError(f"Payload serialization failed: expected 32 bytes, got {len(payload)}")
        return payload

    def verify_document_binding(
        self,
        document_hash: str,
        session_id: SessionID | str,
    ) -> bool:
        """Cryptographically verify that this payload is bound to the given document and session."""
        expected = self.compute_document_binding(document_hash, session_id, self.watermark_id)
        return self.document_binding == expected

    @classmethod
    def from_bytes(cls, data: bytes) -> WatermarkPayload:
        """Deserialize from exact 32 bytes (256 bits) with checksum validation."""
        if len(data) != 32:
            raise ValidationError(f"WatermarkPayload expects exactly 32 bytes, got {len(data)}")

        version = struct.unpack(">B", data[0:1])[0]
        wm_raw = data[1:17].hex()
        watermark_id = WatermarkID(f"wm-{wm_raw}")
        session_tag = data[17:25]
        doc_binding = data[25:30]
        checksum = struct.unpack(">H", data[30:32])[0]

        # Verify CRC16
        expected_crc = cls.compute_crc16(data[:30])
        if checksum != expected_crc:
            raise ValidationError(
                f"WatermarkPayload checksum mismatch: expected {expected_crc:#06x}, got {checksum:#06x}"
            )

        return cls(
            version=version,
            watermark_id=watermark_id,
            session_tag=session_tag,
            document_binding=doc_binding,
            checksum=checksum,
        )


class FidelityMetrics(BaseModel):
    """Perceptual invisibility fidelity metrics."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    psnr: float = Field(description="Peak Signal-to-Noise Ratio in dB (target >= 42.0 dB)")
    ssim: float = Field(description="Structural Similarity Index (target >= 0.995)")
    mse: float = Field(description="Mean Squared Error between pristine and watermarked images")


class WatermarkParameters(BaseModel):
    """Tuning parameters for transform-domain watermark embedding."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    embedding_strength: float = Field(default=12.0, ge=1.0, le=50.0)
    block_size: int = Field(default=8, ge=4, le=16)
    render_scale: float = Field(default=2.0, ge=1.0, le=4.0)
    subband: str = Field(default="HL")
    chips_per_bit: int = Field(default=4, ge=1, le=16)


class WatermarkExtractionResult(BaseModel):
    """Detailed forensic result from watermark extraction."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ExtractionStatus
    watermark_version: Optional[int] = None
    watermark_id: Optional[WatermarkID] = None
    session_tag: Optional[str] = None
    document_binding: Optional[str] = None
    bit_error_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_score: float = Field(default=0.0)
    corrected_errors: int = Field(default=0, ge=0)
    pages_analyzed: int = Field(default=1, ge=0)
    pages_decoded: int = Field(default=0, ge=0)
    pages_corrupted: int = Field(default=0, ge=0)
    normalization_metadata: Dict[str, Any] = Field(default_factory=dict)
    diagnostics: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """True if the watermark was successfully decoded and verified."""
        return self.status == ExtractionStatus.DECODED and self.watermark_id is not None
