"""Evidence Ingestion Engine for TraceCrypt Forensic Investigation.

Enforces:
1. Strict read-only evidence access: source artifacts are never modified or rewritten.
2. Canonical SHA3-256 evidence digest calculation.
3. Multi-format support: PDF, PNG, JPEG, and TIFF.
4. Isolated in-memory page representation for subsequent normalization and blind analysis.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import cv2
import numpy as np

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ForensicEvidenceError
from tracecrypt.forensics.types import ForensicEvidence
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.normalizer import WatermarkNormalizer


class EvidenceIngestion:
    """Manages secure, read-only ingestion and cryptographic hashing of forensic evidence."""

    SUPPORTED_MIME_TYPES = {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/tiff",
    }
    MAX_EVIDENCE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB limit
    MAX_PAGE_COUNT = 200                         # 200 pages max
    MAX_IMAGE_DIMENSION = 16384                  # 16384px limit per dimension
    MAX_IMAGE_PIXELS = 100_000_000               # 100 Megapixels limit

    @classmethod
    def _detect_mime_type(cls, data: bytes, filename: Optional[str] = None) -> str:
        """Deterministically determine MIME type from magic headers and filename hint."""
        # Magic header sniffing
        if data.startswith(b"%PDF"):
            return "application/pdf"
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        elif data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        elif data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
            return "image/tiff"

        # Fallback to filename extension
        if filename:
            mime, _ = mimetypes.guess_type(filename)
            if mime and mime in cls.SUPPORTED_MIME_TYPES:
                return mime

        raise ForensicEvidenceError(
            "Unsupported evidence artifact format. Evidence must be PDF, PNG, JPEG, or TIFF."
        )

    @classmethod
    def ingest(
        cls,
        evidence_input: Union[bytes, Path, str],
        filename: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        render_scale: float = 2.0,
    ) -> Tuple[ForensicEvidence, List[np.ndarray]]:
        """Ingest evidence artifact, compute SHA3-256 digest, and extract raw in-memory pages.

        The original evidence file is NEVER modified or overwritten.

        Args:
            evidence_input: Raw evidence bytes, or a filesystem path to the evidence.
            filename: Optional user-supplied filename hint.
            metadata: Optional non-PII investigator case metadata.
            render_scale: Rendering scale for PDF rasterization (default: 2.0).

        Returns:
            Tuple of (ForensicEvidence immutable record, list of 2D uint8 page arrays).
        """
        # 1. Read bytes read-only
        if isinstance(evidence_input, (str, Path)):
            src_path = Path(evidence_input)
            if not src_path.is_file():
                raise FileNotFoundError(f"Evidence file not found: {src_path}")
            resolved_filename = Path(filename or src_path.name).name
            evidence_bytes = src_path.read_bytes()
        elif isinstance(evidence_input, (bytes, bytearray)):
            evidence_bytes = bytes(evidence_input)
            resolved_filename = Path(filename or "evidence.bin").name
        else:
            raise ForensicEvidenceError(
                f"Invalid evidence input type: {type(evidence_input).__name__}. Expected bytes or Path."
            )

        if "\x00" in resolved_filename:
            raise ForensicEvidenceError("Filename contains forbidden null byte character.")

        if not evidence_bytes:
            raise ForensicEvidenceError("Evidence artifact is empty (0 bytes).")

        if len(evidence_bytes) > cls.MAX_EVIDENCE_SIZE_BYTES:
            raise ForensicEvidenceError(
                f"Evidence artifact size ({len(evidence_bytes)} bytes) exceeds maximum limit "
                f"of {cls.MAX_EVIDENCE_SIZE_BYTES} bytes (100 MB)."
            )

        # 2. Compute canonical SHA3-256 evidence digest
        evidence_hash = Hasher.digest_bytes(
            evidence_bytes, HashAlgorithm.SHA3_256.value
        ).formatted

        # 3. Detect MIME type
        mime_type = cls._detect_mime_type(evidence_bytes, resolved_filename)

        # 4. Extract image pages in memory
        pages: List[np.ndarray] = []
        if mime_type == "application/pdf":
            try:
                pages = WatermarkNormalizer.rasterize_pdf(
                    evidence_bytes, scale=render_scale, max_pages=cls.MAX_PAGE_COUNT
                )
            except Exception as e:
                raise ForensicEvidenceError(f"Failed to rasterize evidence PDF: {e}") from e
        else:
            # Raster image (PNG, JPEG, TIFF)
            np_buf = np.frombuffer(evidence_bytes, np.uint8)
            loaded = cv2.imdecode(np_buf, cv2.IMREAD_UNCHANGED)
            if loaded is None:
                raise ForensicEvidenceError(f"Failed to decode evidence image ({mime_type}).")

            if loaded.shape[0] > cls.MAX_IMAGE_DIMENSION or loaded.shape[1] > cls.MAX_IMAGE_DIMENSION:
                raise ForensicEvidenceError(
                    f"Evidence image dimensions ({loaded.shape[1]}x{loaded.shape[0]}) exceed "
                    f"maximum allowed {cls.MAX_IMAGE_DIMENSION}px."
                )
            if loaded.shape[0] * loaded.shape[1] > cls.MAX_IMAGE_PIXELS:
                raise ForensicEvidenceError(
                    f"Evidence image pixel count ({loaded.shape[0] * loaded.shape[1]}) exceeds "
                    f"maximum limit of {cls.MAX_IMAGE_PIXELS} pixels."
                )

            gray = WatermarkNormalizer.to_grayscale(loaded)
            pages = [gray]

        if not pages:
            raise ForensicEvidenceError("Failed to extract any readable pages from evidence artifact.")

        if len(pages) > cls.MAX_PAGE_COUNT:
            raise ForensicEvidenceError(
                f"Evidence page count ({len(pages)}) exceeds maximum allowed {cls.MAX_PAGE_COUNT} pages."
            )

        # 5. Create immutable ForensicEvidence record
        evidence_id = f"evd-{SecureRandom.generate_nonce(16)}"
        now = utc_now_micros()

        evidence_record = ForensicEvidence(
            evidence_id=evidence_id,
            sha3_256=evidence_hash,
            filename=resolved_filename,
            mime_type=mime_type,
            size_bytes=len(evidence_bytes),
            page_count=len(pages),
            ingested_at=now,
            metadata=metadata or {},
        )

        return evidence_record, pages
