"""Document loading and validation reader for TraceCrypt.

Enforces size bounds, non-empty constraints, and MIME-type detection.
"""

from __future__ import annotations

from pathlib import Path
from tracecrypt.errors import ValidationError


class DocumentReader:
    """Safely loads source documents from the local filesystem with size bounds."""

    DEFAULT_MAX_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB limit

    @classmethod
    def read_document(
        cls,
        filepath: Path | str,
        max_bytes: int = DEFAULT_MAX_SIZE_BYTES,
    ) -> tuple[bytes, str, str]:
        """Read source document bytes and extract safe metadata.

        Returns:
            tuple of (document_bytes, mime_type, sanitized_filename)
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Document file does not exist: {path}")
        if not path.is_file():
            raise ValidationError(f"Path is not a regular file: {path}")

        file_size = path.stat().st_size
        if file_size == 0:
            raise ValidationError(f"Source document is empty: {path}")
        if file_size > max_bytes:
            raise ValidationError(
                f"Source document size ({file_size} bytes) exceeds configured limit ({max_bytes} bytes)"
            )

        data = path.read_bytes()
        if len(data) != file_size:
            raise ValidationError("File size changed during read operation.")

        filename = path.name
        mime_type = cls.detect_mime_type(data, filename)

        return data, mime_type, filename

    @classmethod
    def detect_mime_type(cls, data: bytes, filename: str) -> str:
        """Detect MIME type from header magic bytes or filename extension."""
        if data.startswith(b"%PDF-"):
            return "application/pdf"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if filename.lower().endswith(".pdf"):
            return "application/pdf"
        return "application/octet-stream"
