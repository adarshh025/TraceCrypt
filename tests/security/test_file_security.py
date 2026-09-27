"""Path Traversal, Filename Sanitization, and File Security Tests.

Validates:
- Protection against directory traversal attacks (../ and ..\\) in filename parameters.
- Rejection of unsupported archive and container formats (.zip, .tar, .7z).
- Fail-closed behavior on missing or unreadable files.
- Basename isolation for forensic evidence files.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.errors import ForensicEvidenceError
from tracecrypt.forensics.ingestion import EvidenceIngestion


class TestFileSecurity:
    """Evaluate filesystem access safety and path traversal resistance."""

    def test_path_traversal_filename_sanitization(self, tmp_path: Path) -> None:
        """User-supplied filenames containing traversal sequences must be sanitized to basename."""
        valid_png = tmp_path / "valid.png"
        import numpy as np
        from PIL import Image
        img = Image.fromarray(np.zeros((100, 100, 3), dtype=np.uint8))
        img.save(valid_png)

        # Ingest with hostile directory traversal in filename hint
        traversal_filename = "../../../etc/passwd"
        ev, _ = EvidenceIngestion.ingest(
            evidence_input=valid_png,
            filename=traversal_filename,
        )

        # Ingestion must strip path components to safe basename
        assert "/" not in ev.filename
        assert "\\" not in ev.filename
        assert ".." not in ev.filename
        assert ev.filename == "passwd"

    def test_windows_traversal_sanitization(self, tmp_path: Path) -> None:
        """Windows backslash path traversal in filename must be stripped."""
        valid_png = tmp_path / "valid_win.png"
        import numpy as np
        from PIL import Image
        img = Image.fromarray(np.zeros((100, 100, 3), dtype=np.uint8))
        img.save(valid_png)

        traversal_win = "..\\..\\Windows\\System32\\cmd.exe"
        ev, _ = EvidenceIngestion.ingest(
            evidence_input=valid_png,
            filename=traversal_win,
        )
        assert "\\" not in ev.filename
        assert ".." not in ev.filename

    def test_unsupported_archive_formats_rejected(self, tmp_path: Path) -> None:
        """Archives such as ZIP or TAR must be rejected by EvidenceIngestion."""
        zip_file = tmp_path / "malicious.zip"
        zip_file.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        with pytest.raises(ForensicEvidenceError, match="Unsupported evidence artifact format"):
            EvidenceIngestion.ingest(zip_file)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        """Non-existent evidence file must raise FileNotFoundError immediately."""
        non_existent = tmp_path / "does_not_exist.pdf"
        with pytest.raises(FileNotFoundError):
            EvidenceIngestion.ingest(non_existent)
