"""Centralized versioning and protocol compatibility definitions for TraceCrypt.

Distinguishes:
- Application version
- Protocol version
- Ledger consensus version
- Database schema version
- Watermark format version
- Event schema version
- Proof bundle format version

Enforces fail-closed semantics for unsupported or incompatible protocol versions.
"""

from __future__ import annotations

from typing import Dict, Any, NamedTuple
from pydantic import BaseModel, Field

from tracecrypt.errors import SecurityError, ConfigurationError

APPLICATION_VERSION: str = "1.0.0"
PROTOCOL_VERSION: str = "1.0.0"
LEDGER_VERSION: int = 1
DATABASE_SCHEMA_VERSION: int = 1
WATERMARK_FORMAT_VERSION: int = 1
EVENT_SCHEMA_VERSION: int = 1
PROOF_FORMAT_VERSION: int = 1

# Supported protocol major versions
SUPPORTED_PROTOCOL_MAJORS = {1}


class SystemVersions(BaseModel):
    """Strongly typed snapshot of all TraceCrypt system and protocol versions."""
    application_version: str = Field(default=APPLICATION_VERSION)
    protocol_version: str = Field(default=PROTOCOL_VERSION)
    ledger_version: int = Field(default=LEDGER_VERSION)
    database_schema_version: int = Field(default=DATABASE_SCHEMA_VERSION)
    watermark_format_version: int = Field(default=WATERMARK_FORMAT_VERSION)
    event_schema_version: int = Field(default=EVENT_SCHEMA_VERSION)
    proof_format_version: int = Field(default=PROOF_FORMAT_VERSION)

    def as_dict(self) -> Dict[str, Any]:
        return self.model_dump()


def get_system_versions() -> SystemVersions:
    """Return the active system versions."""
    return SystemVersions()


def parse_semver(version_str: str) -> tuple[int, int, int]:
    """Parse a semantic version string into (major, minor, patch)."""
    parts = version_str.strip().split(".")
    if len(parts) != 3:
        raise ConfigurationError(f"Invalid semantic version format: '{version_str}' (expected major.minor.patch)")
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        raise ConfigurationError(f"Non-integer components in version string: '{version_str}'")


def verify_protocol_compatibility(remote_protocol_version: str) -> None:
    """Verify protocol version compatibility, failing closed on major mismatch.
    
    Raises:
        SecurityError: If the remote protocol version has an incompatible major version
                       or cannot be parsed.
    """
    try:
        remote_major, remote_minor, _ = parse_semver(remote_protocol_version)
    except Exception as e:
        raise SecurityError(f"Protocol compatibility check failed: malformed version '{remote_protocol_version}': {e}") from e

    local_major, _, _ = parse_semver(PROTOCOL_VERSION)
    if remote_major != local_major or remote_major not in SUPPORTED_PROTOCOL_MAJORS:
        raise SecurityError(
            f"Protocol version mismatch: local={PROTOCOL_VERSION}, remote={remote_protocol_version}. "
            f"Incompatible major version {remote_major} (supported: {SUPPORTED_PROTOCOL_MAJORS}). "
            f"Failing closed."
        )


def verify_ledger_compatibility(version: int) -> None:
    """Verify ledger version compatibility."""
    if version != LEDGER_VERSION:
        raise SecurityError(
            f"Ledger version mismatch: expected={LEDGER_VERSION}, got={version}. Failing closed."
        )


def verify_proof_compatibility(version: int) -> None:
    """Verify proof bundle format version compatibility."""
    if version != PROOF_FORMAT_VERSION:
        raise SecurityError(
            f"Proof bundle format version mismatch: expected={PROOF_FORMAT_VERSION}, got={version}. Failing closed."
        )
