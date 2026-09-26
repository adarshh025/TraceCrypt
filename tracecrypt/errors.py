"""Structured exception hierarchy for TraceCrypt.

All exceptions inherit from TraceCryptError. Exceptions are designed to provide
actionable, safe diagnostic information without leaking private keys, passphrases,
plaintext document bytes, or cryptographic secrets.
"""

from typing import Any, Mapping, Optional


class TraceCryptError(Exception):
    """Base exception for all TraceCrypt errors."""

    def __init__(self, message: str, details: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = dict(details) if details else {}

    def __str__(self) -> str:
        if self.details:
            details_str = ", ".join(f"{k}={v!r}" for k, v in sorted(self.details.items()))
            return f"{self.message} ({details_str})"
        return self.message


class ConfigurationError(TraceCryptError):
    """Raised when configuration is missing, invalid, or violates security constraints."""
    pass


class ValidationError(TraceCryptError):
    """Raised when data, schemas, or identifiers fail validation rules."""
    pass


class CryptographicError(TraceCryptError):
    """Raised when cryptographic operations (encapsulation, decapsulation, signing) fail."""
    pass


class CanonicalizationError(TraceCryptError):
    """Raised when RFC 8785 canonicalization encounters invalid or non-representable data."""
    pass


class SecurityError(TraceCryptError):
    """Raised when security boundaries, access controls, or tamper defenses are breached."""
    pass


class StorageError(TraceCryptError):
    """Raised when local database or file storage operations fail."""
    pass


class LedgerError(TraceCryptError):
    """Raised when distributed ledger operations, mempool, or consensus fail."""
    pass


class WatermarkError(TraceCryptError):
    """Raised when watermark embedding, transformation, or payload generation fails."""
    pass


class ForensicError(TraceCryptError):
    """Raised when forensic investigation, normalization, or extraction fails."""
    pass


class AirGapViolation(SecurityError):
    """Raised when forbidden network activity (external socket, DNS, HTTP) is attempted."""
    pass


class IntegrityError(SecurityError):
    """Raised when cryptographic hashes, Merkle proofs, or checksums mismatch."""
    pass


class CertificateValidationError(SecurityError):
    """Raised when an identity certificate fails offline validation."""
    pass


class PackageValidationError(SecurityError):
    """Raised when a .tcdist distribution package fails offline structural or integrity validation."""
    pass


class VerificationError(TraceCryptError):
    """Raised when forensic attribution verification encounters an unverifiable state."""
    pass


class LedgerCommitRequiredError(LedgerError):
    """Raised when document release is blocked because ledger commit was not confirmed."""
    pass


class ReleaseGateError(SecurityError):
    """Raised when the centralized DocumentReleaseGate denies release of a document."""
    pass


class ReplayAttackError(SecurityError):
    """Raised when a duplicate EventID, SessionID, or WatermarkID is detected."""
    pass


class AttributionPipelineError(TraceCryptError):
    """Raised when recipient attribution pipeline encounters an unrecoverable failure."""
    pass
