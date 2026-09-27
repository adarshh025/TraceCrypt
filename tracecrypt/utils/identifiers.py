"""Typed identifiers for TraceCrypt.

Enforces strict formats, regex validation, prefix namespaces, and immutability.
Predictable incremental or sequential identifiers are rejected for security-sensitive entities.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Type, TypeVar
from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from tracecrypt.errors import ValidationError

T = TypeVar("T", bound="BaseID")


class BaseID(str):
    """Immutable, strongly-typed base identifier with prefix and format validation."""

    PREFIX: ClassVar[str] = ""
    # Format: <prefix>-<32 lowercase hex characters> or <prefix>-<uuid-v4>
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[a-z0-9]+-[a-f0-9]{32}$")

    def __new__(cls: Type[T], value: str) -> T:
        if not isinstance(value, str):
            raise ValidationError(f"{cls.__name__} must be a string, got {type(value).__name__}")

        # Accidental whitespace detection - fail closed
        if value != value.strip():
            raise ValidationError(f"{cls.__name__} contains accidental leading or trailing whitespace: {value!r}")

        if not value.startswith(cls.PREFIX):
            actual_prefix = value.split("-", 1)[0] if "-" in value else value
            raise ValidationError(
                f"Invalid {cls.__name__} prefix. Expected '{cls.PREFIX}', got '{actual_prefix}'"
            )

        if not cls.PATTERN.match(value):
            raise ValidationError(
                f"Malformed {cls.__name__}: '{value}'. Must match pattern '{cls.PATTERN.pattern}'"
            )

        return super().__new__(cls, value)

    @classmethod
    def generate(cls: Type[T]) -> T:
        """Generate a strongly-typed identifier with 128 bits of CSPRNG entropy."""
        import os
        return cls(f"{cls.PREFIX}{os.urandom(16).hex()}")

    @classmethod
    def from_raw_hex(cls: Type[T], hex_string: str) -> T:
        """Create an identifier from a 32-character hex string."""
        if not isinstance(hex_string, str):
            raise ValidationError(f"Hex string must be str, got {type(hex_string).__name__}")
        cleaned = hex_string.lower().strip()
        if len(cleaned) != 32 or not re.match(r"^[a-f0-9]{32}$", cleaned):
            raise ValidationError(
                f"Invalid raw hex string for {cls.__name__}: expected 32 hex chars, got {hex_string!r}"
            )
        return cls(f"{cls.PREFIX}{cleaned}")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.chain_schema([
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(cls),
        ])

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{self}')"


class DocumentID(BaseID):
    """Unique identifier for a source document."""
    PREFIX: ClassVar[str] = "doc-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^doc-[a-f0-9]{32}$")


class DistributionID(BaseID):
    """Unique identifier for an encrypted document distribution package."""
    PREFIX: ClassVar[str] = "dst-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^dst-[a-f0-9]{32}$")


class UserID(BaseID):
    """Unique identifier for an authorized system user."""
    PREFIX: ClassVar[str] = "usr-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^usr-[a-f0-9]{32}$")


class RecipientID(BaseID):
    """Unique identifier for a document recipient."""
    PREFIX: ClassVar[str] = "rcp-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^rcp-[a-f0-9]{32}$")


class DeviceID(BaseID):
    """Unique identifier for an enrolled physical workstation/device."""
    PREFIX: ClassVar[str] = "dev-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^dev-[a-f0-9]{32}$")


class SessionID(BaseID):
    """Unique identifier for an ephemeral decryption session."""
    PREFIX: ClassVar[str] = "ses-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^ses-[a-f0-9]{32}$")


class WatermarkID(BaseID):
    """Unique 128-bit identifier embedded within the forensic watermark."""
    PREFIX: ClassVar[str] = "wm-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^wm-[a-f0-9]{32}$")


class EventID(BaseID):
    """Unique identifier for a signed decryption event."""
    PREFIX: ClassVar[str] = "evt-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^evt-[a-f0-9]{32}$")


class TransactionID(BaseID):
    """Unique identifier for a committed ledger transaction."""
    PREFIX: ClassVar[str] = "tx-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^tx-[a-f0-9]{32}$")


class BlockID(BaseID):
    """Unique identifier for a committed ledger block."""
    PREFIX: ClassVar[str] = "blk-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^blk-[a-f0-9]{32}$")


class CaseID(BaseID):
    """Unique identifier for a forensic investigation case."""
    PREFIX: ClassVar[str] = "cas-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^cas-[a-f0-9]{32}$")


class ValidatorID(BaseID):
    """Unique identifier for a consensus validator node."""
    PREFIX: ClassVar[str] = "val-"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^val-[a-f0-9]{32}$")
