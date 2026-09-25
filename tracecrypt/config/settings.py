"""Strongly typed configuration system for TraceCrypt.

Supports environment variables, file-based configuration, development/test/production modes,
air-gap enforcement, storage paths, and cryptographic settings. Fails closed on insecure settings.
"""

from __future__ import annotations

from enum import Enum
import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracecrypt.errors import ConfigurationError


class AppMode(str, Enum):
    """Operational mode."""
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    PRODUCTION = "PRODUCTION"


class AirGapConfig(BaseModel):
    """Air-gap enforcement parameters."""
    model_config = ConfigDict(extra="forbid")

    enforce_airgap: bool = Field(default=True, description="Strictly block non-whitelisted sockets")
    allowed_hosts: List[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost", "::1"])
    allow_dns: bool = Field(default=False, description="Whether DNS resolution is permitted")


class StorageConfig(BaseModel):
    """Local storage paths."""
    model_config = ConfigDict(extra="forbid")

    base_dir: Path = Field(default_factory=lambda: Path("data"))
    keys_dir: Path = Field(default_factory=lambda: Path("data/keys"))
    documents_dir: Path = Field(default_factory=lambda: Path("data/documents"))
    ledger_dir: Path = Field(default_factory=lambda: Path("data/ledger"))
    reports_dir: Path = Field(default_factory=lambda: Path("data/reports"))
    sqlite_db_path: Path = Field(default_factory=lambda: Path("data/tracecrypt_local.db"))


class LedgerConfig(BaseModel):
    """Permissioned ledger network parameters."""
    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Field(default="tracecrypt-lan-1", min_length=1)
    validator_count: int = Field(default=4, ge=1, le=100)
    block_finality_seconds: float = Field(default=1.0, ge=0.1, le=10.0)
    rpc_host: str = Field(default="127.0.0.1")
    rpc_port: int = Field(default=8545, ge=1024, le=65535)


class CryptoConfig(BaseModel):
    """Cryptographic parameter sets (NIST FIPS 203 & 204)."""
    model_config = ConfigDict(extra="forbid")

    kem_algorithm: str = Field(default="ML-KEM-768")
    dsa_algorithm: str = Field(default="ML-DSA-65")
    hash_algorithm: str = Field(default="sha3-256")
    argon2_memory_mb: int = Field(default=64, ge=16)
    argon2_iterations: int = Field(default=3, ge=1)
    argon2_parallelism: int = Field(default=4, ge=1)


class LoggingConfig(BaseModel):
    """Secure logging configuration."""
    model_config = ConfigDict(extra="forbid")

    level: str = Field(default="INFO")
    json_format: bool = Field(default=True)
    redact_secrets: bool = Field(default=True)
    log_file: Optional[Path] = None


class Settings(BaseModel):
    """Master application configuration."""
    model_config = ConfigDict(extra="forbid")

    mode: AppMode = Field(default=AppMode.PRODUCTION)
    airgap: AirGapConfig = Field(default_factory=AirGapConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    ledger: LedgerConfig = Field(default_factory=LedgerConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("mode", mode="before")
    @classmethod
    def parse_mode(cls, v: object) -> AppMode:
        if isinstance(v, str):
            v_upper = v.upper().strip()
            if v_upper in AppMode.__members__:
                return AppMode(v_upper)
        if isinstance(v, AppMode):
            return v
        raise ConfigurationError(f"Invalid application mode: {v!r}. Must be one of {[m.value for m in AppMode]}")

    def validate_security_invariants(self) -> None:
        """Fail closed if security-critical invariants are violated."""
        if self.mode == AppMode.PRODUCTION:
            if not self.airgap.enforce_airgap:
                raise ConfigurationError(
                    "Security Invariant Violation: 'enforce_airgap' cannot be disabled in PRODUCTION mode."
                )
            if self.airgap.allow_dns:
                raise ConfigurationError(
                    "Security Invariant Violation: 'allow_dns' cannot be enabled in PRODUCTION mode."
                )
            if not self.logging.redact_secrets:
                raise ConfigurationError(
                    "Security Invariant Violation: Secret redaction cannot be disabled in PRODUCTION mode."
                )

    @classmethod
    def from_env(cls) -> Settings:
        """Load configuration from environment variables with safe defaults."""
        mode_str = os.getenv("TRACECRYPT_MODE", "PRODUCTION")
        enforce_airgap = os.getenv("TRACECRYPT_ENFORCE_AIRGAP", "true").lower() in ("1", "true", "yes")
        allow_dns = os.getenv("TRACECRYPT_ALLOW_DNS", "false").lower() in ("1", "true", "yes")

        data_dir_env = os.getenv("TRACECRYPT_DATA_DIR")
        base_dir = Path(data_dir_env) if data_dir_env else Path("data")

        storage = StorageConfig(
            base_dir=base_dir,
            keys_dir=base_dir / "keys",
            documents_dir=base_dir / "documents",
            ledger_dir=base_dir / "ledger",
            reports_dir=base_dir / "reports",
            sqlite_db_path=base_dir / "tracecrypt_local.db"
        )

        settings = cls(
            mode=AppMode(mode_str.upper().strip()),
            airgap=AirGapConfig(
                enforce_airgap=enforce_airgap,
                allow_dns=allow_dns
            ),
            storage=storage,
            ledger=LedgerConfig(
                cluster_id=os.getenv("TRACECRYPT_LEDGER_CLUSTER", "tracecrypt-lan-1"),
                rpc_host=os.getenv("TRACECRYPT_RPC_HOST", "127.0.0.1"),
                rpc_port=int(os.getenv("TRACECRYPT_RPC_PORT", "8545"))
            ),
            logging=LoggingConfig(
                level=os.getenv("TRACECRYPT_LOG_LEVEL", "INFO"),
                json_format=os.getenv("TRACECRYPT_LOG_JSON", "true").lower() in ("1", "true", "yes"),
                redact_secrets=True
            )
        )
        settings.validate_security_invariants()
        return settings


_GLOBAL_SETTINGS: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the active global configuration, initializing from env if needed."""
    global _GLOBAL_SETTINGS
    if _GLOBAL_SETTINGS is None:
        _GLOBAL_SETTINGS = Settings.from_env()
    return _GLOBAL_SETTINGS


def reset_settings(new_settings: Optional[Settings] = None) -> None:
    """Reset or override global settings (useful for testing)."""
    global _GLOBAL_SETTINGS
    if new_settings is not None:
        new_settings.validate_security_invariants()
    _GLOBAL_SETTINGS = new_settings
