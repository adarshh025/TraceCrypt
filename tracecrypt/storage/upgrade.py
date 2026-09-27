"""Deterministic offline upgrade engine for TraceCrypt.

Coordinates:
- Pre-upgrade state snapshot & backup
- Protocol compatibility validation
- Transactional database schema migration
- Post-upgrade system doctor validation
- Safe failure & rollback guidance
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from tracecrypt.errors import StorageError, SecurityError, ConfigurationError
from tracecrypt.storage.backup import BackupManager
from tracecrypt.storage.migration import DatabaseMigrationManager
from tracecrypt.version import (
    APPLICATION_VERSION,
    PROTOCOL_VERSION,
    verify_protocol_compatibility,
    parse_semver,
)

logger = logging.getLogger("tracecrypt.storage.upgrade")


class UpgradeManager:
    """Manages system version checks, upgrade preparation, and verification."""

    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.backup_mgr = BackupManager(self.data_dir)
        self.migration_mgr = DatabaseMigrationManager(self.data_dir / "tracecrypt_local.db")

    def check_upgrade(self, target_version_str: str) -> Dict[str, Any]:
        """Check compatibility between current version and target upgrade version."""
        current_app = APPLICATION_VERSION
        current_proto = PROTOCOL_VERSION

        try:
            target_major, target_minor, target_patch = parse_semver(target_version_str)
            curr_major, curr_minor, curr_patch = parse_semver(current_app)
        except Exception as e:
            raise ConfigurationError(f"Invalid version string: {e}")

        is_downgrade = (target_major, target_minor, target_patch) < (curr_major, curr_minor, curr_patch)
        if is_downgrade:
            return {
                "allowed": False,
                "reason": "Downgrades are strictly prohibited in production mode to prevent rollback attacks.",
                "current_version": current_app,
                "target_version": target_version_str,
            }

        # Check protocol compatibility
        is_proto_compatible = (target_major == curr_major)

        return {
            "allowed": is_proto_compatible,
            "current_version": current_app,
            "target_version": target_version_str,
            "requires_breaking_migration": (target_major > curr_major),
            "reason": "Compatible release upgrade" if is_proto_compatible else "Breaking protocol major version change",
        }

    def prepare_upgrade(self, backup_output_dir: Optional[Path | str] = None) -> Path:
        """Create a mandatory pre-upgrade backup snapshot."""
        out_dir = Path(backup_output_dir).resolve() if backup_output_dir else self.data_dir / "backups"
        out_dir.mkdir(parents=True, exist_ok=True)
        backup_file = out_dir / f"pre_upgrade_backup_v{APPLICATION_VERSION}.tcbackup"

        logger.info("Creating mandatory pre-upgrade backup: %s", backup_file)
        created_path = self.backup_mgr.create_backup(
            output_path=backup_file,
            include_keystores=False,
            description=f"Pre-upgrade backup before upgrading from {APPLICATION_VERSION}",
        )
        # Verify immediately
        self.backup_mgr.verify_backup(created_path)
        return created_path

    def apply_upgrade(self) -> Dict[str, Any]:
        """Apply database migrations and system updates."""
        logger.info("Applying database migrations...")
        from_ver, to_ver = self.migration_mgr.migrate()
        return {
            "status": "MIGRATIONS_APPLIED",
            "schema_from_version": from_ver,
            "schema_to_version": to_ver,
            "application_version": APPLICATION_VERSION,
            "protocol_version": PROTOCOL_VERSION,
        }

    def verify_upgrade(self) -> Dict[str, Any]:
        """Verify post-upgrade database integrity and system state."""
        db_integrity = self.migration_mgr.check_integrity()
        if not db_integrity.get("is_healthy", False):
            raise StorageError(f"Post-upgrade integrity check failed: {db_integrity}")

        return {
            "status": "UPGRADE_VERIFIED",
            "application_version": APPLICATION_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "database_integrity": db_integrity,
        }
