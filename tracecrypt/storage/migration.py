"""Production schema versioning and deterministic transactional migrations for TraceCrypt.

Supports both operational local storage (tracecrypt_local.db) and ledger persistence databases.
Refuses unsupported downgrades, verifies schema integrity, and fails closed safely.
"""

from __future__ import annotations

import sqlite3
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from tracecrypt.errors import StorageError, SecurityError
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.version import DATABASE_SCHEMA_VERSION

logger = logging.getLogger("tracecrypt.storage.migration")

# Registered migration steps for local SQLite database
# Format: {target_version: [list_of_sql_statements]}
MIGRATIONS: Dict[int, List[str]] = {
    1: [
        """
        CREATE TABLE IF NOT EXISTS schema_versions (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            description TEXT NOT NULL
        );
        """
    ]
}


class DatabaseMigrationManager:
    """Manages schema versions and deterministic transactional migrations."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    def get_current_version(self) -> int:
        """Read the currently applied schema version from the database."""
        if not self.db_path.exists():
            return 0

        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            cursor = conn.cursor()
            # Check if schema_versions table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_versions';")
            if not cursor.fetchone():
                # Check for legacy schema_metadata (used in ledger)
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_metadata';")
                if cursor.fetchone():
                    cursor.execute("SELECT MAX(version) FROM schema_metadata;")
                    row = cursor.fetchone()
                    return int(row[0]) if row and row[0] is not None else 1
                return 0

            cursor.execute("SELECT MAX(version) FROM schema_versions;")
            row = cursor.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        finally:
            conn.close()

    def check_integrity(self) -> Dict[str, Any]:
        """Perform SQLite integrity check and schema status verification."""
        if not self.db_path.exists():
            return {
                "exists": False,
                "status": "NOT_INITIALIZED",
                "current_version": 0,
                "target_version": DATABASE_SCHEMA_VERSION,
                "integrity": "N/A"
            }

        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            integrity_rows = cursor.fetchall()
            integrity_result = [r[0] for r in integrity_rows]
            is_ok = len(integrity_result) == 1 and integrity_result[0] == "ok"

            current_ver = self.get_current_version()
            is_current = (current_ver == DATABASE_SCHEMA_VERSION)

            return {
                "exists": True,
                "status": "HEALTHY" if is_ok and is_current else ("NEEDS_MIGRATION" if is_ok else "CORRUPTED"),
                "current_version": current_ver,
                "target_version": DATABASE_SCHEMA_VERSION,
                "integrity": "ok" if is_ok else "; ".join(integrity_result),
                "is_healthy": is_ok and is_current
            }
        finally:
            conn.close()

    def migrate(self) -> Tuple[int, int]:
        """Apply all pending migrations transactionally. Returns (from_version, to_version)."""
        current_ver = self.get_current_version()
        if current_ver > DATABASE_SCHEMA_VERSION:
            raise SecurityError(
                f"Unsupported database downgrade detected: database version {current_ver} "
                f"is newer than application schema version {DATABASE_SCHEMA_VERSION}. Failing closed."
            )

        if current_ver == DATABASE_SCHEMA_VERSION:
            logger.info("Database schema is already at the latest version (%d).", current_ver)
            return (current_ver, current_ver)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        now = utc_now_micros()

        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys=OFF;")
            cursor.execute("BEGIN IMMEDIATE TRANSACTION;")

            for v in range(current_ver + 1, DATABASE_SCHEMA_VERSION + 1):
                if v in MIGRATIONS:
                    for stmt in MIGRATIONS[v]:
                        formatted_stmt = stmt.format(now=now)
                        cursor.execute(formatted_stmt)
                cursor.execute(
                    "INSERT INTO schema_versions (version, applied_at, description) VALUES (?, ?, ?);",
                    (v, now, f"Migration to version {v}")
                )

            cursor.execute("PRAGMA foreign_keys=ON;")
            conn.commit()
            logger.info("Database migrated successfully from v%d to v%d.", current_ver, DATABASE_SCHEMA_VERSION)
            return (current_ver, DATABASE_SCHEMA_VERSION)
        except Exception as e:
            conn.rollback()
            raise StorageError(f"Database migration failed: {e}. Transaction rolled back.") from e
        finally:
            conn.close()
