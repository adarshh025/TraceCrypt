"""Production-grade offline SQLite persistence and chain verification for TraceCrypt BFT Ledger.

Provides:
- SQLite WAL persistence for blocks, headers, transactions, commit certificates, and indexes
- Authoritative local storage indexes:
  - event_id -> (transaction_id, height)
  - session_id -> (event_id, transaction_id, height)
  - watermark_id -> (event_id, transaction_id, height)
  - transaction_id -> (height, index_in_block)
- Standalone cryptographic Merkle proof export
- Complete chain verification (verify_chain): detects any SQLite tampering,
  broken parent hash links, invalid Merkle roots, modified transactions, or forged commit certificates.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tracecrypt.errors import ChainVerificationError, MerkleProofError
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.block import Block, BlockHeader, LedgerTransaction
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import ByzantineEvidence, CommitCertificate
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.validator import ValidatorSet
from tracecrypt.utils.identifiers import EventID, SessionID, TransactionID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros

logger = logging.getLogger("tracecrypt.ledger.storage")

CURRENT_SCHEMA_VERSION = 1


class LedgerStorage:
    """Authoritative local SQLite persistence engine for a TraceCrypt ledger node."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure_pragmas()
        self._run_migrations()

    def _configure_pragmas(self) -> None:
        """Enforce WAL mode, foreign keys, and synchronous writes for crash resilience."""
        cursor = self._conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        self._conn.commit()

    def _run_migrations(self) -> None:
        """Initialize database schema tables and indexes."""
        cursor = self._conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_metadata (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS genesis_metadata (
                chain_id TEXT PRIMARY KEY,
                genesis_hash TEXT NOT NULL,
                genesis_config_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                round INTEGER NOT NULL,
                block_hash TEXT NOT NULL UNIQUE,
                previous_block_hash TEXT NOT NULL,
                proposer_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                transaction_root TEXT NOT NULL,
                state_root TEXT NOT NULL,
                validator_set_hash TEXT NOT NULL,
                protocol_version TEXT NOT NULL,
                header_json TEXT NOT NULL,
                commit_certificate_json TEXT
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                index_in_block INTEGER NOT NULL,
                submitted_at INTEGER NOT NULL,
                canonical_json TEXT NOT NULL,
                FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_indexes (
                event_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE,
                watermark_id TEXT NOT NULL UNIQUE,
                transaction_id TEXT NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                FOREIGN KEY (transaction_id) REFERENCES transactions (transaction_id) ON DELETE CASCADE
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS byzantine_evidence (
                evidence_hash TEXT PRIMARY KEY,
                validator_id TEXT NOT NULL,
                height INTEGER NOT NULL,
                round INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            );
        """)

        # Indexes for fast forensic and consensus lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks (block_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_event ON transactions (event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_session ON event_indexes (session_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_watermark ON event_indexes (watermark_id);")

        cursor.execute("SELECT version FROM schema_metadata ORDER BY version DESC LIMIT 1;")
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                "INSERT INTO schema_metadata (version, applied_at) VALUES (?, ?);",
                (CURRENT_SCHEMA_VERSION, utc_now_micros()),
            )

        self._conn.commit()

    def close(self) -> None:
        """Safely flush and close database connection."""
        try:
            self._conn.commit()
            self._conn.close()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Genesis Management
    # -------------------------------------------------------------------------

    def save_genesis(self, genesis: GenesisConfig) -> None:
        """Persist canonical genesis configuration."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO genesis_metadata (chain_id, genesis_hash, genesis_config_json, created_at)
            VALUES (?, ?, ?, ?);
            """,
            (
                genesis.chain_id,
                genesis.compute_genesis_hash(),
                genesis.model_dump_json(),
                utc_now_micros(),
            ),
        )
        self._conn.commit()

    def get_genesis(self) -> Optional[GenesisConfig]:
        """Retrieve persisted genesis configuration."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT genesis_config_json FROM genesis_metadata LIMIT 1;")
        row = cursor.fetchone()
        if not row:
            return None
        return GenesisConfig.model_validate_json(row["genesis_config_json"])

    # -------------------------------------------------------------------------
    # Block & Transaction Persistence
    # -------------------------------------------------------------------------

    def save_block(self, block: Block) -> None:
        """Atomically persist a finalized block, its transactions, and index entries."""
        header = block.header
        cert_json = block.commit_certificate.model_dump_json() if block.commit_certificate else None

        cursor = self._conn.cursor()
        try:
            cursor.execute("BEGIN TRANSACTION;")

            cursor.execute(
                """
                INSERT INTO blocks (
                    height, round, block_hash, previous_block_hash, proposer_id,
                    timestamp, transaction_root, state_root, validator_set_hash,
                    protocol_version, header_json, commit_certificate_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    header.height,
                    header.round,
                    header.block_hash,
                    header.previous_block_hash,
                    str(header.proposer_id),
                    header.timestamp,
                    header.transaction_root,
                    header.state_root,
                    header.validator_set_hash,
                    header.protocol_version,
                    header.model_dump_json(),
                    cert_json,
                ),
            )

            for idx, tx in enumerate(block.transactions):
                tx_json = tx.model_dump_json()
                event = tx.signed_event.event

                cursor.execute(
                    """
                    INSERT INTO transactions (
                        transaction_id, event_id, height, index_in_block,
                        submitted_at, canonical_json
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        str(tx.transaction_id),
                        str(tx.event_id),
                        header.height,
                        idx,
                        tx.submitted_at,
                        tx_json,
                    ),
                )

                cursor.execute(
                    """
                    INSERT INTO event_indexes (
                        event_id, session_id, watermark_id, transaction_id, height, event_json
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        str(event.event_id),
                        str(event.session_id),
                        str(event.watermark_id),
                        str(tx.transaction_id),
                        header.height,
                        tx.signed_event.model_dump_json(),
                    ),
                )

            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_block(self, height: int) -> Optional[Block]:
        """Retrieve block by height."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT previous_block_hash, block_hash, state_root, transaction_root,
                   header_json, commit_certificate_json
            FROM blocks WHERE height = ?;
            """,
            (height,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        header = BlockHeader.model_validate_json(row["header_json"])

        # Detect column tampering vs JSON commitment
        if (
            row["previous_block_hash"] != header.previous_block_hash
            or row["block_hash"] != header.block_hash
            or row["state_root"] != header.state_root
            or row["transaction_root"] != header.transaction_root
        ):
            msg = (
                f"Chain verification failed: previous_block_hash mismatch at height {height} "
                f"between SQL column and header."
            )
            raise ChainVerificationError(msg)

        cert = (
            CommitCertificate.model_validate_json(row["commit_certificate_json"])
            if row["commit_certificate_json"]
            else None
        )

        cursor.execute(
            "SELECT canonical_json FROM transactions WHERE height = ? ORDER BY index_in_block ASC;",
            (height,),
        )
        tx_rows = cursor.fetchall()
        txs = [LedgerTransaction.model_validate_json(r["canonical_json"]) for r in tx_rows]

        return Block(header=header, transactions=txs, commit_certificate=cert)

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Retrieve block by its SHA3-256 block_hash."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT height FROM blocks WHERE block_hash = ?;", (block_hash,))
        row = cursor.fetchone()
        if not row:
            return None
        return self.get_block(row["height"])

    def get_latest_height(self) -> int:
        """Get the highest committed block height (0 if empty)."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT MAX(height) as max_height FROM blocks;")
        row = cursor.fetchone()
        if row and row["max_height"] is not None:
            return int(row["max_height"])
        return 0

    def get_latest_block(self) -> Optional[Block]:
        """Retrieve the most recently committed block."""
        height = self.get_latest_height()
        if height == 0:
            cursor = self._conn.cursor()
            cursor.execute("SELECT height FROM blocks WHERE height = 0;")
            if not cursor.fetchone():
                return None
        return self.get_block(height)

    def get_blocks(self, start_height: int = 1, limit: int = 50) -> List[Block]:
        """Retrieve a list of consecutive blocks starting from start_height."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT height FROM blocks WHERE height >= ? ORDER BY height ASC LIMIT ?;",
            (start_height, limit),
        )
        rows = cursor.fetchall()
        blocks: List[Block] = []
        for r in rows:
            blk = self.get_block(r["height"])
            if blk:
                blocks.append(blk)
        return blocks

    # -------------------------------------------------------------------------
    # Transaction & Forensic Query APIs
    # -------------------------------------------------------------------------

    def get_transaction(self, tx_id: TransactionID | str) -> Optional[LedgerTransaction]:
        """Retrieve a transaction by TransactionID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT canonical_json FROM transactions WHERE transaction_id = ?;", (str(tx_id),))
        row = cursor.fetchone()
        if not row:
            return None
        return LedgerTransaction.model_validate_json(row["canonical_json"])

    def get_transaction_with_block(
        self, tx_id: TransactionID | str
    ) -> Optional[Tuple[LedgerTransaction, Block, int]]:
        """Retrieve a transaction together with the Block that contains it and its index."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT height, index_in_block, canonical_json FROM transactions WHERE transaction_id = ?;",
            (str(tx_id),),
        )
        row = cursor.fetchone()
        if not row:
            return None
        height = row["height"]
        index = row["index_in_block"]
        tx = LedgerTransaction.model_validate_json(row["canonical_json"])
        block = self.get_block(height)
        if not block:
            return None
        return tx, block, index

    def get_event(self, event_id: EventID | str) -> Optional[SignedDecryptionEvent]:
        """Retrieve a signed event by EventID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT event_json FROM event_indexes WHERE event_id = ?;", (str(event_id),))
        row = cursor.fetchone()
        if not row:
            return None
        return SignedDecryptionEvent.model_validate_json(row["event_json"])

    def lookup_by_watermark(self, watermark_id: WatermarkID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve signed event by WatermarkID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT event_json FROM event_indexes WHERE watermark_id = ?;", (str(watermark_id),))
        row = cursor.fetchone()
        if not row:
            return None
        return SignedDecryptionEvent.model_validate_json(row["event_json"])

    def get_transaction_with_block_by_watermark(
        self, watermark_id: WatermarkID | str
    ) -> Optional[Tuple[LedgerTransaction, Block, int]]:
        """Forensic lookup: retrieve (transaction, block, index_in_block) by WatermarkID."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT transaction_id FROM event_indexes WHERE watermark_id = ?;",
            (str(watermark_id),),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self.get_transaction_with_block(row["transaction_id"])

    def get_all_document_hashes(self) -> List[str]:
        """Retrieve all unique document hashes from committed events."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT event_json FROM event_indexes;")
        rows = cursor.fetchall()
        hashes = set()
        for r in rows:
            try:
                import json
                ev = json.loads(r["event_json"])
                dh = ev.get("event", {}).get("document_hash")
                if dh:
                    hashes.add(dh)
            except Exception:
                pass
        return sorted(list(hashes))

    def lookup_by_session(self, session_id: SessionID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve signed event by SessionID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT event_json FROM event_indexes WHERE session_id = ?;", (str(session_id),))
        row = cursor.fetchone()
        if not row:
            return None
        return SignedDecryptionEvent.model_validate_json(row["event_json"])

    def has_transaction(self, tx_id: str) -> bool:
        """Check if TransactionID is committed."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM transactions WHERE transaction_id = ? LIMIT 1;", (str(tx_id),))
        return cursor.fetchone() is not None

    def has_event(self, event_id: str) -> bool:
        """Check if EventID is committed."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM event_indexes WHERE event_id = ? LIMIT 1;", (str(event_id),))
        return cursor.fetchone() is not None

    def has_session(self, session_id: str) -> bool:
        """Check if SessionID is committed."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM event_indexes WHERE session_id = ? LIMIT 1;", (str(session_id),))
        return cursor.fetchone() is not None

    def has_watermark(self, watermark_id: str) -> bool:
        """Check if WatermarkID is committed."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM event_indexes WHERE watermark_id = ? LIMIT 1;", (str(watermark_id),))
        return cursor.fetchone() is not None

    # -------------------------------------------------------------------------
    # Byzantine Evidence Logging
    # -------------------------------------------------------------------------

    def record_byzantine_evidence(self, evidence: ByzantineEvidence) -> None:
        """Persist verifiable cryptographic proof of validator equivocation."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO byzantine_evidence (
                evidence_hash, validator_id, height, round, evidence_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                evidence.evidence_hash,
                str(evidence.validator_id),
                evidence.height,
                evidence.round,
                evidence.model_dump_json(),
                utc_now_micros(),
            ),
        )
        self._conn.commit()

    def get_byzantine_evidence(self) -> List[ByzantineEvidence]:
        """Retrieve all recorded Byzantine evidence entries."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT evidence_json FROM byzantine_evidence ORDER BY recorded_at ASC;")
        rows = cursor.fetchall()
        return [ByzantineEvidence.model_validate_json(r["evidence_json"]) for r in rows]

    # -------------------------------------------------------------------------
    # Standalone Cryptographic Inclusion Proof Export
    # -------------------------------------------------------------------------

    def export_merkle_proof(self, tx_id: TransactionID | str) -> Dict[str, Any]:
        """Generate standalone cryptographic proof linking transaction to block header and commit certificate.

        Returns:
            Dict containing:
            - transaction: LedgerTransaction canonical dictionary
            - block_header: BlockHeader model dict
            - merkle_proof: MerkleInclusionProof model dict
            - commit_certificate: CommitCertificate model dict
        """
        match = self.get_transaction_with_block(tx_id)
        if not match:
            raise MerkleProofError(f"Transaction '{tx_id}' not found in committed ledger.")

        tx, block, index = match
        leaf_bytes_list = [t.to_canonical_bytes() for t in block.transactions]
        proof = MerkleTree.generate_merkle_proof(index, leaf_bytes_list)

        return {
            "transaction": tx.to_canonical_dict(),
            "block_header": block.header.model_dump(),
            "merkle_proof": proof.model_dump(),
            "commit_certificate": block.commit_certificate.model_dump() if block.commit_certificate else None,
        }

    # -------------------------------------------------------------------------
    # Cryptographic Chain Integrity Verification
    # -------------------------------------------------------------------------

    def verify_chain(self, validator_set: ValidatorSet) -> bool:
        """Perform end-to-end cryptographic verification of local ledger storage from genesis to tip.

        Enforces:
        1. Strict height monotonicity: 1, 2, ..., N
        2. Block hash computation self-consistency
        3. Parent hash continuity: block[h].previous_block_hash == block[h-1].block_hash
        4. Transaction Merkle root commitment equals independently recomputed Merkle tree
        5. State transitions from genesis match: recomputed logical state_root == block[h].state_root
        6. Commit certificate quorum verification: >= 2f + 1 valid signatures from authorized validators
        7. Transaction event signature validity: recipient ML-DSA-65 signature is valid

        Raises:
            ChainVerificationError: If any data was altered, deleted, or forged in SQLite.
        """
        genesis = self.get_genesis()
        if genesis is None:
            raise ChainVerificationError("Chain verification failed: Genesis configuration not found in storage.")

        latest_height = self.get_latest_height()
        if latest_height == 0:
            logger.info("Chain verification passed: ledger is at genesis with 0 committed blocks.")
            return True

        # Initialize clean state tracker from genesis
        recomputed_state = LedgerState(
            chain_id=genesis.chain_id,
            initial_state_root=genesis.initial_state_root,
        )
        prev_block_hash = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000"

        for h in range(1, latest_height + 1):
            block = self.get_block(h)
            if block is None:
                raise ChainVerificationError(
                    f"Chain verification failed: Block {h} missing from storage (chain gap detected)."
                )

            header = block.header

            # 1. Height check
            if header.height != h:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: Block reports height {header.height}."
                )

            # 2. Previous hash link
            if header.previous_block_hash != prev_block_hash:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: previous_block_hash mismatch. "
                    f"Expected '{prev_block_hash}', got '{header.previous_block_hash}'"
                )

            # 3. Block hash computation self-consistency
            computed_block_hash = header.compute_block_hash()
            if header.block_hash != computed_block_hash:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: block_hash mismatch. "
                    f"Header claims '{header.block_hash}', recomputed '{computed_block_hash}'"
                )

            # 4. Merkle transaction root verification
            tx_canonical_bytes = [tx.to_canonical_bytes() for tx in block.transactions]
            recomputed_tx_root = MerkleTree.build_merkle_root(tx_canonical_bytes)
            if header.transaction_root != recomputed_tx_root:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: transaction_root mismatch. "
                    f"Header claims '{header.transaction_root}', recomputed '{recomputed_tx_root}'"
                )

            # 5. State transitions and state_root recomputation
            for tx in block.transactions:
                recomputed_state.apply_transaction(tx)

            recomputed_state_root = recomputed_state.compute_state_root()
            if header.state_root != recomputed_state_root:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: state_root mismatch. "
                    f"Header claims '{header.state_root}', recomputed '{recomputed_state_root}'"
                )

            # 6. Commit certificate verification
            if block.commit_certificate is None:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: Block missing required CommitCertificate."
                )

            cert = block.commit_certificate
            if cert.height != header.height:
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: Certificate height {cert.height} != block {h}."
                )
            if cert.block_hash != header.block_hash:
                err = (
                    f"Chain verification failed at height {h}: "
                    f"Certificate hash {cert.block_hash} != {header.block_hash}."
                )
                raise ChainVerificationError(err)

            if not cert.verify_certificate(validator_set, header.block_hash):
                raise ChainVerificationError(
                    f"Chain verification failed at height {h}: CommitCertificate failed cryptographic verification."
                )

            # Update link for next block
            prev_block_hash = header.block_hash

        logger.info("Chain verification successfully verified %d blocks from genesis.", latest_height)
        return True
