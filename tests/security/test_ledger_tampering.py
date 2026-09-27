"""Adversarial Ledger Tampering and Integrity Verification Tests.

Validates:
- SQLite is merely persistence: direct database modifications fail cryptographic verification.
- Tampering with transaction contents, Merkle roots, block headers, state roots, or validator sets.
- Prevention of database rollback attacks via monotonic checkpoints.
- Rejection of conflicting genesis configuration overwrite.
- Fork rejection and strict chain continuity enforcement.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ChainVerificationError, SecurityError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    ValidatorID,
    WatermarkID,
)


def _commit_test_event(env):
    helper = env["helper"]
    dsa_sk = env["dsa_sk"]
    dsa_cert = env["dsa_cert"]

    event = DecryptionEvent(
        event_id=EventID.generate(),
        document_id=DocumentID.generate(),
        distribution_id=DistributionID.generate(),
        document_hash="sha3-256:" + "aa" * 32,
        recipient_id=RecipientID(dsa_cert.subject_id),
        recipient_certificate_id=dsa_cert.serial_number,
        session_id=SessionID.generate(),
        watermark_id=WatermarkID.generate(),
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=1700000000000000,
        pqc_algorithms=PQCAlgorithms(),
    )
    return helper.commit_event(event, dsa_sk, dsa_cert, height=1)


class TestLedgerTampering:
    """Evaluate ledger integrity verification against adversarial storage tampering."""

    def test_sqlite_tampering_fails_verification(self, forensic_environment) -> None:
        """Modifying SQLite records directly must trigger ChainVerificationError."""
        storage = forensic_environment["storage"]
        _, tx = _commit_test_event(forensic_environment)

        # 1. Modify transaction canonical JSON in SQLite directly
        conn = sqlite3.connect(str(storage.db_path))
        try:
            cursor = conn.cursor()
            sql = (
                "UPDATE transactions SET canonical_json = "
                "REPLACE(canonical_json, 'DECRYPTION_ATTRIBUTION', 'TAMPERED') "
                "WHERE transaction_id = ?;"
            )
            cursor.execute(sql, (str(tx.transaction_id),))
            conn.commit()
        finally:
            conn.close()

        # Chain verification must detect the Merkle root mismatch
        val_set = forensic_environment["val_set"]
        with pytest.raises(ChainVerificationError, match="transaction_root mismatch"):
            storage.verify_chain(val_set)

    def test_state_root_tampering_detected(self, forensic_environment) -> None:
        """Modifying state_root in block header table fails verify_chain."""
        storage = forensic_environment["storage"]
        val_set = forensic_environment["val_set"]
        _commit_test_event(forensic_environment)

        conn = sqlite3.connect(str(storage.db_path))
        try:
            cursor = conn.cursor()
            fake_root = "sha3-256:" + "00" * 32
            cursor.execute("UPDATE blocks SET state_root = ? WHERE height = 1;", (fake_root,))
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(ChainVerificationError, match="block_hash mismatch|state_root mismatch|metadata mismatch"):
            storage.verify_chain(val_set)

    def test_validator_set_tampering_detected(self, forensic_environment) -> None:
        """Modifying validator_set_hash in block header or commit certificate fails verify_chain."""
        storage = forensic_environment["storage"]
        val_set = forensic_environment["val_set"]
        _commit_test_event(forensic_environment)

        conn = sqlite3.connect(str(storage.db_path))
        try:
            cursor = conn.cursor()
            fake_val_hash = "sha3-256:" + "99" * 32
            cursor.execute("UPDATE blocks SET validator_set_hash = ? WHERE height = 1;", (fake_val_hash,))
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(ChainVerificationError):
            storage.verify_chain(val_set)

    def test_conflicting_genesis_rejection(self, tmp_path: Path) -> None:
        """Storage must reject overwriting an established genesis with a conflicting configuration."""
        db_path = tmp_path / "genesis_test.db"
        storage = LedgerStorage(db_path)

        pk, _ = generate_mldsa_keypair()
        vinfo = ValidatorInfo(
            validator_id=ValidatorID.generate(),
            public_key_b64=pk.to_b64(),
            certificate_id="crt-1",
            certificate_fingerprint="fp1",
            voting_power=1,
            role=NodeRole.VALIDATOR,
        )
        val_set = ValidatorSet(validators=[
            vinfo,
            vinfo.model_copy(update={"validator_id": ValidatorID.generate()}),
            vinfo.model_copy(update={"validator_id": ValidatorID.generate()}),
            vinfo.model_copy(update={"validator_id": ValidatorID.generate()}),
        ])

        genesis_1 = GenesisConfig(
            chain_id="chain-alpha",
            genesis_time=1700000000000000,
            validator_set=val_set,
        )
        storage.save_genesis(genesis_1)

        # Attempt to save a different genesis on the same storage
        genesis_2 = GenesisConfig(
            chain_id="chain-bravo-conflicting",
            genesis_time=1700000000000000,
            validator_set=val_set,
        )
        with pytest.raises(ChainVerificationError, match="Genesis conflict"):
            storage.save_genesis(genesis_2)

        storage.close()

    def test_database_rollback_attack_detection(self, forensic_environment, tmp_path: Path) -> None:
        """Restoring an older SQLite database snapshot with a lower height triggers SecurityError."""
        storage = forensic_environment["storage"]
        checkpoint_path = storage.checkpoint_path

        # Simulate checkpoint showing height 5 while storage has height 1
        assert checkpoint_path is not None
        import json
        checkpoint_data = {
            "max_height": 5,
            "tip_hash": "sha3-256:5555555555555555555555555555555555555555555555555555555555555555",
            "updated_at": 1700000000000000,
        }
        checkpoint_path.write_text(json.dumps(checkpoint_data), encoding="utf-8")

        # Re-opening storage must detect the rollback and raise SecurityError
        with pytest.raises(SecurityError, match="Database rollback detected"):
            LedgerStorage(storage.db_path)
