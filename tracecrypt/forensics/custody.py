"""Forensic Chain of Custody implementation with cryptographic hash chaining.

Guarantees immutable and tamper-evident audit trails for evidence handling,
normalization, watermark extraction, cryptographic verification, and export.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import SecurityError
from tracecrypt.forensics.types import ChainOfCustodyEntry, CustodyAction
from tracecrypt.utils.timestamps import utc_now_micros

GENESIS_PREVIOUS_HASH = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000"


class ChainOfCustody:
    """Manages an ordered, cryptographically hash-chained sequence of custody events."""

    def __init__(self, evidence_hash: str) -> None:
        self.evidence_hash = evidence_hash
        self._entries: List[ChainOfCustodyEntry] = []

    @property
    def entries(self) -> List[ChainOfCustodyEntry]:
        """Return shallow copy of all custody entries."""
        return list(self._entries)

    def record_action(
        self,
        action: CustodyAction,
        actor_id: str = "tracecrypt-forensics-workstation",
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[int] = None,
    ) -> ChainOfCustodyEntry:
        """Append a new tamper-evident action to the chain."""
        now = timestamp if timestamp is not None else utc_now_micros()
        seq = len(self._entries)

        if seq == 0:
            prev_hash = GENESIS_PREVIOUS_HASH
        else:
            prev_hash = self._entries[-1].action_hash

        # Compute deterministic SHA3-256 action hash over domain-separated context
        ctx = (
            f"tracecrypt:custody:v1:{seq}:{action.value}:{actor_id}:{now}:"
            f"{self.evidence_hash}:{prev_hash}"
        ).encode("utf-8")
        action_hash = Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).formatted

        entry = ChainOfCustodyEntry(
            sequence_index=seq,
            action=action,
            actor_id=actor_id,
            timestamp=now,
            evidence_hash=self.evidence_hash,
            previous_action_hash=prev_hash,
            action_hash=action_hash,
            details=details or {},
        )
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """Verify the cryptographic continuity of all entries in the chain."""
        if not self._entries:
            return True

        expected_prev = GENESIS_PREVIOUS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.sequence_index != idx:
                raise SecurityError(
                    f"Custody sequence break: expected index {idx}, got {entry.sequence_index}"
                )
            if entry.previous_action_hash != expected_prev:
                raise SecurityError(
                    f"Custody link broken at index {idx}: previous_action_hash mismatch"
                )
            if entry.evidence_hash != self.evidence_hash:
                raise SecurityError(
                    f"Custody evidence mismatch at index {idx}: expected {self.evidence_hash}, "
                    f"got {entry.evidence_hash}"
                )

            # Recompute hash
            ctx = (
                f"tracecrypt:custody:v1:{idx}:{entry.action.value}:{entry.actor_id}:"
                f"{entry.timestamp}:{self.evidence_hash}:{entry.previous_action_hash}"
            ).encode("utf-8")
            recomputed = Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).formatted
            if entry.action_hash != recomputed:
                raise SecurityError(
                    f"Custody action hash tampering detected at index {idx}: "
                    f"expected {recomputed}, got {entry.action_hash}"
                )

            expected_prev = entry.action_hash

        return True
