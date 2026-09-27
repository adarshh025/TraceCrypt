"""Deterministic Transaction Mempool with cryptographic validation and replay defense.

Guarantees:
- Rejection of duplicates against both committed state and pending mempool
- Validation of recipient ML-DSA-65 signatures and Root CA certificate chain
- Deterministic transaction ordering: sorted by (submitted_at, transaction_id)
- Bounded capacity (max pending count and max payload bytes)
- Atomic removal of committed transactions upon block finality
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Sequence, Set

from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.errors import ReplayAttackError, TransactionValidationError
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.ledger.block import LedgerTransaction
from tracecrypt.ledger.state import LedgerState
from tracecrypt.utils.identifiers import EventID, SessionID, TransactionID, WatermarkID


DEFAULT_MAX_MEMPOOL_TRANSACTIONS = 10_000
DEFAULT_MAX_MEMPOOL_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_TX_SIZE_BYTES = 64 * 1024        # 64 KB


class Mempool:
    """Thread-safe, deterministic transaction pool for a BFT validator node."""

    def __init__(
        self,
        max_transactions: int = DEFAULT_MAX_MEMPOOL_TRANSACTIONS,
        max_bytes: int = DEFAULT_MAX_MEMPOOL_BYTES,
        max_tx_bytes: int = DEFAULT_MAX_TX_SIZE_BYTES,
    ) -> None:
        self.max_transactions = max_transactions
        self.max_bytes = max_bytes
        self.max_tx_bytes = max_tx_bytes

        self._lock = threading.RLock()
        self._txs: Dict[TransactionID, LedgerTransaction] = {}
        self._pending_events: Set[EventID] = set()
        self._pending_sessions: Set[SessionID] = set()
        self._pending_watermarks: Set[WatermarkID] = set()
        self._current_bytes: int = 0

    @property
    def size(self) -> int:
        """Count of pending transactions in mempool."""
        with self._lock:
            return len(self._txs)

    @property
    def total_bytes(self) -> int:
        """Total memory footprint of pending transactions."""
        with self._lock:
            return self._current_bytes

    def contains(self, tx_id: TransactionID | str) -> bool:
        """Check if transaction is currently pending in mempool."""
        with self._lock:
            return TransactionID(str(tx_id)) in self._txs

    def has_transaction(self, tx_id: TransactionID | str) -> bool:
        """Alias for contains()."""
        return self.contains(tx_id)

    def has_event(self, event_id: EventID | str) -> bool:
        """Check if event is currently pending in mempool."""
        with self._lock:
            return EventID(str(event_id)) in self._pending_events

    def has_session(self, session_id: SessionID | str) -> bool:
        """Check if session is currently pending in mempool."""
        with self._lock:
            return SessionID(str(session_id)) in self._pending_sessions

    def has_watermark(self, watermark_id: WatermarkID | str) -> bool:
        """Check if watermark is currently pending in mempool."""
        with self._lock:
            return WatermarkID(str(watermark_id)) in self._pending_watermarks

    def add_transaction(
        self,
        tx: LedgerTransaction,
        committed_state: Optional[LedgerState] = None,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[object] = None,
    ) -> None:
        """Validate and insert transaction into mempool.

        Raises:
            ReplayAttackError: If duplicate TransactionID, EventID, SessionID, or WatermarkID.
            TransactionValidationError: If cryptographic signature or certificate is invalid.
        """
        with self._lock:
            # 1. Capacity check
            if len(self._txs) >= self.max_transactions:
                raise TransactionValidationError("Mempool capacity exceeded: pool is full.")

            # 2. Transaction size check
            tx_canonical_bytes = tx.to_canonical_bytes()
            tx_size = len(tx_canonical_bytes)
            if tx_size > self.max_tx_bytes:
                raise TransactionValidationError(
                    f"Transaction size {tx_size} exceeds limit {self.max_tx_bytes} bytes."
                )

            tx_id = tx.transaction_id
            event = tx.signed_event.event

            # 3. Check duplicates against pending mempool
            if tx_id in self._txs:
                raise ReplayAttackError(f"Duplicate transaction '{tx_id}' already pending in mempool.")
            if event.event_id in self._pending_events:
                raise ReplayAttackError(f"Duplicate event '{event.event_id}' already pending in mempool.")
            if event.session_id in self._pending_sessions:
                raise ReplayAttackError(f"Duplicate session '{event.session_id}' already pending in mempool.")
            if event.watermark_id in self._pending_watermarks:
                raise ReplayAttackError(f"Duplicate watermark '{event.watermark_id}' already pending in mempool.")

            # 4. Check duplicates against committed ledger state
            if committed_state is not None:
                committed_state.validate_transaction(tx)

            # 5. Cryptographic signature and certificate validation (if certificate provided)
            if tx.recipient_certificate is not None:
                verification_result = DecryptionEventVerifier.verify_signed_event(
                    signed_event=tx.signed_event,
                    recipient_certificate=tx.recipient_certificate,
                    root_ca_public_key=root_ca_public_key,
                    revocation_provider=revocation_provider,
                    expected_document_hash=event.document_hash,
                    expected_watermark_id=event.watermark_id,
                    expected_session_id=event.session_id,
                )
                if not verification_result.valid:
                    err_summary = "; ".join(verification_result.errors)
                    raise TransactionValidationError(
                        f"Cryptographic validation failed for event {event.event_id}: {err_summary}"
                    )

            # 6. Insert into pending tracking
            self._txs[tx_id] = tx
            self._pending_events.add(event.event_id)
            self._pending_sessions.add(event.session_id)
            self._pending_watermarks.add(event.watermark_id)
            self._current_bytes += tx_size

    def get_ordered_transactions(
        self,
        max_count: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> List[LedgerTransaction]:
        """Produce deterministically ordered transactions for block proposal.

        Ordering rule:
        Sorted strictly by (submitted_at, transaction_id).
        Guarantees that any two nodes with identical mempools construct identical proposals.
        """
        with self._lock:
            sorted_txs = sorted(
                self._txs.values(),
                key=lambda tx: (tx.submitted_at, str(tx.transaction_id))
            )

            selected: List[LedgerTransaction] = []
            accumulated_bytes = 0

            for tx in sorted_txs:
                if max_count is not None and len(selected) >= max_count:
                    break
                tx_len = len(tx.to_canonical_bytes())
                if max_bytes is not None and accumulated_bytes + tx_len > max_bytes:
                    break
                selected.append(tx)
                accumulated_bytes += tx_len

            return selected

    def remove_committed(self, committed_transactions: Sequence[LedgerTransaction]) -> None:
        """Atomically evict committed transactions from mempool upon block finality."""
        with self._lock:
            for tx in committed_transactions:
                tx_id = tx.transaction_id
                if tx_id in self._txs:
                    evicted = self._txs.pop(tx_id)
                    evt = evicted.signed_event.event
                    self._pending_events.discard(evt.event_id)
                    self._pending_sessions.discard(evt.session_id)
                    self._pending_watermarks.discard(evt.watermark_id)
                    self._current_bytes -= len(evicted.to_canonical_bytes())
                    if self._current_bytes < 0:
                        self._current_bytes = 0

    def clear(self) -> None:
        """Reset mempool to empty state."""
        with self._lock:
            self._txs.clear()
            self._pending_events.clear()
            self._pending_sessions.clear()
            self._pending_watermarks.clear()
            self._current_bytes = 0
