"""Development / Test-Only In-Memory Ledger Adapter.

================================================================================
CRITICAL ARCHITECTURAL WARNING:
THIS MODULE IS FOR DEVELOPMENT AND TEST AUTOMATION ONLY.
IT IS NOT A DISTRIBUTED LEDGER, BLOCKCHAIN, OR BYZANTINE FAULT TOLERANT ENGINE.
PRODUCTION DEPLOYMENTS MUST CONNECT TO THE PHASE 6 BFT DISTRIBUTED LEDGER.
================================================================================
"""

from __future__ import annotations

import threading
from typing import ClassVar, Dict, Optional, Set, Tuple

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import LedgerError, ReplayAttackError
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.utils.identifiers import EventID, SessionID, TransactionID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros


class InMemoryLedgerAdapter:
    """In-memory mock adapter fulfilling the DecryptionEventLedger protocol.

    ENVIRONMENT: DEVELOPMENT / TEST ONLY.
    DO NOT USE IN PRODUCTION.
    """

    ENVIRONMENT: ClassVar[str] = "DEVELOPMENT / TEST ONLY"

    def __init__(
        self,
        simulate_rejection: bool = False,
        simulate_timeout: bool = False,
        simulate_network_failure: bool = False,
    ) -> None:
        self._lock = threading.Lock()
        self._events: Dict[str, SignedDecryptionEvent] = {}
        self._transactions: Dict[str, LedgerTransactionReceipt] = {}
        self._session_ids: Set[str] = set()
        self._watermark_ids: Set[str] = set()
        self._doc_session_pairs: Set[Tuple[str, str]] = set()
        self._watermark_to_event: Dict[str, str] = {}

        # Testing control flags
        self.simulate_rejection = simulate_rejection
        self.simulate_timeout = simulate_timeout
        self.simulate_network_failure = simulate_network_failure

    def submit_event(self, signed_event: SignedDecryptionEvent) -> LedgerTransactionReceipt:
        """Submit a signed decryption event to the in-memory ledger store.

        Enforces strict anti-replay validation:
        - Rejects duplicate EventID
        - Rejects duplicate SessionID
        - Rejects duplicate WatermarkID
        - Rejects duplicate (DocumentID, SessionID) pair
        """
        with self._lock:
            if self.simulate_network_failure:
                raise LedgerError("Simulated ledger transport connection failure (network unreachable)")

            event = signed_event.event
            eid = str(event.event_id)
            sid = str(event.session_id)
            wmid = str(event.watermark_id)
            doc_id = str(event.document_id)
            doc_ses_pair = (doc_id, sid)
            now = utc_now_micros()

            # Anti-Replay: Check EventID duplicate
            if eid in self._events:
                raise ReplayAttackError(
                    f"Replay rejected: EventID '{eid}' has already been submitted to the ledger."
                )

            # Anti-Replay: Check SessionID duplicate
            if sid in self._session_ids:
                raise ReplayAttackError(
                    f"Replay rejected: SessionID '{sid}' has already been used in an attribution event."
                )

            # Anti-Replay: Check WatermarkID duplicate
            if wmid in self._watermark_ids:
                raise ReplayAttackError(
                    f"Replay rejected: WatermarkID '{wmid}' has already been consumed."
                )

            # Anti-Replay: Check (DocumentID, SessionID) pair
            if doc_ses_pair in self._doc_session_pairs:
                raise ReplayAttackError(
                    f"Replay rejected: DocumentID '{doc_id}' with SessionID '{sid}' already exists."
                )

            # Generate unique TransactionID
            tx_id = str(SecureRandom.generate_typed_id(TransactionID))

            # Simulate timeout / unknown state if requested
            if self.simulate_timeout:
                receipt = LedgerTransactionReceipt(
                    transaction_id=tx_id,
                    event_id=event.event_id,
                    status=CommitStatus.UNKNOWN_COMMIT_STATE,
                    committed_at=now,
                    error_message="Simulated consensus timeout: commit status unknown",
                )
                self._transactions[tx_id] = receipt
                return receipt

            # Simulate explicit ledger rejection if requested
            if self.simulate_rejection:
                receipt = LedgerTransactionReceipt(
                    transaction_id=tx_id,
                    event_id=event.event_id,
                    status=CommitStatus.REJECTED,
                    committed_at=now,
                    error_message="Simulated validator quorum rejection",
                )
                self._transactions[tx_id] = receipt
                return receipt

            # Record commitment
            event_with_tx = signed_event.with_transaction_id(tx_id)
            self._events[eid] = event_with_tx
            self._session_ids.add(sid)
            self._watermark_ids.add(wmid)
            self._doc_session_pairs.add(doc_ses_pair)
            self._watermark_to_event[wmid] = eid

            receipt = LedgerTransactionReceipt(
                transaction_id=tx_id,
                event_id=event.event_id,
                status=CommitStatus.COMMITTED,
                committed_at=now,
                block_height=len(self._events),
                error_message=None,
            )
            self._transactions[tx_id] = receipt
            return receipt

    def check_duplicate(self, event_id: EventID | str) -> bool:
        """Check whether an EventID has already been registered."""
        with self._lock:
            return str(event_id) in self._events

    def check_session(self, session_id: SessionID | str) -> bool:
        """Check whether a SessionID has already been registered."""
        with self._lock:
            return str(session_id) in self._session_ids

    def check_watermark(self, watermark_id: WatermarkID | str) -> bool:
        """Check whether a WatermarkID has already been registered."""
        with self._lock:
            return str(watermark_id) in self._watermark_ids

    def get_commit_status(self, transaction_id: str) -> CommitStatus:
        """Query transaction status by transaction ID."""
        with self._lock:
            rcpt = self._transactions.get(transaction_id)
            if rcpt is None:
                return CommitStatus.UNKNOWN_COMMIT_STATE
            return rcpt.status

    def get_event(self, event_id: EventID | str) -> Optional[SignedDecryptionEvent]:
        """Retrieve committed signed event by EventID."""
        with self._lock:
            return self._events.get(str(event_id))

    def lookup_by_watermark(self, watermark_id: WatermarkID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve committed signed event by WatermarkID."""
        with self._lock:
            eid = self._watermark_to_event.get(str(watermark_id))
            if eid is None:
                return None
            return self._events.get(eid)

    def count_events(self) -> int:
        """Return total number of committed events."""
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        """Reset the in-memory adapter state (test helper)."""
        with self._lock:
            self._events.clear()
            self._transactions.clear()
            self._session_ids.clear()
            self._watermark_ids.clear()
            self._doc_session_pairs.clear()
            self._watermark_to_event.clear()
