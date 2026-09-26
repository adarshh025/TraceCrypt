"""Ledger abstraction interface for signed decryption event submission and state queries.

Defines the DecryptionEventLedger protocol. In Phase 5, this interface decouples
the recipient attribution pipeline from the underlying consensus mechanism.
The production BFT distributed ledger implementation will fulfill this interface in Phase 6.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.utils.identifiers import EventID, SessionID, WatermarkID


@runtime_checkable
class DecryptionEventLedger(Protocol):
    """Protocol for interacting with the TraceCrypt ledger."""

    def submit_event(self, signed_event: SignedDecryptionEvent) -> LedgerTransactionReceipt:
        """Submit a signed decryption event for ledger inclusion and commitment.

        Raises:
            ReplayAttackError: If duplicate EventID, SessionID, or WatermarkID is detected.
            LedgerError: If ledger submission or transport fails.
        """
        ...

    def check_duplicate(self, event_id: EventID | str) -> bool:
        """Check whether an EventID has already been registered on the ledger."""
        ...

    def check_session(self, session_id: SessionID | str) -> bool:
        """Check whether a SessionID has already been registered on the ledger."""
        ...

    def check_watermark(self, watermark_id: WatermarkID | str) -> bool:
        """Check whether a WatermarkID has already been registered on the ledger."""
        ...

    def get_commit_status(self, transaction_id: str) -> CommitStatus:
        """Query the current commit/finality status of a transaction."""
        ...

    def get_event(self, event_id: EventID | str) -> Optional[SignedDecryptionEvent]:
        """Retrieve a committed signed event by its EventID."""
        ...

    def lookup_by_watermark(self, watermark_id: WatermarkID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve a signed event by its embedded WatermarkID."""
        ...
