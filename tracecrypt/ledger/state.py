"""Deterministic Logical State Machine and State Root commitments for TraceCrypt BFT Ledger.

Implements:
- Authoritative state indexes:
  - event_id -> SignedDecryptionEvent
  - session_id -> EventID
  - watermark_id -> EventID
  - transaction_id -> EventID
- Deterministic State Root computation via domain-separated Merkle commitments
- Validate-before-mutate state transitions:
  - apply_transaction()
  - apply_block()
- Strict anti-replay verification across EventID, SessionID, WatermarkID, and TransactionID
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from tracecrypt.errors import ReplayAttackError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.block import Block, LedgerTransaction
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.utils.identifiers import EventID, SessionID, TransactionID, WatermarkID


DOMAIN_STATE_ENTRY = b"tracecrypt:state:entry:"


class LedgerState:
    """In-memory authoritative state of the distributed ledger.

    Guarantees deterministic state-root computation and strictly validated state transitions.
    """

    def __init__(
        self,
        chain_id: str,
        initial_state_root: str = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    ) -> None:
        self.chain_id = chain_id
        self.height: int = 0
        self.last_block_hash: str = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000"
        self.state_root: str = initial_state_root

        # State storage indexes
        self._events: Dict[EventID, SignedDecryptionEvent] = {}
        self._sessions: Dict[SessionID, EventID] = {}
        self._watermarks: Dict[WatermarkID, EventID] = {}
        self._transactions: Dict[TransactionID, LedgerTransaction] = {}
        self._tx_by_event: Dict[EventID, TransactionID] = {}

    def clone(self) -> LedgerState:
        """Create an exact deep copy of current state for speculative execution."""
        cloned = LedgerState(self.chain_id, self.state_root)
        cloned.height = self.height
        cloned.last_block_hash = self.last_block_hash
        cloned._events = dict(self._events)
        cloned._sessions = dict(self._sessions)
        cloned._watermarks = dict(self._watermarks)
        cloned._transactions = dict(self._transactions)
        cloned._tx_by_event = dict(self._tx_by_event)
        return cloned

    # -------------------------------------------------------------------------
    # State Inspection
    # -------------------------------------------------------------------------

    def has_transaction(self, tx_id: TransactionID | str) -> bool:
        """Check whether transaction ID is committed."""
        return TransactionID(str(tx_id)) in self._transactions

    def has_event(self, event_id: EventID | str) -> bool:
        """Check whether EventID is committed."""
        return EventID(str(event_id)) in self._events

    def has_session(self, session_id: SessionID | str) -> bool:
        """Check whether SessionID is committed."""
        return SessionID(str(session_id)) in self._sessions

    def has_watermark(self, watermark_id: WatermarkID | str) -> bool:
        """Check whether WatermarkID is committed."""
        return WatermarkID(str(watermark_id)) in self._watermarks

    def get_event(self, event_id: EventID | str) -> Optional[SignedDecryptionEvent]:
        """Lookup signed event by EventID."""
        return self._events.get(EventID(str(event_id)))

    def get_by_session(self, session_id: SessionID | str) -> Optional[SignedDecryptionEvent]:
        """Lookup signed event by SessionID."""
        eid = self._sessions.get(SessionID(str(session_id)))
        return self._events.get(eid) if eid else None

    def get_by_watermark(self, watermark_id: WatermarkID | str) -> Optional[SignedDecryptionEvent]:
        """Lookup signed event by WatermarkID."""
        eid = self._watermarks.get(WatermarkID(str(watermark_id)))
        return self._events.get(eid) if eid else None

    def get_transaction(self, tx_id: TransactionID | str) -> Optional[LedgerTransaction]:
        """Lookup transaction by TransactionID."""
        return self._transactions.get(TransactionID(str(tx_id)))

    def get_transaction_for_event(self, event_id: EventID | str) -> Optional[LedgerTransaction]:
        """Lookup transaction by EventID."""
        tx_id = self._tx_by_event.get(EventID(str(event_id)))
        return self._transactions.get(tx_id) if tx_id else None

    # -------------------------------------------------------------------------
    # State Root Calculation
    # -------------------------------------------------------------------------

    def compute_state_root(self) -> str:
        """Compute deterministic SHA3-256 Merkle state root across canonical logical state entries.

        Guarantees that identical committed events, sessions, watermarks, and transactions
        produce the exact same state root regardless of insertion order, SQLite layout,
        or physical memory organization.
        """
        entries: List[bytes] = []

        # 1. Canonical Event entries: "evt:<event_id>" -> event_digest
        for eid in sorted(self._events.keys()):
            signed_evt = self._events[eid]
            entry_dict = {
                "key": f"evt:{eid}",
                "value": signed_evt.event_digest,
            }
            entries.append(DOMAIN_STATE_ENTRY + canonicalize(entry_dict))

        # 2. Canonical Session entries: "ses:<session_id>" -> event_id
        for ses in sorted(self._sessions.keys()):
            entry_dict = {
                "key": f"ses:{ses}",
                "value": str(self._sessions[ses]),
            }
            entries.append(DOMAIN_STATE_ENTRY + canonicalize(entry_dict))

        # 3. Canonical Watermark entries: "wm:<watermark_id>" -> event_id
        for wm in sorted(self._watermarks.keys()):
            entry_dict = {
                "key": f"wm:{wm}",
                "value": str(self._watermarks[wm]),
            }
            entries.append(DOMAIN_STATE_ENTRY + canonicalize(entry_dict))

        # 4. Canonical Transaction entries: "tx:<tx_id>" -> event_id
        for tx in sorted(self._transactions.keys()):
            entry_dict = {
                "key": f"tx:{tx}",
                "value": str(self._transactions[tx].event_id),
            }
            entries.append(DOMAIN_STATE_ENTRY + canonicalize(entry_dict))

        if not entries:
            # Empty state commitment
            prefix = b"tracecrypt:state:empty"
            return f"sha3-256:{hashlib.sha3_256(prefix).hexdigest()}"

        return MerkleTree.build_merkle_root(entries)

    # -------------------------------------------------------------------------
    # State Transitions (Validate-Before-Mutate)
    # -------------------------------------------------------------------------

    def validate_transaction(self, tx: LedgerTransaction) -> None:
        """Validate transaction against current state. Raises on duplicate or invalid state."""
        tx_id = tx.transaction_id
        event = tx.signed_event.event

        if tx_id in self._transactions:
            raise ReplayAttackError(f"Replay rejected: TransactionID '{tx_id}' already committed.")

        if event.event_id in self._events:
            raise ReplayAttackError(f"Replay rejected: EventID '{event.event_id}' already committed.")

        if event.session_id in self._sessions:
            raise ReplayAttackError(f"Replay rejected: SessionID '{event.session_id}' already committed.")

        if event.watermark_id in self._watermarks:
            raise ReplayAttackError(f"Replay rejected: WatermarkID '{event.watermark_id}' already committed.")

    def apply_transaction(self, tx: LedgerTransaction) -> None:
        """Apply a single transaction to the state after strict validation."""
        self.validate_transaction(tx)

        tx_id = tx.transaction_id
        event = tx.signed_event.event

        self._transactions[tx_id] = tx
        self._events[event.event_id] = tx.signed_event
        self._sessions[event.session_id] = event.event_id
        self._watermarks[event.watermark_id] = event.event_id
        self._tx_by_event[event.event_id] = tx_id

    def apply_block(self, block: Block) -> str:
        """Apply all transactions in a block and update chain state.

        Returns:
            Computed state_root
        """
        # Speculatively apply transactions to clone
        working_state = self.clone()
        for tx in block.transactions:
            working_state.apply_transaction(tx)

        computed_state_root = working_state.compute_state_root()

        # Commit to real state
        self._events = working_state._events
        self._sessions = working_state._sessions
        self._watermarks = working_state._watermarks
        self._transactions = working_state._transactions
        self._tx_by_event = working_state._tx_by_event
        self.height = block.header.height
        self.last_block_hash = block.header.block_hash
        self.state_root = computed_state_root

        return self.state_root
