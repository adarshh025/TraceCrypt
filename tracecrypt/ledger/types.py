"""Type definitions and models for the TraceCrypt Ledger subsystem."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.utils.identifiers import EventID


class CommitStatus(str, Enum):
    """Transaction finality status on the distributed ledger."""
    COMMITTED = "COMMITTED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"
    UNKNOWN_COMMIT_STATE = "UNKNOWN_COMMIT_STATE"


class LedgerTransactionReceipt(BaseModel):
    """Receipt returned upon submitting a signed event to the ledger interface."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str = Field(description="Unique ledger transaction identifier, e.g. tx-...")
    event_id: EventID = Field(description="Identifier of the submitted DecryptionEvent")
    status: CommitStatus = Field(description="Commit/finality status of the transaction")
    committed_at: int = Field(description="POSIX microsecond UTC timestamp of commit or receipt generation")
    block_height: Optional[int] = Field(default=None, description="Committed block height (Phase 6)")
    error_message: Optional[str] = Field(default=None, description="Diagnostic error message if rejected")

    @property
    def is_committed(self) -> bool:
        """True if the transaction has achieved final commitment."""
        return self.status == CommitStatus.COMMITTED
