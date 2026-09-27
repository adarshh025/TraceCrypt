"""State Synchronization and Catch-Up Protocol for TraceCrypt BFT Ledger.

Implements:
- StateSyncRequest and StateSyncResponse message schemas
- SyncManager: handles catching up a node behind the consensus tip
- Independent cryptographic verification before accepting any synchronized blocks:
  - CommitCertificate quorum verification
  - Structural and Merkle transaction root verification
  - State transition and state root recomputation
  - Parent hash continuity
"""

from __future__ import annotations

import logging
from typing import List
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.errors import BlockValidationError, StateSyncError
from tracecrypt.ledger.block import Block
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import ValidatorSet

logger = logging.getLogger("tracecrypt.ledger.sync")


class StateSyncRequest(BaseModel):
    """Request sent by a lagging node to obtain missing finalized blocks."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Chain ID")
    start_height: int = Field(ge=1, description="First missing block height requested")
    max_blocks: int = Field(default=50, ge=1, le=500, description="Maximum blocks to return in batch")
    requester_id: str = Field(description="Identifier of requesting node")


class StateSyncResponse(BaseModel):
    """Response containing sequential finalized blocks and latest chain height."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Chain ID")
    start_height: int = Field(ge=1, description="First block height in this batch")
    blocks: List[Block] = Field(description="Sequential finalized blocks with CommitCertificates")
    latest_height: int = Field(ge=0, description="Highest committed block height known to responder")
    responder_id: str = Field(description="Identifier of responding node")


class SyncManager:
    """Manages node catch-up and cryptographic synchronization."""

    def __init__(
        self,
        storage: LedgerStorage,
        state: LedgerState,
        validator_set: ValidatorSet,
        chain_id: str,
        node_id: str,
    ) -> None:
        self.storage = storage
        self.state = state
        self.validator_set = validator_set
        self.chain_id = chain_id
        self.node_id = node_id

    def create_sync_request(self, max_blocks: int = 50) -> StateSyncRequest:
        """Create a request for the next missing block height."""
        current_height = self.storage.get_latest_height()
        return StateSyncRequest(
            chain_id=self.chain_id,
            start_height=current_height + 1,
            max_blocks=max_blocks,
            requester_id=self.node_id,
        )

    def handle_sync_request(self, request: StateSyncRequest) -> StateSyncResponse:
        """Serve missing blocks to a requesting peer."""
        if request.chain_id != self.chain_id:
            raise StateSyncError(f"Mismatched chain_id in sync request: {request.chain_id} != {self.chain_id}")

        blocks = self.storage.get_blocks(start_height=request.start_height, limit=request.max_blocks)
        latest_height = self.storage.get_latest_height()

        return StateSyncResponse(
            chain_id=self.chain_id,
            start_height=request.start_height,
            blocks=blocks,
            latest_height=latest_height,
            responder_id=self.node_id,
        )

    def apply_sync_response(self, response: StateSyncResponse) -> int:
        """Independently verify and commit synchronized blocks.

        Never trusts the sender's assertion of block validity.
        Verifies commit certificates, Merkle roots, and re-executes state transitions locally.
        """
        if response.chain_id != self.chain_id:
            raise StateSyncError(f"Mismatched chain_id in sync response: {response.chain_id} != {self.chain_id}")

        if not response.blocks:
            return 0

        applied_count = 0
        current_height = self.storage.get_latest_height()

        for block in response.blocks:
            header = block.header
            expected_height = current_height + 1

            if header.height != expected_height:
                raise StateSyncError(
                    f"Sync error: received block {header.height} out of sequence (expected {expected_height})."
                )

            # 1. Verify parent hash link
            if header.previous_block_hash != self.state.last_block_hash:
                raise StateSyncError(
                    f"Sync error at height {header.height}: previous_block_hash mismatch. "
                    f"Expected '{self.state.last_block_hash}', got '{header.previous_block_hash}'"
                )

            # 2. Structural & Merkle integrity
            try:
                block.validate_structural_integrity()
            except BlockValidationError as e:
                raise StateSyncError(f"Sync error at height {header.height}: block integrity invalid: {e}")

            # 3. Commit certificate verification with quorum
            if block.commit_certificate is None:
                err = f"Sync error at height {header.height}: synchronized block lacks commit certificate."
                raise StateSyncError(err)

            if not block.commit_certificate.verify_certificate(self.validator_set, header.block_hash):
                err = f"Sync error at height {header.height}: commit certificate failed quorum verification."
                raise StateSyncError(err)

            # 4. State transition recomputation
            computed_state_root = self.state.apply_block(block)
            if header.state_root != computed_state_root:
                raise StateSyncError(
                    f"Sync error at height {header.height}: state_root mismatch. "
                    f"Block claims '{header.state_root}', recomputed '{computed_state_root}'"
                )

            # 5. Persist to storage
            self.storage.save_block(block)
            current_height = header.height
            applied_count += 1

        logger.info(
            "Successfully synchronized and applied %d blocks (tip at height %d).",
            applied_count,
            current_height,
        )
        return applied_count
