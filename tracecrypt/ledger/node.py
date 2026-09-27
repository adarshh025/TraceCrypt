"""Comprehensive BFT Ledger Validator & Observer Node for TraceCrypt.

Integrates:
- ConsensusEngine (Propose -> Prevote -> Precommit -> Commit)
- LedgerState (Logical state transitions, state-root Merkle commitment)
- LedgerStorage (SQLite WAL persistence, chain verification, Merkle proofs)
- Mempool (Deterministic ordering, anti-replay deduplication)
- P2PNetwork (Air-gapped LAN message passing)
- SyncManager (Catch-up protocol)
- Fulfills the DecryptionEventLedger protocol required by Phase 5
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tracecrypt.crypto.types import MLDSAPrivateKey
from tracecrypt.errors import (
    ReplayAttackError,
    SecurityError,
    ValidationError,
)
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.block import Block, LedgerTransaction
from tracecrypt.ledger.consensus import ConsensusEngine
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.interface import DecryptionEventLedger
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.messages import VoteMessage
from tracecrypt.ledger.network import P2PNetwork
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.sync import StateSyncRequest, SyncManager
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.ledger.validator import NodeRole
from tracecrypt.utils.identifiers import EventID, SessionID, TransactionID, ValidatorID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros

logger = logging.getLogger("tracecrypt.ledger.node")


class BFTLedgerNode(DecryptionEventLedger):
    """Production-grade offline BFT ledger node (Validator or Observer)."""

    def __init__(
        self,
        validator_id: ValidatorID,
        private_key: MLDSAPrivateKey,
        genesis: GenesisConfig,
        data_dir: str | Path,
        listen_host: str = "127.0.0.1",
        listen_port: int = 9101,
        peers: Optional[List[Tuple[str, int]]] = None,
        role: NodeRole = NodeRole.VALIDATOR,
    ) -> None:
        self.validator_id = validator_id
        self._private_key = private_key
        self.genesis = genesis
        self.role = role
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = self.data_dir / "ledger.db"
        self.storage = LedgerStorage(self.db_path)

        # 1. Initialize or verify genesis
        existing_genesis = self.storage.get_genesis()
        if existing_genesis is None:
            self.storage.save_genesis(genesis)
        else:
            if existing_genesis.compute_genesis_hash() != genesis.compute_genesis_hash():
                raise ValidationError("Existing database genesis hash differs from configured genesis!")

        self.validator_set = genesis.validator_set
        self.chain_id = genesis.chain_id

        # 2. Startup Chain Verification
        logger.info("Executing startup chain verification on %s...", self.db_path)
        self.storage.verify_chain(self.validator_set)

        # 3. Rebuild in-memory authoritative state from persisted storage
        self.state = LedgerState(self.chain_id, genesis.initial_state_root)
        latest_height = self.storage.get_latest_height()
        for h in range(1, latest_height + 1):
            blk = self.storage.get_block(h)
            if blk:
                self.state.apply_block(blk)

        # 4. Initialize Mempool and Consensus Engine
        self.mempool = Mempool()
        self.consensus = ConsensusEngine(
            validator_id=self.validator_id,
            private_key=self._private_key,
            validator_set=self.validator_set,
            chain_id=self.chain_id,
            state=self.state,
            mempool=self.mempool,
            on_block_committed=self._on_block_committed,
        )

        # 5. Initialize Sync Manager
        self.sync_manager = SyncManager(
            storage=self.storage,
            state=self.state,
            validator_set=self.validator_set,
            chain_id=self.chain_id,
            node_id=str(self.validator_id),
        )

        # 6. Initialize Network
        self.peers = peers or []
        self.network = P2PNetwork(
            node_id=str(self.validator_id),
            listen_host=listen_host,
            listen_port=listen_port,
            peers=self.peers,
        )
        self._setup_network_handlers()

        self._running: bool = False
        self._consensus_loop_task: Optional[asyncio.Task] = None

    def _on_block_committed(self, block: Block) -> None:
        """Callback invoked by ConsensusEngine upon finalizing a block."""
        self.storage.save_block(block)
        logger.info("Node %s persisted block %d to SQLite storage.", self.validator_id, block.header.height)

    # -------------------------------------------------------------------------
    # Network Handlers
    # -------------------------------------------------------------------------

    def _setup_network_handlers(self) -> None:
        """Configure wire message dispatching for LAN P2P messages."""
        self.network.register_handler("PROPOSAL", self._handle_network_proposal)
        self.network.register_handler("VOTE", self._handle_network_vote)
        self.network.register_handler("TX_SUBMIT", self._handle_network_tx)
        self.network.register_handler("SYNC_REQ", self._handle_network_sync_req)
        self.network.register_handler("STATUS_REQ", self._handle_network_status_req)

    async def _handle_network_proposal(self, data: Dict[str, Any], sender_id: str) -> Optional[Dict[str, Any]]:
        block = Block.model_validate(data)
        accepted = self.consensus.receive_proposal(block)
        if accepted and self.role == NodeRole.VALIDATOR:
            # Broadcast our prevote
            prevote = self.consensus.prevote()
            if prevote:
                await self.network.broadcast("VOTE", prevote.model_dump())
        return {"accepted": accepted}

    async def _handle_network_vote(self, data: Dict[str, Any], sender_id: str) -> Optional[Dict[str, Any]]:
        vote = VoteMessage.model_validate(data)
        accepted = self.consensus.add_vote(vote)
        if accepted and self.role == NodeRole.VALIDATOR:
            # Check for prevote quorum -> trigger precommit
            has_prevote_q, _ = self.consensus.check_prevote_quorum()
            if has_prevote_q and self.consensus.step == "PREVOTE":
                precommit = self.consensus.precommit()
                if precommit:
                    await self.network.broadcast("VOTE", precommit.model_dump())

            # Check for precommit quorum -> commit block
            has_precommit_q, cert = self.consensus.check_precommit_quorum()
            if has_precommit_q and cert is not None:
                self.consensus.commit_block(cert)

        return {"accepted": accepted}

    async def _handle_network_tx(self, data: Dict[str, Any], sender_id: str) -> Optional[Dict[str, Any]]:
        tx = LedgerTransaction.model_validate(data)
        try:
            self._validate_and_enqueue_tx(tx)
            return {"status": "ACCEPTED", "transaction_id": str(tx.transaction_id)}
        except Exception as e:
            return {"status": "REJECTED", "error": str(e)}

    async def _handle_network_sync_req(self, data: Dict[str, Any], sender_id: str) -> Optional[Dict[str, Any]]:
        req = StateSyncRequest.model_validate(data)
        resp = self.sync_manager.handle_sync_request(req)
        return resp.model_dump()

    async def _handle_network_status_req(self, data: Dict[str, Any], sender_id: str) -> Optional[Dict[str, Any]]:
        return self.get_status()

    # -------------------------------------------------------------------------
    # Lifecycle Management
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start P2P network and consensus engine."""
        self._running = True
        await self.network.start()
        logger.info("Node %s started in %s role.", self.validator_id, self.role.value)

    async def stop(self) -> None:
        """Gracefully stop node and flush database."""
        self._running = False
        if self._consensus_loop_task:
            self._consensus_loop_task.cancel()
        await self.network.stop()
        self.storage.close()
        logger.info("Node %s stopped.", self.validator_id)

    # -------------------------------------------------------------------------
    # Transaction Processing & DecryptionEventLedger Interface
    # -------------------------------------------------------------------------

    def _validate_and_enqueue_tx(self, tx: LedgerTransaction) -> None:
        """Enforce strict multi-layer transaction validation prior to mempool entry."""
        event = tx.signed_event.event

        # 1. Anti-replay verification against committed state and local storage
        if self.state.has_transaction(tx.transaction_id) or self.storage.has_transaction(str(tx.transaction_id)):
            raise ReplayAttackError(f"Replay rejected: TransactionID '{tx.transaction_id}' already committed.")

        if self.state.has_event(event.event_id) or self.storage.has_event(str(event.event_id)):
            raise ReplayAttackError(f"Replay rejected: EventID '{event.event_id}' already committed.")

        if self.state.has_session(event.session_id) or self.storage.has_session(str(event.session_id)):
            raise ReplayAttackError(f"Replay rejected: SessionID '{event.session_id}' already committed.")

        if self.state.has_watermark(event.watermark_id) or self.storage.has_watermark(str(event.watermark_id)):
            raise ReplayAttackError(f"Replay rejected: WatermarkID '{event.watermark_id}' already committed.")

        # 2. Check canonical event digest integrity
        expected_digest = event.compute_event_digest()
        if tx.signed_event.event_digest != expected_digest:
            raise SecurityError(
                f"Event digest mismatch: expected '{expected_digest}', got '{tx.signed_event.event_digest}'"
            )

        # 3. Cryptographic signature verification if certificate is provided
        if tx.recipient_certificate is not None:
            from tracecrypt.event.verifier import DecryptionEventVerifier
            res = DecryptionEventVerifier.verify_signed_event(
                tx.signed_event,
                recipient_certificate=tx.recipient_certificate,
            )
            if not res.is_valid:
                raise SecurityError(f"Invalid ML-DSA-65 signature on event '{event.event_id}': {res.errors}")

        # 4. Add to mempool (deduplicates against pending transactions)
        self.mempool.add_transaction(tx)

    def submit_event(
        self,
        signed_event: SignedDecryptionEvent,
        recipient_certificate: Optional[Any] = None,
    ) -> LedgerTransactionReceipt:
        """Submit a signed decryption event to the ledger (implements DecryptionEventLedger)."""
        event = signed_event.event
        tx_id = TransactionID.generate()
        now = utc_now_micros()

        tx = LedgerTransaction.from_signed_event(
            transaction_id=tx_id,
            signed_event=signed_event,
            submitted_at=now,
            recipient_certificate=recipient_certificate,
        )

        # Enforces ReplayAttackError raising on duplicate
        self._validate_and_enqueue_tx(tx)

        return LedgerTransactionReceipt(
            transaction_id=str(tx_id),
            event_id=event.event_id,
            status=CommitStatus.PENDING,
            committed_at=now,
        )

    def check_duplicate(self, event_id: EventID | str) -> bool:
        """Check whether an EventID has already been registered in state or storage."""
        eid_str = str(event_id)
        return self.state.has_event(eid_str) or self.storage.has_event(eid_str) or self.mempool.has_event(eid_str)

    def check_session(self, session_id: SessionID | str) -> bool:
        """Check whether a SessionID has already been registered."""
        sid_str = str(session_id)
        return (
            self.state.has_session(sid_str)
            or self.storage.has_session(sid_str)
            or self.mempool.has_session(sid_str)
        )

    def check_watermark(self, watermark_id: WatermarkID | str) -> bool:
        """Check whether a WatermarkID has already been registered."""
        wid_str = str(watermark_id)
        return (
            self.state.has_watermark(wid_str)
            or self.storage.has_watermark(wid_str)
            or self.mempool.has_watermark(wid_str)
        )

    def get_commit_status(self, transaction_id: str) -> CommitStatus:
        """Query transaction finality status."""
        if self.storage.has_transaction(transaction_id) or self.state.has_transaction(transaction_id):
            return CommitStatus.COMMITTED
        if self.mempool.has_transaction(transaction_id):
            return CommitStatus.PENDING
        return CommitStatus.UNKNOWN_COMMIT_STATE

    def get_event(self, event_id: EventID | str) -> Optional[SignedDecryptionEvent]:
        """Retrieve a committed signed event by EventID."""
        evt = self.state.get_event(event_id)
        if evt:
            return evt
        return self.storage.get_event(event_id)

    def lookup_by_watermark(self, watermark_id: WatermarkID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve committed signed event by WatermarkID."""
        evt = self.state.get_by_watermark(watermark_id)
        if evt:
            return evt
        return self.storage.lookup_by_watermark(watermark_id)

    def lookup_by_session(self, session_id: SessionID | str) -> Optional[SignedDecryptionEvent]:
        """Forensic lookup: retrieve committed signed event by SessionID."""
        evt = self.state.get_by_session(session_id)
        if evt:
            return evt
        return self.storage.lookup_by_session(session_id)

    # -------------------------------------------------------------------------
    # Consensus Round Step Execution (Multi-Node / Simulation / Test API)
    # -------------------------------------------------------------------------

    def step_consensus_round(self, peer_nodes: Optional[List[BFTLedgerNode]] = None) -> Optional[Block]:
        """Execute one complete deterministic consensus round across this node (and optional peers).

        Ideal for deterministic synchronous testing and benchmarking.
        """
        all_nodes = [self] + (peer_nodes or [])
        online_ids = {n.validator_id for n in all_nodes}

        # 0. Align round index across all participating nodes to max round seen
        max_round = max(n.consensus.round for n in all_nodes)
        for n in all_nodes:
            while n.consensus.round < max_round:
                n.consensus.advance_round()

        # 1. Proposer Selection & Round Advancement if Proposer is Offline
        max_round_attempts = len(self.validator_set.validators) * 2
        attempts = 0
        while attempts < max_round_attempts:
            proposer_id = self.validator_set.get_proposer(self.consensus.height, self.consensus.round)
            if proposer_id in online_ids:
                break
            # Designated proposer is offline: advance round across all active nodes
            logger.info("Designated proposer %s is offline. Advancing round...", proposer_id)
            for n in all_nodes:
                n.consensus.advance_round()
            attempts += 1

        # Distribute pending transactions across all participating nodes' mempools
        all_txs = []
        for n in all_nodes:
            all_txs.extend(n.mempool.get_ordered_transactions())
        for n in all_nodes:
            for tx in all_txs:
                if not n.mempool.has_transaction(tx.transaction_id) and not n.state.has_transaction(tx.transaction_id):
                    try:
                        n.mempool.add_transaction(tx)
                    except Exception:
                        pass

        proposer_node = next((n for n in all_nodes if n.validator_id == proposer_id), self)
        proposal = proposer_node.consensus.create_proposal()

        # 2. Prevote
        prevotes: List[VoteMessage] = []
        for n in all_nodes:
            if n.role == NodeRole.VALIDATOR:
                n.consensus.receive_proposal(proposal)
                vote = n.consensus.prevote()
                if vote:
                    prevotes.append(vote)

        # Distribute prevotes to all nodes
        for n in all_nodes:
            for v in prevotes:
                n.consensus.add_vote(v)

        # 3. Precommit
        precommits: List[VoteMessage] = []
        for n in all_nodes:
            if n.role == NodeRole.VALIDATOR:
                vote = n.consensus.precommit()
                if vote:
                    precommits.append(vote)

        # Distribute precommits to all nodes
        for n in all_nodes:
            for v in precommits:
                n.consensus.add_vote(v)

        # 4. Commit
        finalized_block: Optional[Block] = None
        for n in all_nodes:
            has_quorum, cert = n.consensus.check_precommit_quorum()
            if has_quorum and cert is not None:
                blk = n.consensus.commit_block(cert)
                if n == self:
                    finalized_block = blk

        if finalized_block is None:
            # Round failed to commit (e.g., partition or timeout):
            # Advance round across all participating nodes to prepare for next round attempt
            for n in all_nodes:
                n.consensus.advance_round()

        return finalized_block

    # -------------------------------------------------------------------------
    # Ledger Query & Forensic Verification APIs
    # -------------------------------------------------------------------------

    def get_block(self, height: int) -> Optional[Block]:
        """Retrieve block at specified height."""
        return self.storage.get_block(height)

    def get_transaction(self, transaction_id: str) -> Optional[LedgerTransaction]:
        """Retrieve transaction by ID."""
        return self.storage.get_transaction(transaction_id)

    def get_transaction_proof(self, transaction_id: str) -> Dict[str, Any]:
        """Export standalone cryptographic Merkle inclusion proof for investigator."""
        return self.storage.export_merkle_proof(transaction_id)

    def verify_chain(self) -> bool:
        """Perform end-to-end chain verification on local storage."""
        return self.storage.verify_chain(self.validator_set)

    def get_status(self) -> Dict[str, Any]:
        """Retrieve current status of node, height, and cryptographic roots."""
        return {
            "chain_id": self.chain_id,
            "validator_id": str(self.validator_id),
            "role": self.role.value,
            "height": self.storage.get_latest_height(),
            "consensus_height": self.consensus.height,
            "consensus_round": self.consensus.round,
            "consensus_step": self.consensus.step.value,
            "last_block_hash": self.state.last_block_hash,
            "state_root": self.state.state_root,
            "mempool_size": self.mempool.size(),
            "validator_count": len(self.validator_set.validators),
            "evidence_count": len(self.storage.get_byzantine_evidence()),
        }
