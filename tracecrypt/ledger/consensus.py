"""Deterministic Byzantine Fault Tolerant (BFT) Consensus State Machine for TraceCrypt.

Inspired by the Tendermint / CometBFT safety and finality specification:
- Height -> Round -> PROPOSE -> PREVOTE -> PRECOMMIT -> COMMIT
- 2f + 1 Quorum-based voting and locking rules
- Cryptographic proof of equivocation (ByzantineEvidence)
- Generic quorum verification across arbitrary validator sets
- Deterministic proposer selection and round-robin view change
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from tracecrypt.crypto.types import MLDSAPrivateKey
from tracecrypt.errors import (
    BlockValidationError,
    ByzantineFaultDetected,
    ConsensusError,
    QuorumNotReachedError,
)
from tracecrypt.ledger.block import Block, BlockHeader
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import (
    ByzantineEvidence,
    CommitCertificate,
    VoteMessage,
    VoteType,
)
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.validator import NodeRole, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros

logger = logging.getLogger("tracecrypt.ledger.consensus")


class ConsensusStep(str, Enum):
    """Phases within a consensus round."""
    PROPOSE = "PROPOSE"
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"
    COMMIT = "COMMIT"


class ConsensusEngine:
    """Core BFT Consensus state machine for a validator node."""

    def __init__(
        self,
        validator_id: ValidatorID,
        private_key: MLDSAPrivateKey,
        validator_set: ValidatorSet,
        chain_id: str,
        state: LedgerState,
        mempool: Mempool,
        on_block_committed: Optional[Callable[[Block], None]] = None,
    ) -> None:
        self.validator_id = validator_id
        self._private_key = private_key
        self.validator_set = validator_set
        self.chain_id = chain_id
        self.state = state
        self.mempool = mempool
        self.on_block_committed = on_block_committed

        # Consensus state
        self.height: int = state.height + 1
        self.round: int = 0
        self.step: ConsensusStep = ConsensusStep.PROPOSE

        # Locking variables (prevents safety violations across rounds)
        self.locked_round: int = -1
        self.locked_block: Optional[Block] = None
        self.valid_round: int = -1
        self.valid_block: Optional[Block] = None

        # Proposal for current height & round
        self.current_proposal: Optional[Block] = None

        # Vote storage: (height, round, vote_type) -> validator_id -> VoteMessage
        self._votes: Dict[Tuple[int, int, VoteType], Dict[ValidatorID, VoteMessage]] = {}

        # Byzantine evidence log: evidence_hash -> ByzantineEvidence
        self.evidence_log: Dict[str, ByzantineEvidence] = {}

    @property
    def is_validator(self) -> bool:
        """True if this node is an authorized consensus validator."""
        return self.validator_set.is_validator(self.validator_id)

    # -------------------------------------------------------------------------
    # Vote Management & Byzantine Equivocation Defense
    # -------------------------------------------------------------------------

    def get_votes_for(
        self,
        height: int,
        round_idx: int,
        vote_type: VoteType,
    ) -> Dict[ValidatorID, VoteMessage]:
        """Retrieve all recorded votes for given height, round, and phase."""
        key = (height, round_idx, vote_type)
        return self._votes.setdefault(key, {})

    def add_vote(self, vote: VoteMessage) -> bool:
        """Process, validate, and record an incoming validator vote.

        Enforces:
        - Chain ID match
        - Height and round bounds
        - Validator membership in active validator set
        - Cryptographic signature validity
        - Strict equivocation detection (conflicting votes trigger ByzantineEvidence)

        Returns:
            True if vote was successfully accepted and recorded
        """
        if vote.chain_id != self.chain_id:
            logger.warning("Rejected vote with mismatched chain_id: %s", vote.chain_id)
            return False

        if vote.height != self.height:
            logger.debug("Ignored vote for height %d while at height %d", vote.height, self.height)
            return False

        val_info = self.validator_set.get_validator(vote.validator_id)
        if val_info is None or val_info.role != NodeRole.VALIDATOR:
            logger.warning("Rejected vote from non-validator: %s", vote.validator_id)
            return False

        # Verify signature
        if not vote.verify_signature(val_info.get_public_key()):
            logger.warning("Rejected vote with invalid signature from %s", vote.validator_id)
            return False

        key = (vote.height, vote.round, vote.vote_type)
        bucket = self._votes.setdefault(key, {})

        if vote.validator_id in bucket:
            existing = bucket[vote.validator_id]
            if existing.block_hash != vote.block_hash:
                # Cryptographically provable equivocation detected!
                evidence = ByzantineEvidence.create(existing, vote)
                self.evidence_log[evidence.evidence_hash] = evidence
                logger.critical(
                    "BYZANTINE EQUIVOCATION DETECTED from validator %s at height %d, round %d! "
                    "Evidence hash: %s",
                    vote.validator_id,
                    vote.height,
                    vote.round,
                    evidence.evidence_hash,
                )
                msg = f"Validator '{vote.validator_id}' equivocated at height {vote.height}, round {vote.round}"
                raise ByzantineFaultDetected(msg)
            # Duplicate identical vote: idempotent ignore
            return True

        bucket[vote.validator_id] = vote
        return True

    def count_votes_for_block(
        self,
        height: int,
        round_idx: int,
        vote_type: VoteType,
        block_hash: Optional[str],
    ) -> Tuple[int, List[VoteMessage]]:
        """Calculate total voting power supporting a specific block_hash (or NIL)."""
        votes_map = self.get_votes_for(height, round_idx, vote_type)
        matching_votes: List[VoteMessage] = []
        power = 0

        for vid, vote in votes_map.items():
            if vote.block_hash == block_hash:
                v_info = self.validator_set.get_validator(vid)
                if v_info is not None:
                    power += v_info.voting_power
                    matching_votes.append(vote)

        return power, matching_votes

    # -------------------------------------------------------------------------
    # Consensus Round Progression (Propose -> Prevote -> Precommit -> Commit)
    # -------------------------------------------------------------------------

    def create_proposal(self) -> Block:
        """Construct a valid Block proposal from current mempool and state."""
        proposer_id = self.validator_set.get_proposer(self.height, self.round)
        if proposer_id != self.validator_id:
            err = (
                f"Node {self.validator_id} is not the designated proposer for height {self.height}, "
                f"round {self.round}. Expected: {proposer_id}"
            )
            raise ConsensusError(err)

        txs = self.mempool.get_ordered_transactions()
        tx_bytes = [tx.to_canonical_bytes() for tx in txs]
        tx_root = MerkleTree.build_merkle_root(tx_bytes)

        # Speculatively apply transactions to compute state_root
        speculative_state = self.state.clone()
        for tx in txs:
            try:
                speculative_state.apply_transaction(tx)
            except Exception as e:
                logger.warning("Excluded invalid tx %s from proposal: %s", tx.transaction_id, e)

        state_root = speculative_state.compute_state_root()

        now = utc_now_micros()
        header_proto = BlockHeader(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            previous_block_hash=self.state.last_block_hash,
            timestamp=now,
            proposer_id=self.validator_id,
            transaction_root=tx_root,
            state_root=state_root,
            validator_set_hash=self.validator_set.compute_hash(),
            protocol_version="1.0.0",
            block_hash="",
        )
        block_hash = header_proto.compute_block_hash()
        header = header_proto.model_copy(update={"block_hash": block_hash})

        block = Block(
            header=header,
            transactions=txs,
            commit_certificate=None,
        )
        self.current_proposal = block
        return block

    def receive_proposal(self, block: Block) -> bool:
        """Validate and record an incoming proposed block.

        Validates:
        - Designated proposer authority
        - Structural integrity & Merkle root
        - State root match against local execution
        - Chain continuity (previous_block_hash)
        """
        header = block.header
        if header.chain_id != self.chain_id or header.height != self.height or header.round != self.round:
            return False

        expected_proposer = self.validator_set.get_proposer(self.height, self.round)
        if header.proposer_id != expected_proposer:
            logger.warning(
                "Proposal rejected: proposer %s != expected %s",
                header.proposer_id,
                expected_proposer,
            )
            return False

        if header.previous_block_hash != self.state.last_block_hash:
            logger.warning(
                "Proposal rejected: previous_block_hash %s != local %s",
                header.previous_block_hash,
                self.state.last_block_hash,
            )
            return False

        try:
            block.validate_structural_integrity()
        except BlockValidationError as e:
            logger.warning("Proposal rejected due to structural validation failure: %s", e)
            return False

        # Validate state transitions
        speculative_state = self.state.clone()
        for tx in block.transactions:
            try:
                speculative_state.validate_transaction(tx)
                speculative_state.apply_transaction(tx)
            except Exception as e:
                logger.warning("Proposal rejected due to invalid transaction %s: %s", tx.transaction_id, e)
                return False

        computed_state_root = speculative_state.compute_state_root()
        if header.state_root != computed_state_root:
            logger.warning(
                "Proposal rejected: state_root mismatch. Block claims '%s', recomputed '%s'",
                header.state_root,
                computed_state_root,
            )
            return False

        self.current_proposal = block
        return True

    def prevote(self) -> Optional[VoteMessage]:
        """Generate and record local PREVOTE vote.

        Voting rule:
        - If proposal is valid and (not locked or locked_block matches proposal):
            Vote for proposal's block_hash
        - Otherwise:
            Vote for NIL (None)
        """
        if not self.is_validator:
            return None

        target_hash: Optional[str] = None

        if self.current_proposal is not None:
            prop_hash = self.current_proposal.header.block_hash
            if self.locked_block is None or self.locked_block.header.block_hash == prop_hash:
                target_hash = prop_hash

        now = utc_now_micros()
        vote = VoteMessage.create_and_sign(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            vote_type=VoteType.PREVOTE,
            block_hash=target_hash,
            validator_id=self.validator_id,
            signing_key=self._private_key,
            timestamp=now,
        )

        self.add_vote(vote)
        self.step = ConsensusStep.PREVOTE
        return vote

    def check_prevote_quorum(self) -> Tuple[bool, Optional[str]]:
        """Evaluate if any block_hash (or NIL) reached 2f + 1 Prevotes.

        If a block reaches quorum, the validator locks on that block.
        """
        votes_map = self.get_votes_for(self.height, self.round, VoteType.PREVOTE)
        # Check all distinct block hashes voted for
        hashes_seen = {v.block_hash for v in votes_map.values()}

        for b_hash in hashes_seen:
            power, matching = self.count_votes_for_block(
                self.height, self.round, VoteType.PREVOTE, b_hash
            )
            if self.validator_set.has_quorum(power):
                if b_hash is not None and self.current_proposal is not None:
                    if self.current_proposal.header.block_hash == b_hash:
                        # Lock on this proposal
                        self.locked_round = self.round
                        self.locked_block = self.current_proposal
                        self.valid_round = self.round
                        self.valid_block = self.current_proposal
                return True, b_hash

        return False, None

    def precommit(self) -> Optional[VoteMessage]:
        """Generate and record local PRECOMMIT vote.

        Voting rule:
        - If locked on a block that received 2f + 1 Prevotes in this round:
            Vote for locked_block.block_hash
        - Otherwise:
            Vote for NIL (None)
        """
        if not self.is_validator:
            return None

        target_hash: Optional[str] = None
        has_quorum, q_hash = self.check_prevote_quorum()

        if has_quorum and q_hash is not None:
            if self.locked_block is not None and self.locked_block.header.block_hash == q_hash:
                target_hash = q_hash

        now = utc_now_micros()
        vote = VoteMessage.create_and_sign(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            vote_type=VoteType.PRECOMMIT,
            block_hash=target_hash,
            validator_id=self.validator_id,
            signing_key=self._private_key,
            timestamp=now,
        )

        self.add_vote(vote)
        self.step = ConsensusStep.PRECOMMIT
        return vote

    def check_precommit_quorum(self) -> Tuple[bool, Optional[CommitCertificate]]:
        """Evaluate if any block achieved 2f + 1 Precommits, finalizing the block."""
        votes_map = self.get_votes_for(self.height, self.round, VoteType.PRECOMMIT)
        hashes_seen = {v.block_hash for v in votes_map.values() if v.block_hash is not None}

        for b_hash in hashes_seen:
            power, matching_votes = self.count_votes_for_block(
                self.height, self.round, VoteType.PRECOMMIT, b_hash
            )
            if self.validator_set.has_quorum(power):
                cert = CommitCertificate(
                    chain_id=self.chain_id,
                    height=self.height,
                    round=self.round,
                    block_hash=b_hash,
                    votes=matching_votes,
                    validator_set_hash=self.validator_set.compute_hash(),
                )
                return True, cert

        return False, None

    def commit_block(self, certificate: CommitCertificate) -> Optional[Block]:
        """Finalize the committed block, execute state transition, and advance height."""
        target_block = self.current_proposal or self.locked_block
        if target_block is None or target_block.header.block_hash != certificate.block_hash:
            logger.error(
                "Cannot commit block: block with hash %s not locally available.",
                certificate.block_hash,
            )
            return None

        # Verify certificate
        if not certificate.verify_certificate(self.validator_set, target_block.header.block_hash):
            raise QuorumNotReachedError("Commit certificate failed cryptographic quorum verification.")

        finalized_block = target_block.model_copy(update={"commit_certificate": certificate})

        # Apply state transition
        self.state.apply_block(finalized_block)

        # Evict transactions from mempool
        self.mempool.remove_committed(finalized_block.transactions)

        # Notify callback (e.g. database persistence)
        if self.on_block_committed is not None:
            self.on_block_committed(finalized_block)

        # Advance consensus state to next height
        self.height += 1
        self.round = 0
        self.step = ConsensusStep.PROPOSE
        self.locked_round = -1
        self.locked_block = None
        self.valid_round = -1
        self.valid_block = None
        self.current_proposal = None

        logger.info(
            "COMMITTED Block %d (hash: %s) with %d transactions.",
            finalized_block.header.height,
            finalized_block.header.block_hash,
            len(finalized_block.transactions),
        )
        return finalized_block

    def advance_round(self) -> int:
        """Execute deterministic round/view change when proposal or votes timeout."""
        self.round += 1
        self.step = ConsensusStep.PROPOSE
        self.current_proposal = None
        logger.info(
            "Advanced to Round %d at Height %d. New proposer: %s",
            self.round,
            self.height,
            self.validator_set.get_proposer(self.height, self.round),
        )
        return self.round
