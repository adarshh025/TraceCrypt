"""Block and Transaction schemas, cryptographic header commitments, and validation.

Implements:
- LedgerTransaction encapsulating SignedDecryptionEvent from Phase 5
- BlockHeader with domain-separated SHA3-256 block_hash
- Block container with transactions and CommitCertificate
- Complete structural and cryptographic integrity validation
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.errors import BlockValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import CommitCertificate
from tracecrypt.utils.identifiers import EventID, TransactionID, ValidatorID


DOMAIN_BLOCK_HEADER = b"tracecrypt:block:header:"


class LedgerTransaction(BaseModel):
    """An atomic transaction submitted to and committed by the BFT distributed ledger.

    Wraps the Phase 5 SignedDecryptionEvent proving recipient attribution.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: TransactionID = Field(description="Unique ledger transaction identifier (tx-...)")
    event_id: EventID = Field(description="Associated signed decryption event identifier (evt-...)")
    signed_event: SignedDecryptionEvent = Field(description="Underlying recipient-signed decryption event")
    submitted_at: int = Field(description="POSIX microsecond UTC timestamp of transaction submission")
    recipient_certificate: Optional[PQCIdentityCertificate] = Field(
        default=None,
        description="Certified ML-DSA-65 identity certificate of recipient (for independent verification)"
    )

    def to_canonical_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical representation."""
        cert_dict = self.recipient_certificate.model_dump() if self.recipient_certificate else None
        return {
            "event_id": str(self.event_id),
            "recipient_certificate": cert_dict,
            "signed_event": self.signed_event.model_dump(),
            "submitted_at": self.submitted_at,
            "transaction_id": str(self.transaction_id),
        }

    def to_canonical_bytes(self) -> bytes:
        """Produce deterministic RFC 8785 canonical bytes."""
        return canonicalize(self.to_canonical_dict())

    @classmethod
    def from_signed_event(
        cls,
        transaction_id: TransactionID,
        signed_event: SignedDecryptionEvent,
        submitted_at: int,
        recipient_certificate: Optional[PQCIdentityCertificate] = None,
    ) -> LedgerTransaction:
        """Construct a LedgerTransaction from a validated SignedDecryptionEvent."""
        return cls(
            transaction_id=transaction_id,
            event_id=signed_event.event.event_id,
            signed_event=signed_event,
            submitted_at=submitted_at,
            recipient_certificate=recipient_certificate,
        )


class BlockHeader(BaseModel):
    """Cryptographically sealed header committing to block state and transactions."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Chain ID binding this block to its network")
    height: int = Field(ge=0, description="Monotonically increasing block height (0 = genesis)")
    round: int = Field(ge=0, description="Consensus round index in which proposal was finalized")
    previous_block_hash: str = Field(description="SHA3-256 hash of parent block: 'sha3-256:<hex>'")
    timestamp: int = Field(description="POSIX microsecond UTC timestamp of block proposal")
    proposer_id: ValidatorID = Field(description="Identity of the validator that proposed this block")
    transaction_root: str = Field(description="SHA3-256 Merkle tree root over block's transactions")
    state_root: str = Field(description="SHA3-256 commitment of the logical ledger state after applying block")
    validator_set_hash: str = Field(description="SHA3-256 commitment of the active validator set")
    protocol_version: str = Field(default="1.0.0", description="Consensus protocol version")
    block_hash: str = Field(description="SHA3-256 hash of header: 'sha3-256:<hex>'")

    def to_signing_dict(self) -> Dict[str, object]:
        """Produce dictionary excluding block_hash for deterministic header hash computation."""
        return {
            "chain_id": self.chain_id,
            "height": self.height,
            "previous_block_hash": self.previous_block_hash,
            "proposer_id": str(self.proposer_id),
            "protocol_version": self.protocol_version,
            "round": self.round,
            "state_root": self.state_root,
            "timestamp": self.timestamp,
            "transaction_root": self.transaction_root,
            "validator_set_hash": self.validator_set_hash,
        }

    def compute_block_hash(self) -> str:
        """Compute the domain-separated SHA3-256 block hash."""
        canonical_bytes = canonicalize(self.to_signing_dict())
        digest = hashlib.sha3_256(DOMAIN_BLOCK_HEADER + canonical_bytes).hexdigest()
        return f"sha3-256:{digest}"


class Block(BaseModel):
    """An immutable, finalized block on the TraceCrypt distributed ledger."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    header: BlockHeader = Field(description="Cryptographically sealed block header")
    transactions: List[LedgerTransaction] = Field(description="Ordered list of included transactions")
    commit_certificate: Optional[CommitCertificate] = Field(
        default=None,
        description="Quorum commit certificate certifying finality (required for committed blocks)"
    )

    def to_canonical_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical representation."""
        cert_dict = self.commit_certificate.to_canonical_dict() if self.commit_certificate else None
        return {
            "commit_certificate": cert_dict,
            "header": self.header.model_dump(),
            "transactions": [tx.to_canonical_dict() for tx in self.transactions],
        }

    def validate_structural_integrity(self) -> None:
        """Independently verify all cryptographic commitments in the block."""
        # 1. Header block_hash self-consistency
        expected_block_hash = self.header.compute_block_hash()
        if self.header.block_hash != expected_block_hash:
            raise BlockValidationError(
                f"Block {self.header.height} block_hash mismatch: "
                f"expected '{expected_block_hash}', got '{self.header.block_hash}'"
            )

        # 2. Transaction Merkle root commitment
        tx_bytes_list = [tx.to_canonical_bytes() for tx in self.transactions]
        expected_tx_root = MerkleTree.build_merkle_root(tx_bytes_list)
        if self.header.transaction_root != expected_tx_root:
            raise BlockValidationError(
                f"Block {self.header.height} transaction_root mismatch: "
                f"expected '{expected_tx_root}', got '{self.header.transaction_root}'"
            )

        # 3. Commit certificate validation (if present)
        if self.commit_certificate is not None:
            if self.commit_certificate.height != self.header.height:
                raise BlockValidationError(
                    f"Commit certificate height {self.commit_certificate.height} "
                    f"does not match block height {self.header.height}."
                )
            if self.commit_certificate.block_hash != self.header.block_hash:
                raise BlockValidationError(
                    f"Commit certificate block_hash {self.commit_certificate.block_hash} "
                    f"does not match block header {self.header.block_hash}."
                )
