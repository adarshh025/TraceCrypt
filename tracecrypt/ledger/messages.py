"""Consensus message schemas, canonical signing, and Byzantine evidence for TraceCrypt BFT.

Implements:
- VoteType (PREVOTE, PRECOMMIT)
- VoteMessage with ML-DSA-65 signature over canonical RFC 8785 representation
- CommitCertificate aggregating 2f + 1 validator Precommit votes
- ProposalMessage with proposer signature
- ByzantineEvidence documenting cryptographically provable equivocation
- Domain-separated message signing to prevent replay across chains, heights, rounds, and message types
"""

from __future__ import annotations

import base64
import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.pqc_dsa import sign_mldsa, verify_mldsa
from tracecrypt.crypto.types import MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature
from tracecrypt.errors import ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.utils.identifiers import ValidatorID


DOMAIN_CONSENSUS_VOTE = b"tracecrypt:consensus:vote:"
DOMAIN_CONSENSUS_PROPOSAL = b"tracecrypt:consensus:proposal:"
DOMAIN_BYZANTINE_EVIDENCE = b"tracecrypt:consensus:evidence:"


class VoteType(str, Enum):
    """BFT consensus voting stages."""
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"


class VoteMessage(BaseModel):
    """Cryptographically authenticated vote from a permissioned validator."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Unique chain ID binding this vote to the network")
    height: int = Field(ge=0, description="Block height being voted on")
    round: int = Field(ge=0, description="Consensus round index (0, 1, 2, ...)")
    vote_type: VoteType = Field(description="Vote phase: PREVOTE or PRECOMMIT")
    block_hash: Optional[str] = Field(
        default=None,
        description="Voted block_hash ('sha3-256:<hex>') or None/NIL for timeout"
    )
    validator_id: ValidatorID = Field(description="Identity of voting validator")
    timestamp: int = Field(description="POSIX microsecond UTC timestamp of vote creation")
    signature: str = Field(description="Base64-encoded NIST FIPS 204 ML-DSA-65 signature")

    def to_signing_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical signing."""
        return {
            "block_hash": self.block_hash,
            "chain_id": self.chain_id,
            "height": self.height,
            "round": self.round,
            "timestamp": self.timestamp,
            "validator_id": str(self.validator_id),
            "vote_type": self.vote_type.value,
        }

    def to_signing_bytes(self) -> bytes:
        """Produce domain-separated bytes to be signed."""
        canonical_bytes = canonicalize(self.to_signing_dict())
        return DOMAIN_CONSENSUS_VOTE + canonical_bytes

    @classmethod
    def create_and_sign(
        cls,
        chain_id: str,
        height: int,
        round: int,
        vote_type: VoteType,
        block_hash: Optional[str],
        validator_id: ValidatorID,
        signing_key: MLDSAPrivateKey,
        timestamp: int,
    ) -> VoteMessage:
        """Construct and cryptographically sign a VoteMessage with validator's private key."""
        proto = {
            "block_hash": block_hash,
            "chain_id": chain_id,
            "height": height,
            "round": round,
            "timestamp": timestamp,
            "validator_id": str(validator_id),
            "vote_type": vote_type.value,
        }
        signing_bytes = DOMAIN_CONSENSUS_VOTE + canonicalize(proto)
        sig = sign_mldsa(signing_key, signing_bytes)
        return cls(
            chain_id=chain_id,
            height=height,
            round=round,
            vote_type=vote_type,
            block_hash=block_hash,
            validator_id=validator_id,
            timestamp=timestamp,
            signature=sig.to_b64(),
        )

    def verify_signature(self, public_key: MLDSAPublicKey) -> bool:
        """Verify the ML-DSA-65 signature on this vote using validator's public key."""
        try:
            sig_bytes = base64.b64decode(self.signature)
            sig = MLDSASignature(sig_bytes)
            signing_bytes = self.to_signing_bytes()
            return verify_mldsa(public_key, signing_bytes, sig)
        except Exception:
            return False


class ProposalMessage(BaseModel):
    """Cryptographically authenticated proposal message from designated proposer."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Unique chain ID binding this proposal")
    height: int = Field(ge=0, description="Block height being proposed")
    round: int = Field(ge=0, description="Consensus round index")
    block_hash: str = Field(description="SHA3-256 hash of proposed block: 'sha3-256:<hex>'")
    proposer_id: ValidatorID = Field(description="Identity of proposing validator")
    timestamp: int = Field(description="POSIX microsecond UTC timestamp")
    signature: str = Field(description="Base64-encoded NIST FIPS 204 ML-DSA-65 signature")

    def to_signing_dict(self) -> Dict[str, object]:
        return {
            "block_hash": self.block_hash,
            "chain_id": self.chain_id,
            "height": self.height,
            "proposer_id": str(self.proposer_id),
            "round": self.round,
            "timestamp": self.timestamp,
        }

    def to_signing_bytes(self) -> bytes:
        canonical_bytes = canonicalize(self.to_signing_dict())
        return DOMAIN_CONSENSUS_PROPOSAL + canonical_bytes

    @classmethod
    def create_and_sign(
        cls,
        chain_id: str,
        height: int,
        round: int,
        block_hash: str,
        proposer_id: ValidatorID,
        signing_key: MLDSAPrivateKey,
        timestamp: int,
    ) -> ProposalMessage:
        proto = {
            "block_hash": block_hash,
            "chain_id": chain_id,
            "height": height,
            "proposer_id": str(proposer_id),
            "round": round,
            "timestamp": timestamp,
        }
        signing_bytes = DOMAIN_CONSENSUS_PROPOSAL + canonicalize(proto)
        sig = sign_mldsa(signing_key, signing_bytes)
        return cls(
            chain_id=chain_id,
            height=height,
            round=round,
            block_hash=block_hash,
            proposer_id=proposer_id,
            timestamp=timestamp,
            signature=sig.to_b64(),
        )

    def verify_signature(self, public_key: MLDSAPublicKey) -> bool:
        try:
            sig_bytes = base64.b64decode(self.signature)
            sig = MLDSASignature(sig_bytes)
            signing_bytes = self.to_signing_bytes()
            return verify_mldsa(public_key, signing_bytes, sig)
        except Exception:
            return False


class CommitCertificate(BaseModel):
    """Cryptographic evidence certifying that a block achieved final commitment by quorum."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(description="Chain ID")
    height: int = Field(ge=1, description="Committed block height")
    round: int = Field(ge=0, description="Consensus round in which commitment was reached")
    block_hash: str = Field(description="SHA3-256 hash of finalized block: 'sha3-256:<hex>'")
    votes: List[VoteMessage] = Field(description="Collection of >= 2f + 1 valid PRECOMMIT votes")
    validator_set_hash: str = Field(description="Hash of active validator set that authorized this block")

    def to_canonical_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical representation."""
        sorted_votes = sorted(self.votes, key=lambda v: str(v.validator_id))
        return {
            "block_hash": self.block_hash,
            "chain_id": self.chain_id,
            "height": self.height,
            "round": self.round,
            "validator_set_hash": self.validator_set_hash,
            "votes": [v.model_dump() for v in sorted_votes],
        }

    def verify_certificate(
        self,
        validator_set: Any,
        expected_block_hash: str,
    ) -> bool:
        """Independently verify that the certificate contains quorum of valid signatures."""
        if self.block_hash != expected_block_hash:
            return False

        if hasattr(validator_set, "compute_hash"):
            expected_valset_hash = validator_set.compute_hash()
            if self.validator_set_hash and self.validator_set_hash != expected_valset_hash:
                return False

        accumulated_power = 0
        seen_validators = set()

        for vote in self.votes:
            if vote.chain_id != self.chain_id:
                return False
            if vote.height != self.height:
                return False
            if vote.round != self.round:
                return False
            if vote.vote_type != VoteType.PRECOMMIT:
                return False
            if vote.block_hash != self.block_hash:
                return False
            if vote.validator_id in seen_validators:
                # Duplicate vote from same validator in same certificate
                return False

            val_info = validator_set.get_validator(vote.validator_id)
            if val_info is None:
                return False

            pk = val_info.get_public_key()
            if not vote.verify_signature(pk):
                return False

            seen_validators.add(vote.validator_id)
            accumulated_power += val_info.voting_power

        return validator_set.has_quorum(accumulated_power)


class ByzantineEvidence(BaseModel):
    """Independently verifiable cryptographic proof of validator equivocation or malicious behavior."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    validator_id: ValidatorID = Field(description="Equivocating validator identity")
    height: int = Field(ge=0, description="Height where conflicting votes occurred")
    round: int = Field(ge=0, description="Round where conflicting votes occurred")
    vote_type: VoteType = Field(description="Phase in which equivocation occurred")
    conflicting_vote_a: VoteMessage = Field(description="First signed vote")
    conflicting_vote_b: VoteMessage = Field(description="Second conflicting signed vote")
    evidence_hash: str = Field(description="SHA3-256 hash of evidence")

    @classmethod
    def create(
        cls,
        vote_a: VoteMessage,
        vote_b: VoteMessage,
    ) -> ByzantineEvidence:
        """Construct verified ByzantineEvidence from two conflicting votes."""
        if vote_a.validator_id != vote_b.validator_id:
            raise ValidationError("Equivocation evidence requires identical validator IDs.")
        if vote_a.height != vote_b.height or vote_a.round != vote_b.round:
            raise ValidationError("Equivocation evidence requires identical height and round.")
        if vote_a.vote_type != vote_b.vote_type:
            raise ValidationError("Equivocation evidence requires identical vote type.")
        if vote_a.block_hash == vote_b.block_hash:
            raise ValidationError("Identical votes do not constitute equivocation.")

        proto = {
            "height": vote_a.height,
            "round": vote_a.round,
            "validator_id": str(vote_a.validator_id),
            "vote_a": vote_a.model_dump(),
            "vote_b": vote_b.model_dump(),
            "vote_type": vote_a.vote_type.value,
        }
        canonical_bytes = canonicalize(proto)
        digest = hashlib.sha3_256(DOMAIN_BYZANTINE_EVIDENCE + canonical_bytes).hexdigest()

        return cls(
            validator_id=vote_a.validator_id,
            height=vote_a.height,
            round=vote_a.round,
            vote_type=vote_a.vote_type,
            conflicting_vote_a=vote_a,
            conflicting_vote_b=vote_b,
            evidence_hash=f"sha3-256:{digest}",
        )

    def verify(self, validator_key_or_set: Any) -> bool:
        """Verify that both conflicting votes were indeed signed by the alleged validator.

        Accepts either an MLDSAPublicKey or a ValidatorSet.
        """
        if hasattr(validator_key_or_set, "get_validator"):
            val_info = validator_key_or_set.get_validator(self.validator_id)
            if val_info is None:
                return False
            pub_key = val_info.get_public_key()
        else:
            pub_key = validator_key_or_set

        return (
            self.conflicting_vote_a.verify_signature(pub_key)
            and self.conflicting_vote_b.verify_signature(pub_key)
            and self.conflicting_vote_a.block_hash != self.conflicting_vote_b.block_hash
        )
