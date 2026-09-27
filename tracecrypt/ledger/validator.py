"""Validator identity, roles, and quorum management for TraceCrypt BFT Ledger.

Implements:
- NodeRole (VALIDATOR, OBSERVER)
- ValidatorInfo with certified ML-DSA-65 consensus verification key
- ValidatorSet with generic (2f + 1) quorum calculation
- Deterministic proposer selection based strictly on agreed chain state
- Domain-separated validator set hashing
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.errors import ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.utils.identifiers import ValidatorID


class NodeRole(str, Enum):
    """Operational node roles within the permissioned BFT network."""
    VALIDATOR = "VALIDATOR"
    OBSERVER = "OBSERVER"


class ValidatorInfo(BaseModel):
    """Cryptographic identity and consensus parameters for an active validator."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    validator_id: ValidatorID = Field(description="Unique validator identifier (val-...)")
    public_key_b64: str = Field(description="Base64-encoded NIST FIPS 204 ML-DSA-65 public key")
    certificate_id: str = Field(description="Serial number of validator's consensus identity certificate")
    certificate_fingerprint: str = Field(description="Public key fingerprint of validator certificate")
    voting_power: int = Field(default=1, ge=1, description="Consensus voting weight (must be >= 1)")
    role: NodeRole = Field(default=NodeRole.VALIDATOR, description="Node role: VALIDATOR or OBSERVER")

    @classmethod
    def from_certificate(
        cls,
        validator_id: ValidatorID,
        certificate: PQCIdentityCertificate,
        voting_power: int = 1,
        role: NodeRole = NodeRole.VALIDATOR,
    ) -> ValidatorInfo:
        """Create ValidatorInfo bound to an authenticated PQCIdentityCertificate."""
        return cls(
            validator_id=validator_id,
            public_key_b64=certificate.public_key_b64,
            certificate_id=certificate.serial_number,
            certificate_fingerprint=certificate.public_key_fingerprint,
            voting_power=voting_power,
            role=role,
        )

    def get_public_key(self) -> MLDSAPublicKey:
        """Instantiate strongly-typed MLDSAPublicKey from base64 representation."""
        import base64
        return MLDSAPublicKey(base64.b64decode(self.public_key_b64))

    def to_canonical_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical representation."""
        return {
            "certificate_fingerprint": self.certificate_fingerprint,
            "certificate_id": self.certificate_id,
            "public_key_b64": self.public_key_b64,
            "role": self.role.value,
            "validator_id": str(self.validator_id),
            "voting_power": self.voting_power,
        }


class ValidatorSet(BaseModel):
    """Immutable collection of permissioned validators participating in BFT consensus."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    validators: List[ValidatorInfo] = Field(description="Ordered list of permissioned validators")

    @property
    def validator_map(self) -> Dict[ValidatorID, ValidatorInfo]:
        """Map of ValidatorID to ValidatorInfo."""
        return {v.validator_id: v for v in self.validators}

    @property
    def total_voting_power(self) -> int:
        """Total voting power of all active VALIDATOR nodes."""
        return sum(v.voting_power for v in self.validators if v.role == NodeRole.VALIDATOR)

    @property
    def max_byzantine_faults(self) -> int:
        """Maximum tolerated Byzantine faults f = floor((n - 1) / 3)."""
        active_count = sum(1 for v in self.validators if v.role == NodeRole.VALIDATOR)
        return (active_count - 1) // 3

    @property
    def quorum_threshold(self) -> int:
        """Generic Byzantine quorum threshold: floor(2 * TotalPower / 3) + 1.

        For n=4 equal-weight validators (TotalPower=4):
        floor(8 / 3) + 1 = 2 + 1 = 3 votes required (tolerating f = 1).
        """
        w = self.total_voting_power
        if w == 0:
            return 0
        return (2 * w) // 3 + 1

    @property
    def quorum(self) -> int:
        """Alias for quorum_threshold."""
        return self.quorum_threshold

    def has_quorum(self, votes_power: int) -> bool:
        """Evaluate if accumulated voting power satisfies consensus quorum."""
        return votes_power >= self.quorum_threshold

    def is_validator(self, validator_id: ValidatorID | str) -> bool:
        """True if validator_id is an authorized active consensus validator."""
        vid = ValidatorID(str(validator_id))
        info = self.validator_map.get(vid)
        return info is not None and info.role == NodeRole.VALIDATOR

    def get_validator(self, validator_id: ValidatorID | str) -> Optional[ValidatorInfo]:
        """Retrieve ValidatorInfo for given validator identifier."""
        vid = ValidatorID(str(validator_id))
        return self.validator_map.get(vid)

    def compute_hash(self) -> str:
        """Compute SHA3-256 hash of canonical validator set commitment.

        Domain separator: 'tracecrypt:valset:'
        """
        sorted_vals = sorted(self.validators, key=lambda v: str(v.validator_id))
        canonical_list = [v.to_canonical_dict() for v in sorted_vals]
        canonical_bytes = canonicalize(canonical_list)
        prefix = b"tracecrypt:valset:"
        digest = hashlib.sha3_256(prefix + canonical_bytes).hexdigest()
        return f"sha3-256:{digest}"

    def get_proposer(self, height: int, round_idx: int) -> ValidatorID:
        """Deterministic round-robin proposer selection based strictly on agreed chain state.

        Given identical validator set, height, and round, every honest node computes
        the exact same proposer without local timing, random sources, or external clocks.
        """
        active_validators = sorted(
            [v for v in self.validators if v.role == NodeRole.VALIDATOR],
            key=lambda v: str(v.validator_id)
        )
        if not active_validators:
            raise ValidationError("ValidatorSet has zero active VALIDATOR nodes.")

        # Deterministic slot calculation
        slot = (height + round_idx) % len(active_validators)
        return active_validators[slot].validator_id
