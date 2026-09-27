"""Deterministic Genesis Configuration for TraceCrypt Permissioned BFT Ledger.

Guarantees:
- Identical genesis hash across all nodes given identical configuration
- Strict validation of validator set (minimum 4 validators for f=1 BFT safety)
- Domain-separated genesis hashing (tracecrypt:genesis:)
"""

from __future__ import annotations

import hashlib
from typing import Dict
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.errors import ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.ledger.validator import ValidatorSet


class GenesisConfig(BaseModel):
    """Immutable deterministic genesis parameters for a TraceCrypt BFT ledger chain."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(min_length=3, description="Globally unique chain identifier (e.g. tracecrypt-airgap-1)")
    protocol_version: str = Field(default="1.0.0", description="Consensus protocol version")
    ledger_version: str = Field(default="1.0.0", description="Ledger state machine version")
    genesis_time: int = Field(description="POSIX microsecond UTC genesis epoch timestamp")
    validator_set: ValidatorSet = Field(description="Genesis validator set")
    initial_state_root: str = Field(
        default="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        description="Initial state root commitment before block 1",
    )

    def to_canonical_dict(self) -> Dict[str, object]:
        """Produce dictionary for deterministic canonical representation."""
        sorted_vals = sorted(self.validator_set.validators, key=lambda v: str(v.validator_id))
        return {
            "chain_id": self.chain_id,
            "genesis_time": self.genesis_time,
            "initial_state_root": self.initial_state_root,
            "ledger_version": self.ledger_version,
            "protocol_version": self.protocol_version,
            "validators": [v.to_canonical_dict() for v in sorted_vals],
        }

    def compute_genesis_hash(self) -> str:
        """Compute SHA3-256 hash of canonical genesis configuration.

        Domain separator: 'tracecrypt:genesis:'
        """
        canonical_bytes = canonicalize(self.to_canonical_dict())
        prefix = b"tracecrypt:genesis:"
        digest = hashlib.sha3_256(prefix + canonical_bytes).hexdigest()
        return f"sha3-256:{digest}"

    def validate_genesis(self) -> None:
        """Validate structural, cryptographic, and quorum requirements of genesis."""
        if not self.chain_id or len(self.chain_id.strip()) == 0:
            raise ValidationError("Genesis chain_id cannot be empty.")

        val_count = len(self.validator_set.validators)
        if val_count < 4:
            raise ValidationError(
                f"Genesis must configure at least 4 validators for f=1 BFT fault tolerance, got {val_count}."
            )

        unique_ids = set()
        for v in self.validator_set.validators:
            if v.validator_id in unique_ids:
                raise ValidationError(f"Duplicate validator ID in genesis: {v.validator_id}")
            unique_ids.add(v.validator_id)

            if v.voting_power < 1:
                raise ValidationError(f"Validator {v.validator_id} has invalid voting power {v.voting_power}")

        if not self.initial_state_root.startswith("sha3-256:"):
            raise ValidationError(f"Invalid initial_state_root format: {self.initial_state_root}")
