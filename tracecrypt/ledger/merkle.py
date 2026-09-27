"""Deterministic Cryptographic Merkle Transaction Tree & Inclusion Proofs for TraceCrypt.

Implements:
- Domain-separated leaf hashing: SHA3-256(b"tracecrypt:merkle:leaf:" || canonical_bytes)
- Domain-separated inner node hashing: SHA3-256(b"tracecrypt:merkle:node:" || left || right)
- Merkle root computation over arbitrary lists of canonical items
- Cryptographic inclusion proof generation (audit paths)
- Standalone independent verification for forensic investigators
"""

from __future__ import annotations

import hashlib
from typing import Any, List, Literal, Optional, Sequence
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.errors import MerkleProofError


DOMAIN_LEAF = b"tracecrypt:merkle:leaf:"
DOMAIN_NODE = b"tracecrypt:merkle:node:"
DOMAIN_EMPTY = b"tracecrypt:merkle:empty"

EMPTY_MERKLE_ROOT = f"sha3-256:{hashlib.sha3_256(DOMAIN_EMPTY).hexdigest()}"


class MerkleProofStep(BaseModel):
    """Single step along the Merkle audit path."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    direction: Literal["left", "right"] = Field(
        description="Position of the sibling node relative to current path node"
    )
    sibling_hash: str = Field(description="SHA3-256 hex string of sibling node: 'sha3-256:<hex>'")


class MerkleInclusionProof(BaseModel):
    """Cryptographic proof certifying membership of a transaction in a block's transaction_root."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    leaf_hash: str = Field(description="SHA3-256 digest of target leaf")
    leaf_index: int = Field(ge=0, description="0-indexed position of leaf in transaction tree")
    total_leaves: int = Field(ge=0, description="Total number of leaves in the tree")
    audit_path: List[MerkleProofStep] = Field(description="Ordered sequence of sibling hashes to root")
    expected_root: str = Field(description="Expected transaction_root commitment: 'sha3-256:<hex>'")

    def verify(self, leaf_bytes: bytes) -> bool:
        """Independently verify this proof given the raw canonical transaction bytes."""
        return MerkleTree.verify_merkle_proof(leaf_bytes, self, self.expected_root)


class MerkleTree:
    """Deterministic binary Merkle tree engine."""

    def __init__(self, leaf_items: Optional[Sequence[bytes]] = None) -> None:
        self.leaf_items: List[bytes] = list(leaf_items) if leaf_items else []
        self.root_hash: str = self.build_merkle_root(self.leaf_items)

    def generate_proof(self, target_index: int) -> MerkleInclusionProof:
        """Generate proof for a leaf in this tree instance."""
        return self.generate_merkle_proof(self.leaf_items, target_index)

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """Compute 32-byte domain-separated leaf digest."""
        return hashlib.sha3_256(DOMAIN_LEAF + data).digest()

    @classmethod
    def compute_leaf_hash(cls, data: bytes) -> str:
        """Compute formatted SHA3-256 domain-separated leaf hash: 'sha3-256:<hex>'."""
        return f"sha3-256:{cls.hash_leaf(data).hex()}"

    @staticmethod
    def hash_node(left: bytes, right: bytes) -> bytes:
        """Compute 32-byte domain-separated inner node digest."""
        return hashlib.sha3_256(DOMAIN_NODE + left + right).digest()

    @classmethod
    def build_merkle_root(cls, leaf_items: Sequence[bytes]) -> str:
        """Compute the deterministic SHA3-256 Merkle root from a sequence of canonical item bytes."""
        if not leaf_items:
            return EMPTY_MERKLE_ROOT

        current_level = [cls.hash_leaf(item) for item in leaf_items]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    parent = cls.hash_node(current_level[i], current_level[i + 1])
                else:
                    # Odd node: promote to next level (RFC 6962 standard)
                    parent = current_level[i]
                next_level.append(parent)
            current_level = next_level

        return f"sha3-256:{current_level[0].hex()}"

    @classmethod
    def generate_merkle_proof(
        cls,
        leaf_items: Any,
        target_index: Any,
    ) -> MerkleInclusionProof:
        """Generate a cryptographic inclusion proof for the leaf at target_index.

        Supports both (leaf_items, target_index) and (target_index, leaf_items) signatures.
        """
        # Support flexible argument order
        if isinstance(leaf_items, int) and hasattr(target_index, "__len__"):
            target_index, leaf_items = leaf_items, target_index

        if not leaf_items:
            raise MerkleProofError("Cannot generate proof from empty leaf set.")
        if target_index < 0 or target_index >= len(leaf_items):
            raise MerkleProofError(
                f"Target index {target_index} out of bounds for leaf count {len(leaf_items)}."
            )

        total_leaves = len(leaf_items)
        target_leaf_hash_bytes = cls.hash_leaf(leaf_items[target_index])
        target_leaf_hash_str = f"sha3-256:{target_leaf_hash_bytes.hex()}"

        # Build tree levels and record audit path
        levels: List[List[bytes]] = [[cls.hash_leaf(item) for item in leaf_items]]
        while len(levels[-1]) > 1:
            prev = levels[-1]
            curr = []
            for i in range(0, len(prev), 2):
                if i + 1 < len(prev):
                    curr.append(cls.hash_node(prev[i], prev[i + 1]))
                else:
                    curr.append(prev[i])
            levels.append(curr)

        root_str = f"sha3-256:{levels[-1][0].hex()}"

        # Reconstruct audit path from target_index
        audit_path: List[MerkleProofStep] = []
        curr_idx = target_index

        for level in levels[:-1]:
            if curr_idx % 2 == 0:
                # Target is left child, sibling is right
                if curr_idx + 1 < len(level):
                    sibling_raw = level[curr_idx + 1]
                    audit_path.append(
                        MerkleProofStep(
                            direction="right",
                            sibling_hash=f"sha3-256:{sibling_raw.hex()}",
                        )
                    )
            else:
                # Target is right child, sibling is left
                sibling_raw = level[curr_idx - 1]
                audit_path.append(
                    MerkleProofStep(
                        direction="left",
                        sibling_hash=f"sha3-256:{sibling_raw.hex()}",
                    )
                )
            curr_idx //= 2

        return MerkleInclusionProof(
            leaf_hash=target_leaf_hash_str,
            leaf_index=target_index,
            total_leaves=total_leaves,
            audit_path=audit_path,
            expected_root=root_str,
        )

    @classmethod
    def verify_merkle_proof(
        cls,
        leaf_data: bytes | str,
        proof: MerkleInclusionProof,
        expected_root: str,
    ) -> bool:
        """Mathematically verify an inclusion proof without database trust."""
        if isinstance(leaf_data, str) and leaf_data.startswith("sha3-256:"):
            if leaf_data != proof.leaf_hash:
                return False
            computed_leaf = bytes.fromhex(leaf_data.split(":", 1)[1])
        else:
            computed_leaf = cls.hash_leaf(bytes(leaf_data))
            if f"sha3-256:{computed_leaf.hex()}" != proof.leaf_hash:
                return False

        current = computed_leaf
        for step in proof.audit_path:
            if not step.sibling_hash.startswith("sha3-256:"):
                return False
            sibling_bytes = bytes.fromhex(step.sibling_hash.split(":", 1)[1])

            if step.direction == "right":
                current = cls.hash_node(current, sibling_bytes)
            elif step.direction == "left":
                current = cls.hash_node(sibling_bytes, current)
            else:
                return False

        computed_root_str = f"sha3-256:{current.hex()}"
        return computed_root_str == expected_root and computed_root_str == proof.expected_root
