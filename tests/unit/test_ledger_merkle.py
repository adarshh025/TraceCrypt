"""Unit tests for Deterministic Merkle Tree and Cryptographic Inclusion Proofs."""

import hashlib
import pytest

from tracecrypt.errors import MerkleProofError
from tracecrypt.ledger.merkle import (
    MerkleInclusionProof,
    MerkleTree,
)


@pytest.mark.unit
def test_merkle_tree_empty():
    root = MerkleTree.build_merkle_root([])
    assert root.startswith("sha3-256:")
    expected_empty = hashlib.sha3_256(b"tracecrypt:merkle:empty").hexdigest()
    assert root == f"sha3-256:{expected_empty}"


@pytest.mark.unit
def test_merkle_tree_single_leaf():
    data = [b"transaction_payload_1"]
    root = MerkleTree.build_merkle_root(data)
    leaf_hash = MerkleTree.compute_leaf_hash(data[0])
    assert root == leaf_hash


@pytest.mark.unit
def test_merkle_tree_determinism():
    leaves1 = [f"tx_{i}".encode("utf-8") for i in range(8)]
    leaves2 = [f"tx_{i}".encode("utf-8") for i in range(8)]

    root1 = MerkleTree.build_merkle_root(leaves1)
    root2 = MerkleTree.build_merkle_root(leaves2)

    assert root1 == root2
    assert root1.startswith("sha3-256:")


@pytest.mark.unit
def test_merkle_tree_odd_number_of_leaves():
    leaves = [f"tx_{i}".encode("utf-8") for i in range(5)]
    root = MerkleTree.build_merkle_root(leaves)
    assert root.startswith("sha3-256:")


@pytest.mark.unit
def test_merkle_inclusion_proof_generation_and_verification():
    leaves = [f"ledger_tx_data_{i}".encode("utf-8") for i in range(16)]
    tree = MerkleTree(leaves)
    root = tree.root_hash

    for i in range(len(leaves)):
        proof = tree.generate_proof(i)
        assert proof.leaf_index == i
        assert proof.total_leaves == 16

        leaf_hash = MerkleTree.compute_leaf_hash(leaves[i])
        verified = MerkleTree.verify_merkle_proof(leaf_hash, proof, root)
        assert verified is True


@pytest.mark.unit
def test_merkle_proof_tampered_leaf_fails():
    leaves = [f"tx_{i}".encode("utf-8") for i in range(4)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(1)

    # Tampered leaf data
    tampered_leaf_hash = MerkleTree.compute_leaf_hash(b"tampered_tx_data_1")
    assert MerkleTree.verify_merkle_proof(tampered_leaf_hash, proof, tree.root_hash) is False


@pytest.mark.unit
def test_merkle_proof_tampered_root_fails():
    leaves = [f"tx_{i}".encode("utf-8") for i in range(4)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    leaf_hash = MerkleTree.compute_leaf_hash(leaves[0])
    forged_root = "sha3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert MerkleTree.verify_merkle_proof(leaf_hash, proof, forged_root) is False


@pytest.mark.unit
def test_merkle_proof_tampered_audit_path_fails():
    leaves = [f"tx_{i}".encode("utf-8") for i in range(4)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    fake_hash = "sha3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    tampered_path = [
        {"direction": step.direction, "sibling_hash": fake_hash}
        for step in proof.audit_path
    ]
    tampered_proof = MerkleInclusionProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        total_leaves=proof.total_leaves,
        audit_path=tampered_path,
        expected_root=proof.expected_root,
    )

    leaf_hash = MerkleTree.compute_leaf_hash(leaves[0])
    assert MerkleTree.verify_merkle_proof(leaf_hash, tampered_proof, tree.root_hash) is False


@pytest.mark.unit
def test_merkle_proof_out_of_bounds_index():
    leaves = [b"tx_1", b"tx_2"]
    with pytest.raises(MerkleProofError):
        MerkleTree.generate_merkle_proof(5, leaves)
    with pytest.raises(MerkleProofError):
        MerkleTree.generate_merkle_proof(-1, leaves)
