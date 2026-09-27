"""Permissioned Byzantine Fault Tolerant (BFT) distributed ledger subsystem for TraceCrypt.

Production-grade replicated state machine with:
- Deterministic BFT consensus (Propose -> Prevote -> Precommit -> Commit)
- Validator identity & offline PKI certificates
- Merkle transaction root & logical state root commitments
- Cryptographic inclusion proofs (Merkle proof export & verification)
- Offline air-gapped LAN P2P network transport
- SQLite WAL persistence & full startup chain integrity verification
- Byzantine equivocation detection and evidence logging
"""

from tracecrypt.ledger.block import Block, BlockHeader, LedgerTransaction
from tracecrypt.ledger.consensus import ConsensusEngine, ConsensusStep
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.interface import DecryptionEventLedger
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.merkle import MerkleInclusionProof, MerkleTree
from tracecrypt.ledger.messages import (
    ByzantineEvidence,
    CommitCertificate,
    VoteMessage,
    VoteType,
)
from tracecrypt.ledger.network import NetworkFrame, P2PNetwork
from tracecrypt.ledger.node import BFTLedgerNode
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.sync import StateSyncRequest, StateSyncResponse, SyncManager
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet

__all__ = [
    # Core Node & Interface
    "BFTLedgerNode",
    "DecryptionEventLedger",
    "InMemoryLedgerAdapter",
    "CommitStatus",
    "LedgerTransactionReceipt",
    # Block & Transactions
    "Block",
    "BlockHeader",
    "LedgerTransaction",
    # Consensus
    "ConsensusEngine",
    "ConsensusStep",
    "VoteMessage",
    "VoteType",
    "CommitCertificate",
    "ByzantineEvidence",
    # Genesis & Validators
    "GenesisConfig",
    "NodeRole",
    "ValidatorInfo",
    "ValidatorSet",
    # Merkle & State
    "MerkleTree",
    "MerkleInclusionProof",
    "LedgerState",
    "Mempool",
    # Persistence & Sync
    "LedgerStorage",
    "SyncManager",
    "StateSyncRequest",
    "StateSyncResponse",
    # Networking
    "P2PNetwork",
    "NetworkFrame",
]
