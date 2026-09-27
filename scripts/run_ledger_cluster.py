"""Development and cluster management script for TraceCrypt 4-Node BFT Ledger.

Provides:
- init: Deterministically provisions offline Root CA, 4 validator keypairs, certificates, and genesis.json
- status: Inspects local databases and consensus state across all 4 nodes
- inject: Generates signed DecryptionEvents and injects them into the ledger
- step: Advances consensus rounds across the cluster, committing pending transactions
- verify: Performs independent end-to-end chain integrity verification on all node databases
- simulate-failure: Demonstrates f=1 Byzantine fault tolerance (1 node offline or faulty)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair  # noqa: E402
from tracecrypt.crypto.random import SecureRandom  # noqa: E402
from tracecrypt.crypto.types import MLDSAPrivateKey  # noqa: E402
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms  # noqa: E402
from tracecrypt.event.signer import DecryptionEventSigner  # noqa: E402
from tracecrypt.identity.ca import OfflineRootCA  # noqa: E402
from tracecrypt.ledger.genesis import GenesisConfig  # noqa: E402
from tracecrypt.ledger.node import BFTLedgerNode  # noqa: E402
from tracecrypt.ledger.storage import LedgerStorage  # noqa: E402
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet  # noqa: E402
from tracecrypt.utils.identifiers import (  # noqa: E402
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    ValidatorID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_ledger_cluster")

DEFAULT_CLUSTER_DIR = Path("C:/TraceCrypt/cluster_data")
DEFAULT_CHAIN_ID = "tracecrypt-airgap-1"
DEFAULT_PORTS = [9101, 9102, 9103, 9104]


def init_cluster(cluster_dir: Path, chain_id: str) -> None:
    """Initialize genesis, offline CA, and 4 independent validator node directories."""
    cluster_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Initializing 4-node BFT cluster in: %s", cluster_dir)

    # 1. Initialize offline Root CA
    ca = OfflineRootCA.initialize(ca_id="ca-root-consensus-offline")
    logger.info("Generated Consensus Master Root CA (fingerprint: %s)", ca.fingerprint[:16])

    validator_infos: List[ValidatorInfo] = []
    node_configs = []

    # 2. Provision 4 separate validator identities & consensus keypairs
    for i in range(1, 5):
        node_dir = cluster_dir / f"node-{i}"
        node_dir.mkdir(parents=True, exist_ok=True)
        for old_file in node_dir.glob("ledger.db*"):
            try:
                old_file.unlink()
            except Exception:
                pass

        val_id = ValidatorID.generate()
        pk, sk = generate_mldsa_keypair()

        cert = ca.issue_validator_certificate(
            subject_id=str(val_id),
            public_key=pk,
            organization="TraceCrypt Permissioned Network",
            role="ConsensusValidator",
            validity_days=730,
        )

        # Save private key securely in node's private directory
        key_file = node_dir / "validator_key.json"
        key_file.write_text(
            json.dumps({"validator_id": str(val_id), "private_key_b64": sk.to_b64()}),
            encoding="utf-8",
        )

        cert_file = node_dir / "validator_cert.json"
        cert_file.write_text(cert.model_dump_json(indent=2), encoding="utf-8")

        val_info = ValidatorInfo.from_certificate(
            validator_id=val_id,
            certificate=cert,
            voting_power=1,
            role=NodeRole.VALIDATOR,
        )
        validator_infos.append(val_info)

        node_configs.append({
            "node_index": i,
            "validator_id": str(val_id),
            "port": DEFAULT_PORTS[i - 1],
            "dir": str(node_dir),
        })

    # 3. Create canonical GenesisConfig
    val_set = ValidatorSet(validators=validator_infos)
    genesis = GenesisConfig(
        chain_id=chain_id,
        genesis_time=utc_now_micros(),
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    genesis.validate_genesis()
    genesis_hash = genesis.compute_genesis_hash()
    logger.info("Canonical Genesis Hash computed: %s", genesis_hash)

    # Save genesis.json to cluster root and all node directories
    genesis_json = genesis.model_dump_json(indent=2)
    (cluster_dir / "genesis.json").write_text(genesis_json, encoding="utf-8")

    for cfg in node_configs:
        n_dir = Path(cfg["dir"])
        (n_dir / "genesis.json").write_text(genesis_json, encoding="utf-8")

        # Configure peer list (excluding self)
        my_port = cfg["port"]
        peers = [("127.0.0.1", p) for p in DEFAULT_PORTS if p != my_port]
        node_meta = {
            "chain_id": chain_id,
            "validator_id": cfg["validator_id"],
            "listen_host": "127.0.0.1",
            "listen_port": my_port,
            "peers": peers,
        }
        (n_dir / "node_config.json").write_text(json.dumps(node_meta, indent=2), encoding="utf-8")

    logger.info("Cluster initialization complete. 4 validator nodes provisioned.")


def load_node(node_dir: Path) -> BFTLedgerNode:
    """Instantiate a BFTLedgerNode from its configuration directory."""
    genesis = GenesisConfig.model_validate_json((node_dir / "genesis.json").read_text(encoding="utf-8"))
    key_data = json.loads((node_dir / "validator_key.json").read_text(encoding="utf-8"))
    config_data = json.loads((node_dir / "node_config.json").read_text(encoding="utf-8"))

    val_id = ValidatorID(key_data["validator_id"])
    sk = MLDSAPrivateKey.from_b64(key_data["private_key_b64"])

    peers: List[Tuple[str, int]] = [(p[0], int(p[1])) for p in config_data["peers"]]

    return BFTLedgerNode(
        validator_id=val_id,
        private_key=sk,
        genesis=genesis,
        data_dir=node_dir,
        listen_host=config_data["listen_host"],
        listen_port=config_data["listen_port"],
        peers=peers,
        role=NodeRole.VALIDATOR,
    )


def cluster_status(cluster_dir: Path) -> None:
    """Print the synchronized ledger status across all nodes."""
    logger.info("Inspecting status for cluster in %s", cluster_dir)
    print("\n" + "=" * 80)
    print(f"{'Node':<8} | {'Height':<8} | {'Committed Block Hash':<38} | {'State Root':<38}")
    print("-" * 80)

    hashes = []
    roots = []

    for i in range(1, 5):
        node_dir = cluster_dir / f"node-{i}"
        if not (node_dir / "ledger.db").exists():
            print(f"node-{i:<3} | {'NOT INITIALIZED':<60}")
            continue

        storage = LedgerStorage(node_dir / "ledger.db")
        h = storage.get_latest_height()
        latest_blk = storage.get_latest_block()
        b_hash = latest_blk.header.block_hash if latest_blk else "NONE"
        s_root = latest_blk.header.state_root if latest_blk else "INITIAL"

        hashes.append(b_hash)
        roots.append(s_root)

        print(f"node-{i:<3} | {h:<8} | {b_hash[:34]+'...':<38} | {s_root[:34]+'...':<38}")
        storage.close()

    print("=" * 80)
    if len(set(hashes)) <= 1 and len(set(roots)) <= 1:
        print("[SUCCESS] All nodes are in identical cryptographic lockstep.\n")
    else:
        print("[WARNING] Divergence detected across node databases!\n")


def inject_transaction(cluster_dir: Path) -> str:
    """Generate and inject a cryptographically valid DecryptionEvent into node-1."""
    # 1. Setup recipient PKI
    ca = OfflineRootCA.initialize(ca_id="ca-root-recipient-offline")
    recip_pk, recip_sk = generate_mldsa_keypair()
    recip_id = RecipientID.generate()
    recip_cert = ca.issue_signing_certificate(
        subject_id=str(recip_id),
        public_key=recip_pk,
        organization="Investigative Corp",
        role="RecipientAuditor",
    )

    # 2. Construct valid DecryptionEvent
    now = utc_now_micros()
    event_id = EventID.generate()
    session_id = SessionID.generate()
    watermark_id = WatermarkID.generate()
    doc_id = DocumentID.generate()
    dist_id = DistributionID.generate()

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=event_id,
        document_id=doc_id,
        distribution_id=dist_id,
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recip_id,
        recipient_certificate_id=recip_cert.serial_number,
        session_id=session_id,
        watermark_id=watermark_id,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=now,
        pqc_algorithms=PQCAlgorithms(),
    )

    signed_event = DecryptionEventSigner.sign_event(
        event=event,
        signing_key=recip_sk,
        signing_cert=recip_cert,
    )

    # 3. Load node-1 and submit event
    node1 = load_node(cluster_dir / "node-1")
    receipt = node1.submit_event(signed_event, recipient_certificate=recip_cert)
    logger.info(
        "Submitted event %s to node-1 mempool. Tx ID: %s (Status: %s)",
        event_id,
        receipt.transaction_id,
        receipt.status,
    )

    node1.storage.close()
    return receipt.transaction_id


def step_consensus(cluster_dir: Path) -> None:
    """Execute a coordinated BFT consensus round across all 4 nodes."""
    logger.info("Executing BFT consensus round across 4 validator nodes...")
    nodes = [load_node(cluster_dir / f"node-{i}") for i in range(1, 5)]

    # Node-1 coordinates the round execution
    finalized_block = nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    for n in nodes:
        n.storage.close()

    if finalized_block:
        logger.info(
            "Consensus round SUCCESS: Committed Block %d (hash: %s) with %d transactions.",
            finalized_block.header.height,
            finalized_block.header.block_hash,
            len(finalized_block.transactions),
        )
    else:
        logger.warning("Consensus round did not finalize a new block.")


def verify_cluster_integrity(cluster_dir: Path) -> None:
    """Run verify_chain on each validator node database to check for local tampering."""
    logger.info("Verifying cryptographic chain integrity across all nodes...")
    for i in range(1, 5):
        node_dir = cluster_dir / f"node-{i}"
        node = load_node(node_dir)
        try:
            passed = node.verify_chain()
            if passed:
                logger.info(
                    "node-%d: [PASS] Chain verification clean from genesis to height %d.",
                    i,
                    node.storage.get_latest_height(),
                )
        except Exception as e:
            logger.error("node-%d: [FAIL] Cryptographic integrity violation detected: %s", i, e)
        finally:
            node.storage.close()


def simulate_byzantine_fault(cluster_dir: Path) -> None:
    """Simulate f=1 Byzantine failure (1 offline node) to verify 3/4 quorum commitment."""
    logger.info("Simulating f=1 Byzantine failure: 1 validator OFFLINE out of 4...")

    # Inject transaction to node 1
    inject_transaction(cluster_dir)

    # Reload node 1 to pick up tx in fresh instance
    node1 = load_node(cluster_dir / "node-1")
    peer_nodes = [load_node(cluster_dir / "node-2"), load_node(cluster_dir / "node-3")]

    # Consensus with only 3 nodes (3 of 4 satisfies 2f+1 quorum)
    blk = node1.step_consensus_round(peer_nodes=peer_nodes)

    for n in [node1] + peer_nodes:
        n.storage.close()

    if blk:
        logger.info("f=1 Fault Tolerance VERIFIED: Block %d finalized with 3/4 validators!", blk.header.height)
    else:
        logger.error("f=1 Fault Tolerance FAILED: Unable to commit block with 3/4 validators.")


def main() -> None:
    parser = argparse.ArgumentParser(description="TraceCrypt BFT Ledger Cluster Runner")
    parser.add_argument("--cluster-dir", type=Path, default=DEFAULT_CLUSTER_DIR, help="Base directory for cluster")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize 4-node cluster and genesis")
    subparsers.add_parser("status", help="Inspect status of all 4 validator nodes")
    subparsers.add_parser("inject", help="Inject a new signed DecryptionEvent transaction")
    subparsers.add_parser("step", help="Step consensus to commit mempool transactions into a block")
    subparsers.add_parser("verify", help="Verify cryptographic chain integrity on all node databases")
    subparsers.add_parser("simulate-failure", help="Simulate f=1 offline validator to test BFT quorum")

    args = parser.parse_args()

    if args.command == "init":
        init_cluster(args.cluster_dir, DEFAULT_CHAIN_ID)
    elif args.command == "status":
        cluster_status(args.cluster_dir)
    elif args.command == "inject":
        inject_transaction(args.cluster_dir)
    elif args.command == "step":
        step_consensus(args.cluster_dir)
    elif args.command == "verify":
        verify_cluster_integrity(args.cluster_dir)
    elif args.command == "simulate-failure":
        simulate_byzantine_fault(args.cluster_dir)


if __name__ == "__main__":
    main()
