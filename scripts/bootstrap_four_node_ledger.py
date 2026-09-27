#!/usr/bin/env python3
"""Offline 4-Node Permissioned BFT Ledger Cluster Bootstrapper for TraceCrypt.

Satisfies Section 15 of Master Prompt 11:
- Independent identity for each of the 4 validator nodes (validator-1 .. validator-4)
- Independent ML-DSA-65 consensus keypair per validator
- Independent storage database (ledger.db) per validator
- Explicit air-gapped peer configuration (127.0.0.1:9101-9104, no discovery)
- Same canonical GenesisConfig (chain ID, initial state root, validator set)
- Deterministic validator set with n=4, f=1 Byzantine fault tolerance
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

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.types import MLDSAPrivateKey
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.node import BFTLedgerNode
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.version import APPLICATION_VERSION, LEDGER_VERSION, PROTOCOL_VERSION

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bootstrap_four_node_ledger")

DEFAULT_PORTS = [9101, 9102, 9103, 9104]


def bootstrap_cluster(
    cluster_dir: Path,
    chain_id: str = "tracecrypt-airgap-1",
    ports: List[int] | None = None,
) -> GenesisConfig:
    """Bootstrap a complete 4-node permissioned BFT network offline."""
    if ports is None:
        ports = DEFAULT_PORTS

    if len(ports) != 4:
        raise ValueError(f"Exactly 4 ports required for 4-node BFT cluster, got {len(ports)}")

    cluster_dir = Path(cluster_dir)
    cluster_dir.mkdir(parents=True, exist_ok=True)
    logger.info("============================================================")
    logger.info("BOOTSTRAPPING 4-NODE TRACECRYPT BFT LEDGER CLUSTER")
    logger.info("Cluster Directory: %s", cluster_dir)
    logger.info("Chain ID:          %s", chain_id)
    logger.info("Consensus Rules:   n=4, f=1, Quorum=3")
    logger.info("============================================================")

    # 1. Initialize dedicated Consensus Root CA
    ca = OfflineRootCA.initialize(ca_id="ca-root-consensus-offline")
    ca_dir = cluster_dir / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "consensus_ca_info.json").write_text(
        json.dumps({
            "ca_id": ca.ca_id,
            "public_key_b64": ca.public_key.to_b64(),
            "fingerprint": ca.fingerprint,
        }, indent=2),
        encoding="utf-8",
    )
    logger.info("[1/5] Consensus Root CA initialized (Fingerprint: %s)", ca.fingerprint[:16])

    validator_infos: List[ValidatorInfo] = []
    node_configs = []

    # 2. Provision 4 separate validator nodes
    logger.info("[2/5] Generating 4 validator identities and ML-DSA-65 consensus keypairs...")
    for i in range(1, 5):
        node_name = f"node-{i}"
        node_dir = cluster_dir / node_name
        node_dir.mkdir(parents=True, exist_ok=True)

        # Clear any prior database files for clean bootstrap
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

        # Write private key and certificate
        key_file = node_dir / "validator_key.json"
        key_file.write_text(
            json.dumps({
                "validator_id": str(val_id),
                "node_name": node_name,
                "private_key_b64": sk.to_b64(),
            }, indent=2),
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
            "node_name": node_name,
            "node_index": i,
            "validator_id": str(val_id),
            "port": ports[i - 1],
            "dir": node_dir,
            "sk": sk,
        })
        logger.info("  * Node %s provisioned: %s (Port: %d)", node_name, val_id, ports[i - 1])

    # 3. Create canonical GenesisConfig
    logger.info("[3/5] Computing canonical genesis configuration...")
    val_set = ValidatorSet(validators=validator_infos)
    genesis = GenesisConfig(
        chain_id=chain_id,
        protocol_version=PROTOCOL_VERSION,
        ledger_version=str(LEDGER_VERSION),
        genesis_time=utc_now_micros(),
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    genesis.validate_genesis()
    genesis_hash = genesis.compute_genesis_hash()
    logger.info("  Canonical Genesis Hash: %s", genesis_hash)

    # Save genesis.json to cluster root
    genesis_json = genesis.model_dump_json(indent=2)
    (cluster_dir / "genesis.json").write_text(genesis_json, encoding="utf-8")

    # 4. Configure each node with peer routing and genesis
    logger.info("[4/5] Establishing explicit air-gapped peer routing matrices...")
    for cfg in node_configs:
        n_dir: Path = cfg["dir"]
        (n_dir / "genesis.json").write_text(genesis_json, encoding="utf-8")

        my_port = cfg["port"]
        peers = [("127.0.0.1", p) for p in ports if p != my_port]
        node_meta = {
            "node_name": cfg["node_name"],
            "chain_id": chain_id,
            "validator_id": cfg["validator_id"],
            "listen_host": "127.0.0.1",
            "listen_port": my_port,
            "peers": peers,
            "protocol_version": PROTOCOL_VERSION,
            "application_version": APPLICATION_VERSION,
        }
        (n_dir / "node_config.json").write_text(json.dumps(node_meta, indent=2), encoding="utf-8")

        # Initialize SQLite WAL ledger database with Genesis
        storage = LedgerStorage(n_dir / "ledger.db")
        storage.save_genesis(genesis)
        storage.close()

    # 5. Verify all node databases
    logger.info("[5/5] Performing startup verification across all 4 node databases...")
    for cfg in node_configs:
        n_dir = cfg["dir"]
        storage = LedgerStorage(n_dir / "ledger.db")
        saved_gen = storage.get_genesis()
        if saved_gen is None or saved_gen.compute_genesis_hash() != genesis_hash:
            raise RuntimeError(f"Genesis verification failed on {cfg['node_name']}")
        storage.verify_chain(val_set)
        storage.close()

    logger.info("============================================================")
    logger.info("4-NODE BFT CLUSTER BOOTSTRAP SUCCEEDED (READY FOR CONSENSUS)")
    logger.info("============================================================")
    return genesis


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap 4-node TraceCrypt BFT ledger offline")
    parser.add_argument("--cluster-dir", "-d", default="deployment/validator/cluster", help="Target cluster root directory")
    parser.add_argument("--chain-id", default="tracecrypt-airgap-1", help="Chain identifier")
    parser.add_argument("--ports", nargs=4, type=int, default=DEFAULT_PORTS, help="4 TCP ports for the validators")
    args = parser.parse_args()

    try:
        bootstrap_cluster(
            cluster_dir=Path(args.cluster_dir),
            chain_id=args.chain_id,
            ports=args.ports,
        )
        return 0
    except Exception as e:
        logger.error("Failed to bootstrap cluster: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
