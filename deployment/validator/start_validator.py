#!/usr/bin/env python3
"""Validator Node Runner Script for TraceCrypt.

Environment D: Validator Nodes (n=4, f=1 BFT Consensus Network)
- Runs offline Tendermint-style BFT consensus loop
- Propose -> Prevote -> Precommit -> Finalize
- Maintains SQLite WAL replicated ledger storage
- Provides Merkle inclusion proofs for committed attribution events
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.types import MLDSAPrivateKey
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.node import BFTLedgerNode
from tracecrypt.ledger.validator import NodeRole
from tracecrypt.utils.identifiers import ValidatorID

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("validator_node")


def main() -> int:
    parser = argparse.ArgumentParser(description="Start TraceCrypt Validator Node")
    parser.add_argument("--node-dir", "-d", required=True, help="Path to validator node directory")
    args = parser.parse_args()

    node_dir = Path(args.node_dir)
    if not node_dir.exists():
        logger.error("Node directory does not exist: %s", node_dir)
        return 1

    genesis = GenesisConfig.model_validate_json((node_dir / "genesis.json").read_text(encoding="utf-8"))
    key_data = json.loads((node_dir / "validator_key.json").read_text(encoding="utf-8"))
    config_data = json.loads((node_dir / "node_config.json").read_text(encoding="utf-8"))

    val_id = ValidatorID(key_data["validator_id"])
    sk = MLDSAPrivateKey.from_b64(key_data["private_key_b64"])
    peers = [(p[0], int(p[1])) for p in config_data.get("peers", [])]

    logger.info("Initializing BFT Validator Node: %s (Listen: %s:%d)", val_id, config_data["listen_host"], config_data["listen_port"])
    node = BFTLedgerNode(
        validator_id=val_id,
        private_key=sk,
        genesis=genesis,
        data_dir=node_dir,
        listen_host=config_data.get("listen_host", "127.0.0.1"),
        listen_port=int(config_data.get("listen_port", 9101)),
        peers=peers,
        role=NodeRole.VALIDATOR,
    )

    logger.info("Validator node started. Press Ctrl+C to terminate.")
    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        logger.info("Stopping validator node...")
        asyncio.run(node.stop())
    return 0


if __name__ == "__main__":
    sys.exit(main())
