"""Production-grade full system smoke test for TraceCrypt.

Validates the entire end-to-end operational pipeline:
1. Configuration & Security Invariants
2. Post-Quantum PKI (OfflineRootCA, ML-DSA-65 and ML-KEM-768 certificates)
3. Document Package (.tcdist) Hybrid Encryption (ML-KEM-768 + AES-256-GCM)
4. Recipient Decapsulation, Decryption, Session Generation
5. Transform-Domain DWT-DCT Invisible Forensic Watermark Embedding
6. RFC 8785 Canonical Decryption Audit Event Creation
7. NIST FIPS 204 ML-DSA-65 Event Digital Signature
8. Permissioned BFT Ledger Commit & Merkle Tree Inclusion Proof
9. Blind Watermark Extraction from Leaked Artifact (no original document needed)
10. Forensic Engine Evaluation producing deterministic VERIFIED verdict
11. Cryptographic Proof Bundle (.tcproof) Generation & Standalone Verification
12. Air-Gapped Backup Creation (.tcbackup), Checksum Verification & Restore
13. Database Schema Integrity Check & Migration Engine
"""

from __future__ import annotations

import io
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.config.settings import get_settings
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import WatermarkParameters, WatermarkPayload
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.ledger.block import Block, BlockHeader, LedgerTransaction
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import CommitCertificate, VoteMessage, VoteType
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import ValidatorInfo, ValidatorSet
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.types import ForensicVerdict
from tracecrypt.forensics.standalone_verifier import StandaloneProofVerifier
from tracecrypt.storage.backup import BackupManager
from tracecrypt.storage.migration import DatabaseMigrationManager
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    TransactionID,
    ValidatorID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.version import get_system_versions, APPLICATION_VERSION, PROTOCOL_VERSION


def _create_sample_pdf() -> bytes:
    """Generate in-memory test PDF document."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(2):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 720, f"TraceCrypt Production Smoke Test Document - Page {p + 1}")
        c.setFont("Helvetica", 10)
        c.drawString(72, 690, "RESTRICTED DISTRIBUTION - POST-QUANTUM FORENSIC MARKED")
        for line in range(12):
            msg = f"Operational test record line {p * 12 + line}: Deterministic blind watermark verification payload."
            c.drawString(72, 650 - line * 20, msg)
        c.showPage()
    c.save()
    return buf.getvalue()


class SmokeTestRunner:
    """Executes all smoke test stages and returns structured results."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose
        self.stages: List[Dict[str, Any]] = []

    def _log(self, stage_num: int, name: str, status: str, details: str = "") -> None:
        self.stages.append({"stage": stage_num, "name": name, "status": status, "details": details})
        if self.verbose:
            tag = "[PASS]" if status == "PASS" else "[FAIL]"
            print(f" {tag} Stage {stage_num:02d}: {name:<45} | {details}")

    def run(self) -> bool:
        """Run all verification stages. Returns True if all pass, False otherwise."""
        if self.verbose:
            print("=" * 78)
            print("           TRACECRYPT PRODUCTION RELEASE SMOKE TEST           ")
            print("=" * 78)

        temp_dir = Path(tempfile.mkdtemp(prefix="tracecrypt_smoke_"))
        all_passed = True

        try:
            # Stage 1: System Version & Invariants
            try:
                versions = get_system_versions()
                assert versions.application_version == APPLICATION_VERSION
                assert versions.protocol_version == PROTOCOL_VERSION
                settings = get_settings()
                settings.validate_security_invariants()
                self._log(1, "System Versions & Security Invariants", "PASS", f"App={versions.application_version}, Mode={settings.mode.value}")
            except Exception as e:
                self._log(1, "System Versions & Security Invariants", "FAIL", str(e))
                all_passed = False

            # Stage 2: Post-Quantum PKI Generation (Offline Root CA & Recipient Certs)
            try:
                root_ca = OfflineRootCA.initialize("ca-smoke-root")
                recip_id = RecipientID.generate()
                kem_pk, kem_sk = generate_mlkem_keypair()
                kem_cert = root_ca.issue_kem_certificate(
                    subject_id=str(recip_id),
                    public_key=kem_pk,
                    organization="Operations Unit",
                    role="Recipient",
                )
                dsa_pk, dsa_sk = generate_mldsa_keypair()
                dsa_cert = root_ca.issue_signing_certificate(
                    subject_id=str(recip_id),
                    public_key=dsa_pk,
                    organization="Operations Unit",
                    role="Recipient",
                )
                self._log(2, "Post-Quantum PKI (ML-DSA Root CA & Recipient)", "PASS", f"CA initialized, Recipient={recip_id}")
            except Exception as e:
                self._log(2, "Post-Quantum PKI (ML-DSA Root CA & Recipient)", "FAIL", str(e))
                all_passed = False

            # Stage 3: Document Packaging (.tcdist ML-KEM + AES-256-GCM)
            try:
                pdf_bytes = _create_sample_pdf()
                dist_pkg, _ = DistributionService.package_document(
                    source_input=pdf_bytes,
                    filename="briefing.pdf",
                    recipients=[RecipientSpec(kem_cert)],
                )
                pkg_bytes = dist_pkg.to_bytes()
                pkg_path = temp_dir / "briefing.tcdist"
                pkg_path.write_bytes(pkg_bytes)
                doc_hash = DocumentHasher.hash_bytes(pdf_bytes)
                self._log(3, "Hybrid Packaging (.tcdist ML-KEM + AES-GCM)", "PASS", f"Pkg size={len(pkg_bytes)}B, DocHash={doc_hash[:18]}...")
            except Exception as e:
                self._log(3, "Hybrid Packaging (.tcdist ML-KEM + AES-GCM)", "FAIL", str(e))
                all_passed = False

            # Stage 4: Recipient Decapsulation & Plaintext Decryption
            try:
                from tracecrypt.crypto.types import MLKEMPrivateKey

                decrypted_buf = DistributionService.decrypt_package(
                    package_input=dist_pkg,
                    recipient_id=recip_id,
                    recipient_sk=MLKEMPrivateKey(kem_sk),
                    recipient_cert=kem_cert,
                )
                assert decrypted_buf.raw_bytes == pdf_bytes
                self._log(4, "Recipient Decapsulation & Decryption", "PASS", f"Plaintext verified ({decrypted_buf.size_bytes} bytes)")
            except Exception as e:
                self._log(4, "Recipient Decapsulation & Decryption", "FAIL", str(e))
                all_passed = False

            # Stage 5: Transform-Domain DWT-DCT Watermark Embedding
            try:
                wmid = WatermarkID.generate()
                sid = SessionID.generate()
                payload = WatermarkPayload.create(
                    watermark_id=wmid,
                    session_id=sid,
                    document_hash=doc_hash,
                )
                embed_res = WatermarkEmbedder.embed_document(
                    pdf_input=pdf_bytes,
                    payload=payload,
                    document_hash=doc_hash,
                    params=WatermarkParameters(embedding_strength=8.0),
                )
                leaked_path = temp_dir / "leaked_briefing.pdf"
                leaked_path.write_bytes(embed_res.watermarked_pdf)
                self._log(5, "Transform-Domain DWT-DCT Watermarking", "PASS", f"Watermark embedded (size={len(embed_res.watermarked_pdf)} bytes)")
            except Exception as e:
                self._log(5, "Transform-Domain DWT-DCT Watermarking", "FAIL", str(e))
                all_passed = False

            # Stage 6: RFC 8785 Canonical Event & ML-DSA-65 Signature
            try:
                event = DecryptionEvent(
                    event_version="1.0.0",
                    schema_version="1.0.0",
                    protocol_version="1.0.0",
                    software_version="1.0.0",
                    event_type="DECRYPTION_ATTRIBUTION",
                    event_id=EventID.generate(),
                    document_id=DocumentID.generate(),
                    distribution_id=DistributionID.generate(),
                    document_hash=doc_hash,
                    recipient_id=recip_id,
                    recipient_certificate_id=dsa_cert.serial_number,
                    session_id=sid,
                    watermark_id=wmid,
                    watermark_version=1,
                    anti_replay_nonce=SecureRandom.random_nonce_128(),
                    timestamp=utc_now_micros(),
                    pqc_algorithms=PQCAlgorithms(),
                )
                signed_evt = DecryptionEventSigner.sign_event(
                    event=event,
                    signing_key=dsa_sk,
                    signing_cert=dsa_cert,
                )
                assert signed_evt.signature is not None
                self._log(6, "Canonical Event & ML-DSA-65 Signature", "PASS", f"EventID={event.event_id}, Sig={len(signed_evt.signature)}B")
            except Exception as e:
                self._log(6, "Canonical Event & ML-DSA-65 Signature", "FAIL", str(e))
                all_passed = False

            # Stage 7: BFT Distributed Ledger Commit & Storage
            try:
                # Set up data directories
                data_dir = temp_dir / "data"
                ledger_dir = data_dir / "ledger"
                keys_dir = data_dir / "keys"
                ledger_dir.mkdir(parents=True, exist_ok=True)
                keys_dir.mkdir(parents=True, exist_ok=True)

                (keys_dir / "recipient_dsa_cert.json").write_text(dsa_cert.to_canonical_json(), encoding="utf-8")
                (keys_dir / "recipient_kem_cert.json").write_text(kem_cert.to_canonical_json(), encoding="utf-8")

                # 4-validator cluster setup
                val_infos: List[ValidatorInfo] = []
                val_keys: Dict[ValidatorID, Tuple[bytes, bytes]] = {}
                for i in range(4):
                    vid = ValidatorID.generate()
                    v_pk, v_sk = generate_mldsa_keypair()
                    val_keys[vid] = (v_pk, v_sk)
                    v_cert = root_ca.issue_validator_certificate(str(vid), v_pk, "Ledger Consortium", "Validator")
                    val_infos.append(ValidatorInfo.from_certificate(vid, v_cert, voting_power=1))

                val_set = ValidatorSet(validators=val_infos)
                ledger_db = ledger_dir / "ledger_smoke.db"
                storage = LedgerStorage(ledger_db)

                genesis = GenesisConfig(
                    chain_id="tracecrypt-smoke-chain",
                    genesis_time=utc_now_micros(),
                    validator_set=val_set,
                    initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                storage.save_genesis(genesis)
                state = LedgerState(chain_id=genesis.chain_id, initial_state_root=genesis.initial_state_root)

                tx = LedgerTransaction.from_signed_event(
                    transaction_id=TransactionID.generate(),
                    signed_event=signed_evt,
                    submitted_at=utc_now_micros(),
                    recipient_certificate=dsa_cert,
                )
                state.apply_transaction(tx)
                state_root = state.compute_state_root()
                tx_root = MerkleTree.build_merkle_root([tx.to_canonical_bytes()])
                now = utc_now_micros()

                header_proto = BlockHeader(
                    chain_id=state.chain_id,
                    height=1,
                    round=0,
                    previous_block_hash="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
                    timestamp=now,
                    proposer_id=val_set.validators[0].validator_id,
                    transaction_root=tx_root,
                    state_root=state_root,
                    validator_set_hash=val_set.compute_hash(),
                    protocol_version="1.0.0",
                    block_hash="",
                )
                b_hash = header_proto.compute_block_hash()
                header = header_proto.model_copy(update={"block_hash": b_hash})

                votes: List[VoteMessage] = []
                for vid in list(val_keys.keys())[:3]:
                    _, sk = val_keys[vid]
                    v = VoteMessage.create_and_sign(
                        chain_id=state.chain_id,
                        height=1,
                        round=0,
                        vote_type=VoteType.PRECOMMIT,
                        block_hash=b_hash,
                        validator_id=vid,
                        signing_key=sk,
                        timestamp=now,
                    )
                    votes.append(v)

                commit_cert = CommitCertificate(
                    chain_id=state.chain_id,
                    height=1,
                    round=0,
                    block_hash=b_hash,
                    validator_set_hash=val_set.compute_hash(),
                    votes=votes,
                )
                block = Block(header=header, transactions=[tx], commit_certificate=commit_cert)
                storage.save_block(block)

                inclusion_proof = storage.export_merkle_proof(tx.transaction_id)
                assert inclusion_proof is not None
                self._log(7, "BFT Ledger Commit & Merkle Inclusion Proof", "PASS", f"Height=1, tx={tx.transaction_id}")
            except Exception as e:
                self._log(7, "BFT Ledger Commit & Merkle Inclusion Proof", "FAIL", str(e))
                all_passed = False

            # Stage 8: Blind Watermark Extraction (No pristine document)
            try:
                engine = ForensicInvestigationEngine(
                    ledger_storage=storage,
                    root_ca_public_key=root_ca.public_key,
                )
                inv = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)
                assert inv.verdict == ForensicVerdict.VERIFIED
                assert inv.watermark_analysis.consensus_watermark_id == wmid
                assert inv.identity_details.recipient_id == recip_id
                self._log(8, "Blind Watermark Extraction & Investigation", "PASS", f"Verdict={inv.verdict.value} (Attributed: {recip_id})")
            except Exception as e:
                self._log(8, "Blind Watermark Extraction & Investigation", "FAIL", str(e))
                all_passed = False

            # Stage 9: Cryptographic Proof Bundle & Standalone Verification
            try:
                proof_file = temp_dir / "case_proof.tcproof"
                proof_bundle = engine.export_proof_bundle(inv, output_path=proof_file)
                verifier = StandaloneProofVerifier()
                v_res = verifier.verify(proof_bundle)
                if not v_res.verified or not v_res.verdict_matches:
                    fail_detail = f"verified={v_res.verified}, verdict_matches={v_res.verdict_matches}, errors={v_res.errors}, checks={v_res.checks}"
                    raise AssertionError(fail_detail)
                self._log(9, "Cryptographic Proof Bundle (.tcproof)", "PASS", f"Standalone verified (Admissible={v_res.verified})")
            except Exception as e:
                import traceback
                self._log(9, "Cryptographic Proof Bundle (.tcproof)", "FAIL", f"{e} | {traceback.format_exc().splitlines()[-2]}")
                all_passed = False

            # Stage 10: Air-Gapped Backup & Restore Engine
            try:
                # Initialize a dummy local db for completeness
                import sqlite3
                conn = sqlite3.connect(str(data_dir / "tracecrypt_local.db"))
                conn.execute("CREATE TABLE test_tab (id INT);")
                conn.commit()
                conn.close()

                backup_mgr = BackupManager(data_dir=data_dir)
                backup_file = temp_dir / "smoke_backup.tcbackup"
                backup_mgr.create_backup(output_path=backup_file, include_keystores=False)
                v_backup = backup_mgr.verify_backup(backup_file)
                assert v_backup["status"] == "VALID"
                restore_dir = temp_dir / "restored_data"
                r_res = backup_mgr.restore_backup(backup_file, target_dir=restore_dir)
                assert r_res["status"] == "RESTORED"
                self._log(10, "Air-Gapped Backup & Restore (.tcbackup)", "PASS", f"Components={v_backup['total_components']}, Restored")
            except Exception as e:
                self._log(10, "Air-Gapped Backup & Restore (.tcbackup)", "FAIL", str(e))
                all_passed = False

            # Stage 11: Database Schema & Migration Engine
            try:
                mig_mgr = DatabaseMigrationManager(restore_dir / "tracecrypt_local.db")
                integ = mig_mgr.check_integrity()
                from_v, to_v = mig_mgr.migrate()
                integ_post = mig_mgr.check_integrity()
                assert integ_post["is_healthy"] is True
                self._log(11, "Database Schema & Migration Engine", "PASS", f"Migrated {from_v}->{to_v}, Status={integ_post['status']}")
            except Exception as e:
                self._log(11, "Database Schema & Migration Engine", "FAIL", str(e))
                all_passed = False

            # Summary Evaluation
            if self.verbose:
                print("=" * 78)
                verdict_str = "SMOKE TEST PASSED (All 11 subsystem stages operational)" if all_passed else "SMOKE TEST FAILED"
                print(f"RESULT: {verdict_str}")
                print("=" * 78)

            return all_passed

        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass


def run_smoke_test() -> int:
    """Entry point for CLI smoke test."""
    runner = SmokeTestRunner(verbose=True)
    success = runner.run()
    return 0 if success else 1
