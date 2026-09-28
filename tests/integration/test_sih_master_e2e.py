"""Master End-to-End Golden Path and Negative Security Tests for SIH 2026.

Conforms to Master Prompt 14 Sections 35 and 36:
1. test_sih_master_e2e_golden_path:
   Initialize identities -> create synthetic document -> encrypt for Alice + Bob + Charlie
   -> Alice decrypts -> Bob decrypts -> Charlie decrypts -> verify visible equivalence
   -> verify watermark uniqueness -> verify signed events -> verify ledger entries
   -> simulate Alice leak -> extract watermark -> verify ledger proof -> verify ML-DSA signature
   -> verify document binding -> produce VERIFIED attribution to Alice.

2. test_sih_master_e2e_negative_attacks:
   - Tamper watermark / recipient framing -> signature verification rejects
   - Associate watermark with different document -> DOCUMENT_MISMATCH
   - Signature bit-flip corruption -> CRYPTOGRAPHIC_SIGNATURE_INVALID
   - Replay attack on ledger -> ReplayAttackError
"""

import pytest
from pathlib import Path

from tracecrypt.demo.engine import SIHDemoEngine
from tracecrypt.models.domain import VerdictEnum


@pytest.mark.integration
def test_sih_master_e2e_golden_path(tmp_path: Path):
    """Execute complete end-to-end golden path from PKI init to blind forensic attribution."""
    engine = SIHDemoEngine(base_dir=tmp_path)

    # 1. Initialize Identities (Root CA, 3 Recipients, 4 Validators)
    init_res = engine.init_environment()
    assert init_res["root_ca"]["ca_id"] == "ca-sih2026-root"
    assert len(init_res["recipients"]) == 3
    assert len(init_res["validators"]) == 4

    # 2. Encrypt Synthetic Document for Alice + Bob + Charlie
    enc_res = engine.encrypt_document()
    assert Path(enc_res["package_path"]).exists()
    assert enc_res["envelopes_count"] == 3
    assert enc_res["package_size_bytes"] > 0

    # 3. Alice Decrypts (DWT-DCT Watermark, ML-DSA-65 Sig, BFT Ledger Commit)
    alice_res = engine.decrypt_for_recipient("alice")
    assert Path(alice_res["output_pdf"]).exists()
    assert alice_res["watermark_id"].startswith("wm-")
    assert alice_res["committed_block_height"] >= 1
    assert alice_res["fidelity"]["psnr_db"] >= 38.0
    assert alice_res["fidelity"]["ssim"] >= 0.88

    # 4. Bob Decrypts
    bob_res = engine.decrypt_for_recipient("bob")
    assert Path(bob_res["output_pdf"]).exists()
    assert bob_res["watermark_id"].startswith("wm-")
    assert bob_res["committed_block_height"] > alice_res["committed_block_height"]

    # 5. Charlie Decrypts
    charlie_res = engine.decrypt_for_recipient("charlie")
    assert Path(charlie_res["output_pdf"]).exists()
    assert charlie_res["watermark_id"].startswith("wm-")
    assert charlie_res["committed_block_height"] > bob_res["committed_block_height"]

    # 6. Verify Watermark Uniqueness & Cryptographic Differentiation
    assert alice_res["watermark_id"] != bob_res["watermark_id"]
    assert bob_res["watermark_id"] != charlie_res["watermark_id"]
    assert alice_res["session_id"] != bob_res["session_id"]
    assert alice_res["event_id"] != bob_res["event_id"]

    # 7. Verify Visual Equivalence (PSNR / SSIM)
    comp_res = engine.compare_decrypted_copies()
    assert comp_res["cryptographic_differentiation"]["watermark_ids_differ"] is True
    assert comp_res["visual_identicality"]["alice_vs_bob"]["psnr_db"] >= 35.0
    assert comp_res["visual_identicality"]["alice_vs_bob"]["ssim"] >= 0.88

    # 8. Simulate Alice Document Leak
    leak_res = engine.leak_document("alice")
    assert Path(leak_res["evidence_path"]).exists()
    assert leak_res["leaked_by_recipient"] == "alice"

    # 9. Blind Forensic Extraction & Attribution (No original document needed)
    inv_res = engine.investigate_leak(evidence_path=leak_res["evidence_path"])
    assert inv_res["verdict"] == VerdictEnum.VERIFIED.value
    assert "a11ce" in inv_res["attributed_recipient_id"]
    assert "Alice" in inv_res["attributed_recipient_name"]
    assert inv_res["ledger"]["merkle_proof_valid"] is True
    assert inv_res["ledger"]["commit_certificate_valid"] is True
    assert inv_res["ledger"]["quorum_satisfied"] is True
    assert inv_res["cryptography"]["mldsa_signature_valid"] is True
    assert inv_res["cryptography"]["document_binding_valid"] is True
    assert inv_res["standalone_verification"]["standalone_verified"] is True
    assert inv_res["standalone_verification"]["recomputed_verdict"] == VerdictEnum.VERIFIED.value


@pytest.mark.integration
def test_sih_master_e2e_negative_attacks(tmp_path: Path):
    """Execute adversarial attacks: identity framing, wrong doc binding, sig bitflip, replay."""
    engine = SIHDemoEngine(base_dir=tmp_path)

    # Setup baseline environment and initial Alice decryption
    engine.init_environment()
    engine.encrypt_document()
    engine.decrypt_for_recipient("alice")
    engine.leak_document("alice")

    # 1. Tampering Attacks (Framing, Wrong Document Binding, Corrupted ML-DSA-65 Signature)
    tamper_res = engine.demonstrate_tampering()
    # Vector 1: Identity framing rejected
    assert tamper_res["vector_1_identity_framing"]["signature_valid"] is False
    assert "REJECTED" in tamper_res["vector_1_identity_framing"]["verdict"]

    # Vector 2: Wrong document binding rejected (DOCUMENT_MISMATCH)
    assert tamper_res["vector_2_wrong_document_binding"]["document_binding_valid"] is False
    assert "DOCUMENT_MISMATCH" in tamper_res["vector_2_wrong_document_binding"]["verdict"]

    # Vector 3: Corrupted signature rejected
    assert tamper_res["vector_3_tampered_signature"]["signature_valid"] is False
    assert "CRYPTOGRAPHIC_SIGNATURE_INVALID" in tamper_res["vector_3_tampered_signature"]["verdict"]

    # 2. Replay Attack Rejected
    replay_res = engine.demonstrate_replay()
    assert replay_res["replay_blocked"] is True
    assert "ReplayAttackError" in replay_res["submission_result"]
    assert "Replay rejected" in replay_res["error_message"]

    # 3. Byzantine Fault Tolerance (4-Node Cluster, f=1 tolerance)
    bft_res = engine.demonstrate_bft()
    assert bft_res["normal_consensus"]["commit_votes"] == 4
    assert bft_res["fault_tolerant_consensus"]["commit_votes"] == 3
    assert bft_res["state_catch_up"]["state_match"] is True
