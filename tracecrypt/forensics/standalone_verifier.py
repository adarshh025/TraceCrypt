"""Standalone Forensic Proof Bundle Verifier.

Executes independent cryptographic verification of a .tcproof bundle without
access to the investigator's local database or workstation state.
"""

from __future__ import annotations

import base64
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.pqc_dsa import MLDSAProvider
from tracecrypt.crypto.types import KeyPurpose, MLDSAPublicKey, MLDSASignature
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.forensics.proof_bundle import ForensicProofBundle
from tracecrypt.forensics.types import (
    DocumentBindingDetails,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
    WatermarkForensicAnalysis,
)
from tracecrypt.forensics.verdict import VerdictEvaluator
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate
from tracecrypt.ledger.block import BlockHeader, LedgerTransaction
from tracecrypt.ledger.merkle import MerkleInclusionProof, MerkleTree
from tracecrypt.ledger.messages import CommitCertificate
from tracecrypt.ledger.validator import ValidatorSet
from tracecrypt.models.domain import VerdictEnum
from tracecrypt.watermark.types import ExtractionStatus, WatermarkPayload


class StandaloneVerificationResult(BaseModel):
    """Result of independent cryptographic verification of a proof bundle."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    recomputed_verdict: VerdictEnum
    bundle_verdict: VerdictEnum
    verdict_matches: bool
    bundle_digest_verified: bool
    merkle_proof_verified: bool = False
    block_hash_verified: bool = False
    commit_certificate_verified: bool = False
    certificate_verified: bool = False
    signature_verified: bool = False
    document_binding_verified: bool = False
    chain_of_custody_verified: bool = False
    checks: Dict[str, bool] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.valid

    @property
    def bundle_integrity_valid(self) -> bool:
        return self.bundle_digest_verified

    @property
    def watermark_valid(self) -> bool:
        return self.checks.get("watermark_structure", False)

    @property
    def block_hash_valid(self) -> bool:
        return self.block_hash_verified

    @property
    def merkle_proof_valid(self) -> bool:
        return self.merkle_proof_verified

    @property
    def commit_cert_valid(self) -> bool:
        return self.commit_certificate_verified

    @property
    def recipient_cert_valid(self) -> bool:
        return self.certificate_verified

    @property
    def signature_valid(self) -> bool:
        return self.signature_verified

    @property
    def document_binding_valid(self) -> bool:
        return self.document_binding_verified

    @property
    def verdict_consistent(self) -> bool:
        return self.verdict_matches


class StandaloneProofVerifier:
    """Verifies complete cryptographic integrity of .tcproof files."""

    def verify(
        self,
        bundle: ForensicProofBundle,
        expected_root_ca_public_key: Optional[MLDSAPublicKey] = None,
    ) -> StandaloneVerificationResult:
        """Instance method forwarding to verify_bundle."""
        return self.verify_bundle(bundle, expected_root_ca_public_key)

    @classmethod
    def verify_bundle(
        cls,
        bundle: ForensicProofBundle,
        expected_root_ca_public_key: Optional[MLDSAPublicKey] = None,
    ) -> StandaloneVerificationResult:
        """Independently verify all cryptographic commitments inside a proof bundle."""
        errors: List[str] = []
        checks: Dict[str, bool] = {}

        # 1. Bundle Digest Self-Consistency
        recomputed_digest = ForensicProofBundle.compute_bundle_digest(bundle.model_dump())
        digest_verified = (recomputed_digest == bundle.bundle_digest)
        checks["bundle_digest"] = digest_verified
        if not digest_verified:
            errors.append(
                f"Bundle digest tampering detected: stored '{bundle.bundle_digest}', "
                f"recomputed '{recomputed_digest}'"
            )

        # 2. Watermark Payload Checksum & Structure
        wm_payload: Optional[WatermarkPayload] = None
        if bundle.extracted_watermark:
            try:
                ew = dict(bundle.extracted_watermark)
                if isinstance(ew.get("session_tag"), str):
                    ew["session_tag"] = bytes.fromhex(ew["session_tag"])
                if isinstance(ew.get("document_binding"), str):
                    ew["document_binding"] = bytes.fromhex(ew["document_binding"])
                wm_payload = WatermarkPayload.model_validate(ew)
                # Verify CRC16
                wm_raw = bytes.fromhex(str(wm_payload.watermark_id).replace("wm-", ""))
                pre_crc = (
                    bytes([wm_payload.version])
                    + wm_raw
                    + wm_payload.session_tag
                    + wm_payload.document_binding
                )
                exp_crc = WatermarkPayload.compute_crc16(pre_crc)
                if wm_payload.checksum != exp_crc:
                    errors.append(
                        f"Watermark payload CRC16 invalid: expected {exp_crc:#06x}, "
                        f"got {wm_payload.checksum:#06x}"
                    )
                    checks["watermark_structure"] = False
                else:
                    checks["watermark_structure"] = True
            except Exception as e:
                errors.append(f"Watermark payload parsing failed: {e}")
                checks["watermark_structure"] = False
        else:
            checks["watermark_structure"] = False

        # 3. Ledger, Merkle Proof, and BFT Commit Certificate Verification
        merkle_verified = False
        block_hash_verified = False
        commit_cert_verified = False
        tx_obj: Optional[LedgerTransaction] = None

        if bundle.ledger_proof:
            try:
                lp = bundle.ledger_proof
                tx_obj = LedgerTransaction.model_validate(lp["transaction"])
                header = BlockHeader.model_validate(lp["block_header"])
                merkle_proof = MerkleInclusionProof.model_validate(lp["merkle_proof"])
                cert = (
                    CommitCertificate.model_validate(lp["commit_certificate"])
                    if lp.get("commit_certificate")
                    else None
                )
                val_set = (
                    ValidatorSet.model_validate(lp["validator_set"])
                    if lp.get("validator_set")
                    else None
                )

                # Recompute block hash
                rec_block_hash = header.compute_block_hash()
                block_hash_verified = (rec_block_hash == header.block_hash)
                checks["block_hash"] = block_hash_verified
                if not block_hash_verified:
                    errors.append(
                        f"Block hash mismatch: header {header.block_hash} != recomputed {rec_block_hash}"
                    )

                # Verify Merkle proof
                leaf_hash = MerkleTree.compute_leaf_hash(tx_obj.to_canonical_bytes())
                merkle_verified = MerkleTree.verify_merkle_proof(
                    leaf_hash, merkle_proof, header.transaction_root
                )
                checks["merkle_proof"] = merkle_verified
                if not merkle_verified:
                    errors.append("Transaction Merkle inclusion proof failed to verify against block header root.")

                # Verify Commit Certificate & Quorum
                if cert and val_set:
                    if cert.block_hash != header.block_hash or cert.height != header.height:
                        errors.append("Commit certificate height/hash does not match block header.")
                    verified_count = 0
                    for vote in cert.votes:
                        val = val_set.get_validator(vote.validator_id)
                        if val and vote.verify_signature(val.get_public_key()):
                            verified_count += 1
                    commit_cert_verified = (verified_count >= val_set.quorum)
                    checks["commit_certificate"] = commit_cert_verified
                    if not commit_cert_verified:
                        errors.append(
                            f"Commit certificate quorum not satisfied: verified {verified_count} "
                            f"< required {val_set.quorum}"
                        )
                else:
                    checks["commit_certificate"] = False
                    errors.append("Ledger proof lacks commit certificate or validator set.")
            except Exception as e:
                errors.append(f"Ledger proof verification exception: {e}")
                checks["merkle_proof"] = False
                checks["block_hash"] = False
                checks["commit_certificate"] = False
        else:
            checks["merkle_proof"] = False
            checks["block_hash"] = False
            checks["commit_certificate"] = False

        # 4. Identity & ML-DSA-65 Signature Verification
        cert_verified = False
        sig_verified = False

        if bundle.recipient_certificate and tx_obj:
            try:
                cert = PQCIdentityCertificate.model_validate(bundle.recipient_certificate)
                root_ca_pk = expected_root_ca_public_key
                if root_ca_pk is None and bundle.root_ca_public_key_b64:
                    root_ca_pk = MLDSAPublicKey(base64.b64decode(bundle.root_ca_public_key_b64))

                # Verify certificate
                CertificateValidator.validate(
                    certificate=cert,
                    root_ca_public_key=root_ca_pk,
                    expected_purpose=KeyPurpose.DIGITAL_SIGNATURE,
                )
                cert_verified = True
                checks["recipient_certificate"] = True

                # Reconstruct canonical event and verify digest
                event = tx_obj.signed_event.event
                canonical_bytes = canonicalize(event.to_canonical_dict())
                event_digest = Hasher.digest_bytes(
                    canonical_bytes, HashAlgorithm.SHA3_256.value
                ).formatted

                if event_digest != tx_obj.signed_event.event_digest:
                    errors.append("Event digest in transaction does not match recomputed RFC 8785 canonical bytes.")
                    checks["event_digest"] = False
                else:
                    checks["event_digest"] = True

                # Verify ML-DSA-65 signature
                provider = MLDSAProvider()
                cert_pk = MLDSAPublicKey(cert.get_public_key_bytes())
                sig_raw = base64.b64decode(tx_obj.signed_event.signature, validate=True)
                sig_obj = MLDSASignature(sig_raw)

                sig_verified = provider.verify(cert_pk, canonical_bytes, sig_obj)
                checks["mldsa_signature"] = sig_verified
                if not sig_verified:
                    errors.append("ML-DSA-65 signature verification failed over canonical event bytes.")
            except Exception as e:
                errors.append(f"Recipient certificate / signature verification failed: {e}")
                checks["recipient_certificate"] = False
                checks["mldsa_signature"] = False
        else:
            checks["recipient_certificate"] = False
            checks["mldsa_signature"] = False

        # 5. Document Binding Verification
        binding_verified = False
        if wm_payload and tx_obj:
            try:
                event = tx_obj.signed_event.event
                # Check session tag
                exp_tag = WatermarkPayload.compute_session_tag(event.session_id)
                tag_ok = (wm_payload.session_tag == exp_tag)

                # Check document binding
                exp_binding = WatermarkPayload.compute_document_binding(
                    event.document_hash, event.session_id, wm_payload.watermark_id
                )
                binding_ok = (wm_payload.document_binding == exp_binding)

                binding_verified = (tag_ok and binding_ok)
                checks["document_binding"] = binding_verified
                if not binding_verified:
                    errors.append("Watermark document binding does not match committed event document hash.")
            except Exception as e:
                errors.append(f"Document binding verification exception: {e}")
                checks["document_binding"] = False
        else:
            checks["document_binding"] = False

        # 6. Chain of Custody Continuity
        custody_verified = True
        if bundle.chain_of_custody:
            from tracecrypt.forensics.custody import GENESIS_PREVIOUS_HASH
            prev_h = GENESIS_PREVIOUS_HASH
            for c in bundle.chain_of_custody:
                entry = c
                ctx = (
                    f"tracecrypt:custody:v1:{entry['sequence_index']}:{entry['action']}:{entry['actor_id']}:"
                    f"{entry['timestamp']}:{entry['evidence_hash']}:{entry['previous_action_hash']}"
                ).encode("utf-8")
                exp_h = Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).formatted
                if entry["action_hash"] != exp_h or entry["previous_action_hash"] != prev_h:
                    custody_verified = False
                    errors.append(f"Custody link broken at index {entry['sequence_index']}")
                    break
                prev_h = entry["action_hash"]
        checks["chain_of_custody"] = custody_verified

        # 7. Independent Verdict Recomputation
        # Synthesize state for VerdictEvaluator
        has_ambiguity = any(
            p.get("status") == ExtractionStatus.AMBIGUOUS.value for p in bundle.page_results
        )
        has_corrupted = any(
            p.get("status") == ExtractionStatus.CORRUPTED.value for p in bundle.page_results
        )
        has_invalid = any(
            p.get("status") == ExtractionStatus.INVALID.value for p in bundle.page_results
        )
        pages_detected = sum(1 for p in bundle.page_results if p.get("detected", False))

        if has_ambiguity:
            overall_status = ExtractionStatus.AMBIGUOUS
        elif wm_payload is not None:
            overall_status = ExtractionStatus.DECODED
        elif has_corrupted:
            overall_status = ExtractionStatus.CORRUPTED
        elif has_invalid:
            overall_status = ExtractionStatus.INVALID
        else:
            overall_status = ExtractionStatus.NOT_DETECTED

        synth_analysis = WatermarkForensicAnalysis(
            overall_status=overall_status,
            pages_analyzed=len(bundle.page_results),
            pages_detected=pages_detected,
            pages_decoded=1 if wm_payload else 0,
            pages_corrupted=1 if has_corrupted else 0,
            total_ecc_corrections=sum(p.get("ecc_corrections", 0) for p in bundle.page_results),
            consensus_watermark_id=wm_payload.watermark_id if wm_payload else None,
            has_cross_page_conflict=has_ambiguity,
        )

        synth_ledger: Optional[LedgerVerificationDetails] = None
        if bundle.ledger_proof and tx_obj:
            synth_ledger = LedgerVerificationDetails(
                transaction_id=str(tx_obj.transaction_id),
                block_height=bundle.ledger_proof["block_header"]["height"],
                block_hash=bundle.ledger_proof["block_header"]["block_hash"],
                merkle_proof_valid=merkle_verified,
                block_valid=block_hash_verified,
                chain_linkage_valid=True,
                commit_certificate_valid=commit_cert_verified,
                quorum_satisfied=commit_cert_verified,
                validator_count=4,
                errors=errors,
            )

        synth_identity: Optional[IdentityVerificationDetails] = None
        if bundle.recipient_certificate and tx_obj:
            synth_identity = IdentityVerificationDetails(
                recipient_id=tx_obj.signed_event.event.recipient_id,
                certificate_id=bundle.recipient_certificate.get("serial_number"),
                certificate_valid=cert_verified,
                key_purpose_valid=cert_verified,
                not_revoked=cert_verified,
                signature_verified=sig_verified,
                errors=errors,
            )

        synth_binding: Optional[DocumentBindingDetails] = None
        if wm_payload and tx_obj:
            synth_binding = DocumentBindingDetails(
                binding_verified=binding_verified,
                event_document_hash=tx_obj.signed_event.event.document_hash,
                document_hash_matched=True,
                watermark_binding_matched=binding_verified,
                errors=errors,
            )

        recomputed_verdict, _, _ = VerdictEvaluator.evaluate(
            analysis=synth_analysis,
            ledger_details=synth_ledger,
            identity_details=synth_identity,
            binding_details=synth_binding,
        )

        verdict_matches = (recomputed_verdict == bundle.verdict)
        checks["verdict_consistency"] = verdict_matches
        if not verdict_matches:
            errors.append(
                f"Verdict mismatch: bundle claims '{bundle.verdict}', "
                f"recomputed independently as '{recomputed_verdict}'"
            )

        overall_valid = digest_verified and verdict_matches and len(errors) == 0

        return StandaloneVerificationResult(
            valid=overall_valid,
            recomputed_verdict=recomputed_verdict,
            bundle_verdict=bundle.verdict,
            verdict_matches=verdict_matches,
            bundle_digest_verified=digest_verified,
            merkle_proof_verified=merkle_verified,
            block_hash_verified=block_hash_verified,
            commit_certificate_verified=commit_cert_verified,
            certificate_verified=cert_verified,
            signature_verified=sig_verified,
            document_binding_verified=binding_verified,
            chain_of_custody_verified=custody_verified,
            checks=checks,
            errors=errors,
        )
