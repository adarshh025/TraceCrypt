"""Cryptographic Verification Pipeline for TraceCrypt Forensic Investigation.

Executes a 12-point deterministic verification pipeline:
1. Re-computes Merkle inclusion proof from transaction canonical bytes to block transaction root.
2. Validates block header integrity, hash self-consistency, and chain linkage.
3. Validates BFT commit certificate signatures against authorized validator set and quorum.
4. Validates recipient identity certificate against Offline Root CA and revocation state.
5. Reconstructs RFC 8785 canonical JSON bytes and SHA3-256 event digest.
6. Verifies recipient NIST FIPS 204 ML-DSA-65 digital signature.
7. Verifies cryptographic document binding and session tag.
"""

from __future__ import annotations

import base64
from typing import Any, List, Optional

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.pqc_dsa import MLDSAProvider
from tracecrypt.crypto.types import KeyPurpose, MLDSAPublicKey, MLDSASignature
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.forensics.types import (
    DocumentBindingDetails,
    IdentityVerificationDetails,
    LedgerVerificationDetails,
)
from tracecrypt.identity.certificate import CertificateValidator
from tracecrypt.ledger.block import Block, LedgerTransaction
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.validator import ValidatorSet
from tracecrypt.watermark.types import WatermarkPayload


class ForensicCryptographicVerifier:
    """Rigorous offline cryptographic verifier for forensic evidence attribution."""

    @classmethod
    def verify_ledger_proof(
        cls,
        tx: LedgerTransaction,
        block: Block,
        previous_block: Optional[Block],
        validator_set: ValidatorSet,
    ) -> LedgerVerificationDetails:
        """Verify transaction Merkle inclusion proof, block integrity, and commit certificate."""
        errors: List[str] = []

        # 1. Block Header Hash verification
        recomputed_hash = block.header.compute_block_hash()
        block_hash_valid = (recomputed_hash == block.header.block_hash)
        if not block_hash_valid:
            errors.append(
                f"Block {block.header.height} hash self-consistency failed: "
                f"header says {block.header.block_hash}, recomputed {recomputed_hash}"
            )

        # 2. Chain linkage verification
        chain_linkage_valid = True
        if block.header.height > 1:
            if previous_block is None:
                errors.append(f"Previous block for height {block.header.height} is missing")
                chain_linkage_valid = False
            elif block.header.previous_block_hash != previous_block.header.block_hash:
                errors.append(
                    f"Chain break at height {block.header.height}: previous_block_hash "
                    f"'{block.header.previous_block_hash}' != '{previous_block.header.block_hash}'"
                )
                chain_linkage_valid = False

        # 3. Merkle inclusion proof
        merkle_proof_valid = False
        try:
            leaf_bytes_list = [t.to_canonical_bytes() for t in block.transactions]
            tx_canonical_bytes = tx.to_canonical_bytes()

            # Find transaction index in block
            match_index = -1
            for idx, candidate in enumerate(leaf_bytes_list):
                if candidate == tx_canonical_bytes:
                    match_index = idx
                    break

            if match_index == -1:
                errors.append(
                    f"Transaction '{tx.transaction_id}' bytes not found in block {block.header.height} transactions"
                )
            else:
                proof = MerkleTree.generate_merkle_proof(match_index, leaf_bytes_list)
                leaf_hash = MerkleTree.compute_leaf_hash(tx_canonical_bytes)
                merkle_proof_valid = MerkleTree.verify_merkle_proof(
                    leaf_hash, proof, block.header.transaction_root
                )
                if not merkle_proof_valid:
                    errors.append(
                        f"Merkle inclusion proof failed to verify against block transaction_root "
                        f"'{block.header.transaction_root}'"
                    )
        except Exception as e:
            errors.append(f"Merkle proof evaluation exception: {e}")

        # 4. Commit Certificate & BFT Quorum verification
        commit_cert_valid = False
        quorum_satisfied = False
        verified_validators: List[str] = []

        cert = block.commit_certificate
        if cert is None:
            errors.append(f"Block at height {block.header.height} lacks a CommitCertificate")
        else:
            if cert.block_hash != block.header.block_hash:
                errors.append(
                    f"Commit certificate commits to '{cert.block_hash}', but block hash is '{block.header.block_hash}'"
                )
            if cert.height != block.header.height:
                errors.append(
                    f"Commit certificate height {cert.height} != block height {block.header.height}"
                )

            # Verify validator signatures
            try:
                for vote in cert.votes:
                    val = validator_set.get_validator(vote.validator_id)
                    if not val:
                        errors.append(
                            f"Commit certificate contains vote from unauthorized validator '{vote.validator_id}'"
                        )
                        continue
                    if vote.verify_signature(val.get_public_key()):
                        verified_validators.append(str(vote.validator_id))
                    else:
                        errors.append(
                            f"Commit certificate signature verification failed for validator '{vote.validator_id}'"
                        )

                # Quorum check
                unique_verified = len(set(verified_validators))
                if unique_verified >= validator_set.quorum:
                    commit_cert_valid = True
                    quorum_satisfied = True
                else:
                    errors.append(
                        f"Commit certificate quorum not satisfied: verified {unique_verified} "
                        f"validators, but quorum threshold is {validator_set.quorum}"
                    )
            except Exception as e:
                errors.append(f"Commit certificate validation exception: {e}")

        return LedgerVerificationDetails(
            transaction_id=str(tx.transaction_id),
            block_height=block.header.height,
            block_hash=block.header.block_hash,
            merkle_proof_valid=merkle_proof_valid,
            block_valid=block_hash_valid,
            chain_linkage_valid=chain_linkage_valid,
            commit_certificate_valid=commit_cert_valid,
            quorum_satisfied=quorum_satisfied,
            validator_count=len(validator_set.validators),
            verified_validators=verified_validators,
            errors=errors,
        )

    @classmethod
    def verify_recipient_identity_and_signature(
        cls,
        tx: LedgerTransaction,
        root_ca_public_key: Optional[MLDSAPublicKey] = None,
        revocation_provider: Optional[Any] = None,
    ) -> IdentityVerificationDetails:
        """Verify recipient identity certificate, revocation state, and ML-DSA-65 event signature."""
        errors: List[str] = []
        signed_event = tx.signed_event
        event = signed_event.event
        cert = tx.recipient_certificate

        cert_valid = False
        key_purpose_valid = False
        not_revoked = False
        sig_verified = False
        canonical_digest: Optional[str] = None

        # 1. Certificate Validation
        if cert is None:
            errors.append("Transaction lacks recipient certificate")
        else:
            if cert.key_purpose != KeyPurpose.DIGITAL_SIGNATURE:
                errors.append(
                    f"Recipient certificate has key purpose '{cert.key_purpose}', "
                    f"strictly required: DIGITAL_SIGNATURE"
                )
            else:
                key_purpose_valid = True

            try:
                # 11-point offline certificate validation
                CertificateValidator.validate(
                    certificate=cert,
                    root_ca_public_key=root_ca_public_key,
                    revocation_provider=revocation_provider,
                    expected_purpose=KeyPurpose.DIGITAL_SIGNATURE,
                )
                cert_valid = True
                not_revoked = True
            except Exception as e:
                errors.append(f"Certificate validation failed: {e}")

        # 2. Canonical JSON & SHA3-256 Digest Reconstruction
        try:
            canonical_dict = event.to_canonical_dict()
            canonical_bytes = canonicalize(canonical_dict)
            canonical_digest = Hasher.digest_bytes(
                canonical_bytes, HashAlgorithm.SHA3_256.value
            ).formatted

            if canonical_digest != signed_event.event_digest:
                errors.append(
                    f"Canonical event digest mismatch: stored '{signed_event.event_digest}', "
                    f"reconstructed '{canonical_digest}'"
                )
        except Exception as e:
            errors.append(f"Event canonicalization failed: {e}")
            canonical_bytes = b""

        # 3. ML-DSA-65 Signature Verification
        if cert and canonical_bytes:
            try:
                provider = MLDSAProvider()
                cert_pk = MLDSAPublicKey(cert.get_public_key_bytes())
                sig_raw = base64.b64decode(signed_event.signature, validate=True)
                sig_obj = MLDSASignature(sig_raw)

                if provider.verify(cert_pk, canonical_bytes, sig_obj):
                    sig_verified = True
                else:
                    errors.append("Recipient ML-DSA-65 signature mathematical verification failed.")
            except Exception as e:
                errors.append(f"Signature verification exception: {e}")

        return IdentityVerificationDetails(
            recipient_id=event.recipient_id,
            certificate_id=cert.serial_number if cert else None,
            certificate_valid=cert_valid,
            key_purpose_valid=key_purpose_valid,
            not_revoked=not_revoked,
            canonical_event_digest=canonical_digest,
            signature_verified=sig_verified,
            signing_algorithm=cert.algorithm if cert else "ML-DSA-65",
            errors=errors,
        )

    @classmethod
    def verify_document_binding(
        cls,
        watermark_payload: WatermarkPayload,
        tx: LedgerTransaction,
        expected_document_hash: Optional[str] = None,
    ) -> DocumentBindingDetails:
        """Verify that the extracted watermark payload cryptographically binds to the transaction event."""
        errors: List[str] = []
        event = tx.signed_event.event

        # 1. WatermarkID consistency
        if str(watermark_payload.watermark_id) != str(event.watermark_id):
            errors.append(
                f"WatermarkID mismatch: extracted '{watermark_payload.watermark_id}' "
                f"!= event '{event.watermark_id}'"
            )

        # 2. Session tag consistency
        expected_tag = WatermarkPayload.compute_session_tag(event.session_id)
        if watermark_payload.session_tag != expected_tag:
            errors.append(
                f"Session tag mismatch: extracted '{watermark_payload.session_tag.hex()}' "
                f"!= expected '{expected_tag.hex()}'"
            )

        # 3. Document binding verification
        binding_matched = watermark_payload.verify_document_binding(
            event.document_hash, event.session_id
        )
        if not binding_matched:
            expected_binding = WatermarkPayload.compute_document_binding(
                event.document_hash, event.session_id, watermark_payload.watermark_id
            )
            errors.append(
                f"Watermark document binding '{watermark_payload.document_binding.hex()}' "
                f"does not match expected '{expected_binding.hex()}' for document '{event.document_hash}'"
            )

        # 4. Expected document hash verification if provided
        doc_hash_matched = True
        if expected_document_hash is not None:
            norm_expected = expected_document_hash.lower().strip()
            norm_event = event.document_hash.lower().strip()
            if norm_expected != norm_event:
                errors.append(
                    f"Document hash mismatch: expected '{norm_expected}', "
                    f"event committed '{norm_event}'"
                )
                doc_hash_matched = False

        binding_verified = binding_matched and doc_hash_matched and len(errors) == 0

        return DocumentBindingDetails(
            binding_verified=binding_verified,
            event_document_hash=event.document_hash,
            expected_document_hash=expected_document_hash,
            document_hash_matched=doc_hash_matched,
            watermark_binding_matched=binding_matched,
            errors=errors,
        )
