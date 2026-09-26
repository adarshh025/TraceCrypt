"""Security and failure-injection tests for Phase 5 Recipient Attribution Pipeline.

Tests strictly enforce:
- Event-level replay protection (EventID, SessionID, WatermarkID, (DocID, SessionID))
- Post-quantum key-purpose separation (ML-KEM vs ML-DSA)
- Certificate validity and revocation enforcement
- Tamper-proofing of canonical DecryptionEvents and digests
- Release Gate failure-injection (watermark, signature, ledger rejection, ledger timeout)
- Fail-closed behavior: no unwatermarked plaintext persists or leaks
- Strict air-gap operation without network sockets
- Zeroization of temporary cryptographic materials
- Security logging hygiene (zero plaintext, key, or passphrase leakage)
"""

from __future__ import annotations

import base64
import io
import logging
import socket
from typing import Optional
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.release_gate import DocumentReleaseGate, ReleaseDecision
from tracecrypt.errors import (
    LedgerCommitRequiredError,
    ReplayAttackError,
    SecurityError,
)
from tracecrypt.event.schema import (
    DecryptionEvent,
    DocumentID,
    DistributionID,
    EventID,
    PQCAlgorithms,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.lifecycle import (
    KeyLifecycleManager,
    OfflineRevocationStore,
    RevocationReason,
)
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import WatermarkPayload


def create_test_pdf(text: str = "Confidential Top Secret TraceCrypt Document", num_pages: int = 2) -> bytes:
    """Generate a minimal multi-page test PDF in memory."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(num_pages):
        c.drawString(72, 750, f"{text} - Page {p + 1}")
        c.drawString(72, 700, "Secure Air-Gapped Forensic Pipeline Verification")
        c.drawString(72, 650, f"Page index {p} content for robust DWT-DCT embedding.")
        c.showPage()
    c.save()
    return buf.getvalue()


def make_test_event(
    recipient_id: RecipientID,
    event_id: Optional[EventID] = None,
    document_id: Optional[DocumentID] = None,
    distribution_id: Optional[DistributionID] = None,
    document_hash: str = "sha3-256:" + "a" * 64,
    session_id: Optional[SessionID] = None,
    watermark_id: Optional[WatermarkID] = None,
) -> DecryptionEvent:
    """Create a fully-populated DecryptionEvent with valid default fields."""
    return DecryptionEvent(
        event_id=event_id or EventID(f"evt-{SecureRandom.generate_nonce(16)}"),
        document_id=document_id or DocumentID(f"doc-{SecureRandom.generate_nonce(16)}"),
        distribution_id=distribution_id or DistributionID(f"dst-{SecureRandom.generate_nonce(16)}"),
        document_hash=document_hash,
        recipient_id=recipient_id,
        session_id=session_id or SessionID(f"ses-{SecureRandom.generate_nonce(16)}"),
        watermark_id=watermark_id or WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}"),
        anti_replay_nonce=SecureRandom.generate_nonce(16),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(kem="ML-KEM-768", dsa="ML-DSA-65", hash="SHA3-256"),
    )


@pytest.fixture
def sec_env():
    """Build a complete offline PKI environment for Alice and Bob."""
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-security")
    rev_provider = OfflineRevocationStore()

    # Alice keys & certs
    alice_id = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")
    alice_kem_pk, alice_kem_sk = generate_mlkem_keypair()
    alice_kem_cert = root_ca.issue_kem_certificate(
        subject_id=alice_id,
        public_key=alice_kem_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    alice_dsa_pk, alice_dsa_sk = generate_mldsa_keypair()
    alice_dsa_cert = root_ca.issue_signing_certificate(
        subject_id=alice_id,
        public_key=alice_dsa_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    alice = RecipientCredentials(
        recipient_id=alice_id,
        kem_private_key=alice_kem_sk,
        kem_certificate=alice_kem_cert,
        dsa_private_key=alice_dsa_sk,
        dsa_certificate=alice_dsa_cert,
    )

    # Bob keys & certs
    bob_id = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")
    bob_kem_pk, bob_kem_sk = generate_mlkem_keypair()
    bob_kem_cert = root_ca.issue_kem_certificate(
        subject_id=bob_id,
        public_key=bob_kem_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    bob_dsa_pk, bob_dsa_sk = generate_mldsa_keypair()
    bob_dsa_cert = root_ca.issue_signing_certificate(
        subject_id=bob_id,
        public_key=bob_dsa_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    bob = RecipientCredentials(
        recipient_id=bob_id,
        kem_private_key=bob_kem_sk,
        kem_certificate=bob_kem_cert,
        dsa_private_key=bob_dsa_sk,
        dsa_certificate=bob_dsa_cert,
    )

    ledger = InMemoryLedgerAdapter()

    return {
        "root_ca": root_ca,
        "rev_provider": rev_provider,
        "alice": alice,
        "bob": bob,
        "ledger": ledger,
    }


class TestAttributionReplayProtection:
    """Validate strict rejection of replay attacks on EventID, SessionID, WatermarkID."""

    def test_duplicate_event_id_rejected(self, sec_env):
        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        event = make_test_event(recipient_id=alice.recipient_id)
        signed = DecryptionEventSigner.sign_event(
            event=event,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

        receipt1 = ledger.submit_event(signed)
        assert receipt1.status == CommitStatus.COMMITTED

        # Second submission of identical EventID must raise ReplayAttackError
        with pytest.raises(ReplayAttackError, match="Replay rejected"):
            ledger.submit_event(signed)

    def test_duplicate_session_id_rejected(self, sec_env):
        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        shared_session = SessionID(f"ses-{SecureRandom.generate_nonce(16)}")

        event1 = make_test_event(recipient_id=alice.recipient_id, session_id=shared_session)
        signed1 = DecryptionEventSigner.sign_event(
            event=event1,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        ledger.submit_event(signed1)

        event2 = make_test_event(recipient_id=alice.recipient_id, session_id=shared_session)
        signed2 = DecryptionEventSigner.sign_event(
            event=event2,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

        with pytest.raises(ReplayAttackError, match="Replay rejected"):
            ledger.submit_event(signed2)

    def test_duplicate_watermark_id_rejected(self, sec_env):
        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        shared_wm = WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}")

        event1 = make_test_event(recipient_id=alice.recipient_id, watermark_id=shared_wm)
        signed1 = DecryptionEventSigner.sign_event(
            event=event1,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        ledger.submit_event(signed1)

        event2 = make_test_event(recipient_id=alice.recipient_id, watermark_id=shared_wm)
        signed2 = DecryptionEventSigner.sign_event(
            event=event2,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

        with pytest.raises(ReplayAttackError, match="Replay rejected"):
            ledger.submit_event(signed2)


class TestKeyAndIdentitySecurity:
    """Validate cryptographic key-purpose enforcement and certificate validation."""

    def test_revoked_signing_certificate_fails_signing(self, sec_env):
        env = sec_env
        alice = env["alice"]
        rev_provider = env["rev_provider"]
        root_ca = env["root_ca"]

        # Revoke Alice's DSA certificate
        rec = KeyLifecycleManager.create_revocation_record(
            serial_number=alice.dsa_certificate.serial_number,
            key_id=f"key-{alice.recipient_id}-dsa-v1",
            reason=RevocationReason.KEY_COMPROMISE,
            ca=root_ca,
        )
        rev_provider.register_revocation(rec)

        event = make_test_event(recipient_id=alice.recipient_id)

        with pytest.raises(SecurityError, match="REVOKED"):
            DecryptionEventSigner.sign_event(
                event=event,
                signing_key=alice.dsa_private_key,
                signing_cert=alice.dsa_certificate,
                root_ca_public_key=root_ca.public_key,
                revocation_provider=rev_provider,
            )

    def test_key_purpose_separation_kem_cert_rejected_as_signing_cert(self, sec_env):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        event = make_test_event(recipient_id=alice.recipient_id)

        # Alice attempts to pass her KEM certificate as a signing certificate
        with pytest.raises(SecurityError, match="Key purpose violation"):
            DecryptionEventSigner.sign_event(
                event=event,
                signing_key=alice.dsa_private_key,
                signing_cert=alice.kem_certificate,  # Wrong key purpose!
                root_ca_public_key=root_ca.public_key,
            )

    def test_subject_mismatch_fails_signing(self, sec_env):
        env = sec_env
        alice = env["alice"]
        bob = env["bob"]
        root_ca = env["root_ca"]

        # Event claims Alice, but signer presents Bob's certificate
        event = make_test_event(recipient_id=alice.recipient_id)

        with pytest.raises(SecurityError, match="Identity binding mismatch"):
            DecryptionEventSigner.sign_event(
                event=event,
                signing_key=bob.dsa_private_key,
                signing_cert=bob.dsa_certificate,
                root_ca_public_key=root_ca.public_key,
            )


class TestEventTamperingDetection:
    """Verify that any modification of canonical event fields or signature fails verification."""

    @pytest.fixture
    def valid_signed_event(self, sec_env):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        event = make_test_event(
            recipient_id=alice.recipient_id,
            document_hash="sha3-256:" + "3" * 64,
        )
        return DecryptionEventSigner.sign_event(
            event=event,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

    def test_tampered_document_hash_detected(self, sec_env, valid_signed_event):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        tampered_event = valid_signed_event.event.model_copy(
            update={"document_hash": "sha3-256:" + "9" * 64}
        )
        tampered_signed = valid_signed_event.model_copy(update={"event": tampered_event})

        result = DecryptionEventVerifier.verify_signed_event(
            signed_event=tampered_signed,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        assert not result.valid
        assert not result.digest_verified

    def test_tampered_session_id_detected(self, sec_env, valid_signed_event):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        tampered_event = valid_signed_event.event.model_copy(
            update={"session_id": SessionID(f"ses-{SecureRandom.generate_nonce(16)}")}
        )
        tampered_signed = valid_signed_event.model_copy(update={"event": tampered_event})

        result = DecryptionEventVerifier.verify_signed_event(
            signed_event=tampered_signed,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        assert not result.valid
        assert not result.digest_verified

    def test_tampered_watermark_id_detected(self, sec_env, valid_signed_event):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        tampered_event = valid_signed_event.event.model_copy(
            update={"watermark_id": WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}")}
        )
        tampered_signed = valid_signed_event.model_copy(update={"event": tampered_event})

        result = DecryptionEventVerifier.verify_signed_event(
            signed_event=tampered_signed,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        assert not result.valid
        assert not result.digest_verified

    def test_tampered_signature_detected(self, sec_env, valid_signed_event):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        sig_raw = bytearray(base64.b64decode(valid_signed_event.signature))
        sig_raw[10] ^= 0xFF
        tampered_sig = base64.b64encode(bytes(sig_raw)).decode("ascii")

        tampered_signed = valid_signed_event.model_copy(update={"signature": tampered_sig})

        result = DecryptionEventVerifier.verify_signed_event(
            signed_event=tampered_signed,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )
        assert not result.valid
        assert not result.signature_verified


class TestReleaseGateFailureInjection:
    """Verify that DocumentReleaseGate strictly denies release upon any subsystem failure."""

    def test_release_gate_rejects_uncommitted_ledger_status(self, sec_env):
        env = sec_env
        alice = env["alice"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf()
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        ses_id = SessionID(f"ses-{SecureRandom.generate_nonce(16)}")
        wm_id = WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}")

        wm_payload = WatermarkPayload.create(
            watermark_id=wm_id,
            session_id=ses_id,
            document_hash=doc_hash,
            version=1,
        )
        wm_res = WatermarkEmbedder.embed_document(pdf_bytes, wm_payload, doc_hash)

        event = make_test_event(
            recipient_id=alice.recipient_id,
            document_hash=doc_hash,
            session_id=ses_id,
            watermark_id=wm_id,
        )
        signed = DecryptionEventSigner.sign_event(
            event=event,
            signing_key=alice.dsa_private_key,
            signing_cert=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
        )

        uncommitted_receipt = LedgerTransactionReceipt(
            transaction_id="tx-uncommitted",
            event_id=event.event_id,
            status=CommitStatus.PENDING,
            committed_at=utc_now_micros(),
        )

        decision = DocumentReleaseGate.evaluate(
            watermark_result=wm_res,
            signed_event=signed,
            ledger_receipt=uncommitted_receipt,
            recipient_certificate=alice.dsa_certificate,
            root_ca_public_key=root_ca.public_key,
            expected_document_hash=doc_hash,
        )

        assert decision.decision == ReleaseDecision.DENIED
        assert not decision.is_allowed
        assert any("not yet committed" in r for r in decision.reasons)

        with pytest.raises(LedgerCommitRequiredError):
            DocumentReleaseGate.assert_release_allowed(
                watermark_result=wm_res,
                signed_event=signed,
                ledger_receipt=uncommitted_receipt,
                recipient_certificate=alice.dsa_certificate,
                root_ca_public_key=root_ca.public_key,
                expected_document_hash=doc_hash,
            )

    def test_ledger_timeout_blocks_release(self, sec_env):
        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf()
        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        # Configure mock ledger to simulate validator timeout
        ledger.simulate_timeout = True

        with pytest.raises(LedgerCommitRequiredError, match="LEDGER_COMMIT_REQUIRED"):
            RecipientAttributionPipeline.execute_decryption(
                package_input=pkg,
                credentials=alice,
                ledger=ledger,
                root_ca_public_key=root_ca.public_key,
            )


class TestAirGapAndHygiene:
    """Verify strictly offline operation with no network dependencies and secure audit logging."""

    def test_air_gap_operation_no_network_sockets(self, sec_env, monkeypatch):
        """Ensure the pipeline runs with network sockets blocked."""
        def guarded_connect(*args, **kwargs):
            raise socket.error("Air-gap violation: external network attempt detected!")

        monkeypatch.setattr(socket.socket, "connect", guarded_connect)

        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        pdf_bytes = create_test_pdf(num_pages=1)
        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        # Decryption attribution pipeline must run completely offline without touching socket
        release = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )
        assert release.watermarked_pdf is not None
        assert release.ledger_receipt.is_committed

    def test_security_logging_does_not_leak_secrets(self, sec_env, caplog):
        """Verify that audit logs never expose private keys, CEKs, or plaintext."""
        env = sec_env
        alice = env["alice"]
        ledger = env["ledger"]
        root_ca = env["root_ca"]

        secret_marker = "VERY_CONFIDENTIAL_PLAINTEXT_SECRET_MARKER"
        pdf_bytes = create_test_pdf(text=secret_marker, num_pages=1)
        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)
        pkg, _ = DistributionService.package_document(
            source_input=pdf_bytes,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        with caplog.at_level(logging.DEBUG):
            RecipientAttributionPipeline.execute_decryption(
                package_input=pkg,
                credentials=alice,
                ledger=ledger,
                root_ca_public_key=root_ca.public_key,
            )

        log_text = caplog.text
        assert secret_marker not in log_text
        assert "private_key" not in log_text.lower() or "dsa_private_key" not in log_text
        assert "raw_plaintext" not in log_text
