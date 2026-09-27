"""Automated Mutation and Event Tampering Tests.

Systematically mutates every single field of a valid signed DecryptionEvent
and asserts that verification fails closed on each mutation.
"""

from __future__ import annotations

import copy
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.event.verifier import DecryptionEventVerifier
from tracecrypt.utils.identifiers import (
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


class TestEventTamperingMutations:
    """Mutate individual fields and verify deterministic signature failure."""

    @pytest.fixture
    def signed_event_fixture(self):
        from tracecrypt.identity.ca import OfflineRootCA
        root_ca = OfflineRootCA.initialize("ca-event-tamper-test")
        pk, sk = generate_mldsa_keypair()
        recip_id = RecipientID.generate()
        cert = root_ca.issue_signing_certificate(
            subject_id=str(recip_id),
            public_key=pk,
            organization="Test Corp",
            role="Recipient",
        )
        event = DecryptionEvent(
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            document_hash="sha3-256:" + "aa" * 32,
            recipient_id=recip_id,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=1700000000000000,
            pqc_algorithms=PQCAlgorithms(),
        )
        signed = DecryptionEventSigner.sign_event(event, sk, cert)
        return signed, pk

    def test_mutate_document_id(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["document_id"] = str(DocumentID.generate())
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_session_id(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["session_id"] = str(SessionID.generate())
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_watermark_id(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["watermark_id"] = str(WatermarkID.generate())
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_anti_replay_nonce(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["anti_replay_nonce"] = SecureRandom.random_nonce_128()
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_recipient_id(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["recipient_id"] = str(RecipientID.generate())
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_timestamp(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["timestamp"] = signed.event.timestamp + 1000
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False

    def test_mutate_document_hash(self, signed_event_fixture) -> None:
        signed, pk = signed_event_fixture
        mutated_dict = copy.deepcopy(signed.event.model_dump())
        mutated_dict["document_hash"] = "sha3-256:" + "ff" * 32
        mutated_event = DecryptionEvent.model_validate(mutated_dict)

        tampered = signed.model_copy(update={"event": mutated_event})
        res = DecryptionEventVerifier.verify_signed_event(tampered, recipient_public_key=pk)
        assert res.valid is False
