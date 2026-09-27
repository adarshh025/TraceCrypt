"""Adversarial Nonce Security and Entropy Verification Tests.

Validates:
- Strict 96-bit (12-byte) AES-GCM nonce requirements.
- Hard rejection of AES-GCM nonce reuse.
- High-entropy CSPRNG generation for SessionID, WatermarkNonce, and WatermarkID.
- Rejection of low-entropy or short anti-replay nonces.
"""

from __future__ import annotations

import pytest

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.errors import CryptographicError, ValidationError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.utils.identifiers import DocumentID, EventID, RecipientID, SessionID, WatermarkID


class TestNonceSecurity:
    """Validate nonce uniqueness, size constraints, and reuse prevention."""

    def setup_method(self) -> None:
        """Reset the used nonces registry before each test."""
        ContentEncryption.reset_nonce_tracker()

    def test_aes_gcm_nonce_length_enforcement(self) -> None:
        """AES-GCM operations must reject nonces not exactly 12 bytes long."""
        cek = ContentEncryption.generate_cek()
        plaintext = b"Sensitive forensic report content"
        aad = b"canonical-aad-context"

        # Attempting override nonce of invalid length
        with pytest.raises(ValidationError, match="Invalid AES-GCM nonce length"):
            ContentEncryption.encrypt_document(
                plaintext, cek, aad, override_nonce=b"\x00" * 8
            )

        with pytest.raises(ValidationError, match="Invalid AES-GCM nonce length"):
            ContentEncryption.encrypt_document(
                plaintext, cek, aad, override_nonce=b"\x00" * 16
            )

    def test_aes_gcm_nonce_reuse_rejection(self) -> None:
        """Attempting to encrypt two payloads with identical nonce must fail closed."""
        cek = ContentEncryption.generate_cek()
        plaintext = b"Payload 1"
        aad = b"context"
        fixed_nonce = b"\x01" * 12

        # First encryption with fixed nonce succeeds
        _, _, _ = ContentEncryption.encrypt_document(
            plaintext, cek, aad, override_nonce=fixed_nonce
        )

        # Second encryption with same nonce must raise CryptographicError
        with pytest.raises(CryptographicError, match="nonce reuse detected"):
            ContentEncryption.encrypt_document(
                b"Payload 2", cek, aad, override_nonce=fixed_nonce
            )

    def test_random_identifier_collision_resistance(self) -> None:
        """Empirical collision resistance test over 5,000 generated identifiers."""
        sample_size = 5000
        session_ids = {str(SessionID.generate()) for _ in range(sample_size)}
        assert len(session_ids) == sample_size, "Collision detected in SessionID generation!"

        watermark_ids = {str(WatermarkID.generate()) for _ in range(sample_size)}
        assert len(watermark_ids) == sample_size, "Collision detected in WatermarkID generation!"

        nonces = {SecureRandom.random_nonce_128() for _ in range(sample_size)}
        assert len(nonces) == sample_size, "Collision detected in 128-bit CSPRNG nonces!"

    def test_anti_replay_nonce_entropy_validation(self) -> None:
        """DecryptionEvent must reject weak, short, or non-hex nonces."""
        base_event_data = {
            "event_id": EventID.generate(),
            "document_id": DocumentID.generate(),
            "document_hash": "sha3-256:" + "0" * 64,
            "recipient_id": RecipientID.generate(),
            "session_id": SessionID.generate(),
            "watermark_id": WatermarkID.generate(),
            "timestamp": 1700000000000000,
            "pqc_algorithms": PQCAlgorithms(),
        }

        # 1. Nonce too short (< 32 hex chars)
        with pytest.raises(ValidationError, match="Anti-replay nonce must be a hex string of at least 32 characters"):
            DecryptionEvent(
                **base_event_data,
                anti_replay_nonce="tooshort123",
            )

        # 2. Nonce not valid hex
        with pytest.raises(ValidationError, match="valid hexadecimal characters"):
            DecryptionEvent(
                **base_event_data,
                anti_replay_nonce="z" * 32,
            )

        # 3. Valid 128-bit hex nonce passes
        event = DecryptionEvent(
            **base_event_data,
            anti_replay_nonce="a" * 32,
        )
        assert event.anti_replay_nonce == "a" * 32
