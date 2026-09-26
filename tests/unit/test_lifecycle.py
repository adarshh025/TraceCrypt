"""Unit tests for key lifecycle state transitions, key rotation, and offline revocation."""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign, verify
from tracecrypt.crypto.types import KeyMetadata, KeyPurpose, KeyStatus
from tracecrypt.errors import SecurityError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.lifecycle import (
    KeyLifecycleManager,
    OfflineRevocationStore,
    RevocationReason,
)
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.timestamps import utc_now_micros


def test_key_lifecycle_state_machine_valid_transitions() -> None:
    """Verify whitelist state transitions (GENERATED -> ACTIVE -> SUSPENDED -> ACTIVE -> REVOKED -> DESTROYED)."""
    meta = KeyMetadata(
        key_id="key-lifecycle-1",
        owner_id="usr-bob",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.GENERATED,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    # GENERATED -> PENDING_ACTIVATION
    meta = KeyLifecycleManager.transition(meta, KeyStatus.PENDING_ACTIVATION)
    assert meta.status == KeyStatus.PENDING_ACTIVATION

    # PENDING_ACTIVATION -> ACTIVE
    meta = KeyLifecycleManager.transition(meta, KeyStatus.ACTIVE)
    assert meta.status == KeyStatus.ACTIVE
    assert meta.activated_at is not None

    # ACTIVE -> SUSPENDED
    meta = KeyLifecycleManager.transition(meta, KeyStatus.SUSPENDED)
    assert meta.status == KeyStatus.SUSPENDED

    # SUSPENDED -> ACTIVE
    meta = KeyLifecycleManager.transition(meta, KeyStatus.ACTIVE)
    assert meta.status == KeyStatus.ACTIVE

    # ACTIVE -> REVOKED
    meta = KeyLifecycleManager.transition(meta, KeyStatus.REVOKED)
    assert meta.status == KeyStatus.REVOKED

    # REVOKED -> DESTROYED
    meta = KeyLifecycleManager.transition(meta, KeyStatus.DESTROYED)
    assert meta.status == KeyStatus.DESTROYED


def test_prohibited_transitions_fail_closed() -> None:
    """Verify that un-revoking (REVOKED -> ACTIVE) or resurrecting DESTROYED keys is blocked."""
    meta = KeyMetadata(
        key_id="key-lifecycle-2",
        owner_id="usr-charlie",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.REVOKED,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    # Attempt forbidden REVOKED -> ACTIVE
    with pytest.raises(SecurityError, match="Prohibited key status transition"):
        KeyLifecycleManager.transition(meta, KeyStatus.ACTIVE)

    # Attempt forbidden REVOKED -> GENERATED
    with pytest.raises(SecurityError, match="Prohibited key status transition"):
        KeyLifecycleManager.transition(meta, KeyStatus.GENERATED)

    destroyed_meta = meta.model_copy(update={"status": KeyStatus.DESTROYED})
    # Attempt any transition from DESTROYED
    with pytest.raises(SecurityError, match="Prohibited key status transition"):
        KeyLifecycleManager.transition(destroyed_meta, KeyStatus.ACTIVE)


def test_key_rotation_historical_verification(tmp_path) -> None:
    """Verify that historical events signed with Key V1 remain verifiable after Key V2 is active."""
    # Recipient generates Key Pair V1
    pk_v1, sk_v1 = generate_mldsa_keypair()
    meta_v1 = KeyMetadata(
        key_id="key-usr-1-v1",
        owner_id="usr-rec-001",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=pk_v1.fingerprint,
    )

    # Recipient signs Event A using Key V1
    event_a_bytes = b"DecryptionEvent_A_Version_1_Payload"
    sig_a = sign(sk_v1, event_a_bytes)
    assert verify(pk_v1, event_a_bytes, sig_a) is True

    # Rotate recipient key pair to V2
    pk_v2, sk_v2 = generate_mldsa_keypair()
    rotated_v1, meta_v2 = KeyLifecycleManager.rotate_key(
        active_key=meta_v1,
        new_key_id="key-usr-1-v2",
        new_fingerprint=pk_v2.fingerprint,
    )

    assert rotated_v1.status == KeyStatus.REVOKED
    assert meta_v2.status == KeyStatus.ACTIVE
    assert meta_v2.version == 2

    # Recipient signs Event B using Key V2
    event_b_bytes = b"DecryptionEvent_B_Version_2_Payload"
    sig_b = sign(sk_v2, event_b_bytes)
    assert verify(pk_v2, event_b_bytes, sig_b) is True

    # Historical event A must still be independently verifiable using Key V1!
    assert verify(pk_v1, event_a_bytes, sig_a) is True
    # And Event A signature must not verify with Key V2!
    assert verify(pk_v2, event_a_bytes, sig_a) is False


def test_offline_revocation_record_creation_and_store(tmp_path) -> None:
    """Verify that Root CA signs revocation assertions and store records them."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-rev-store")
    db_file = tmp_path / "test_rev.db"
    store = SQLiteStorageManager(db_file)
    store.initialize()

    rev_store = OfflineRevocationStore(store)

    # Initially not revoked
    serial = "crt-1234567890abcdef1234567890abcdef"
    assert rev_store.is_serial_revoked(serial) is False

    # CA creates and signs revocation record
    rev_record = KeyLifecycleManager.create_revocation_record(
        serial_number=serial,
        key_id="key-compromised-1",
        reason=RevocationReason.KEY_COMPROMISE,
        ca=ca,
    )

    rev_store.record_revocation(rev_record)
    assert rev_store.is_serial_revoked(serial) is True
    assert rev_store.get_revocation(serial) is not None
