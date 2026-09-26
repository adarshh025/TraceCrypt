"""Unit tests for device enrollment and hardware fingerprint telemetry."""

from __future__ import annotations

from pathlib import Path

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator
from tracecrypt.identity.device import DeviceEnrollmentManager, DeviceFingerprintEngine
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import UserID


def test_device_fingerprint_collection() -> None:
    """Verify device telemetry collection and deterministic hashing."""
    fingerprint = DeviceFingerprintEngine.collect_telemetry()

    assert fingerprint.hostname != ""
    assert fingerprint.os_family != ""
    assert fingerprint.machine_guid_hash != ""
    assert fingerprint.fingerprint_hash.startswith("sha3-256:")

    # Verify that telemetry warning acknowledges spoofing risk
    assert "Hardware identifiers are spoofable" in fingerprint.telemetry_warning


def test_device_enrollment_lifecycle(tmp_path: Path) -> None:
    """Verify device enrollment, certificate issuance, and local database storage."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-device-test")
    db_file = tmp_path / "devices.db"
    store = SQLiteStorageManager(db_file)
    store.initialize()

    dev_mgr = DeviceEnrollmentManager(ca=ca, storage=store)

    user_id = SecureRandom.generate_id(UserID)
    device_pk, _ = generate_mldsa_keypair()

    device, cert = dev_mgr.enroll_device(
        user_id=user_id,
        device_public_key=device_pk,
        organization="Naval Cyber Warfare",
        role="Field Laptop",
    )

    assert device.user_id == user_id
    assert device.device_id.startswith("dev-")
    assert cert.device_id == str(device.device_id)
    assert cert.subject_id == str(user_id)

    # Verify the device certificate validates against Root CA
    CertificateValidator.validate(cert, ca.public_key)

    # Verify device persisted in SQLite store
    stored_dev = store.get_device(str(device.device_id))
    assert stored_dev is not None
    assert stored_dev.hostname == device.hostname
    assert stored_dev.fingerprint_hash == device.fingerprint_hash
