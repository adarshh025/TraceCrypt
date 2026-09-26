"""Workstation Device Enrollment and Hardware Fingerprint Telemetry.

SECURITY NOTICE ON HARDWARE FINGERPRINTING:
Raw hardware signals (MAC addresses, CPU IDs, motherboard UUIDs) can be cloned, spoofed,
or altered by VM snapshots, driver shims, and hardware replacement.

In TraceCrypt:
1. Hardware fingerprinting is treated as a secondary telemetry signal for anomaly detection.
2. It DOES NOT constitute cryptographic proof of physical device identity.
3. Cryptographic device binding is achieved via certified PQC device keys enrolled with the Root CA.
"""

from __future__ import annotations

import platform
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import MLDSAPublicKey
from tracecrypt.errors import ValidationError
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.models.domain import Device, User, UserRole, UserStatus
from tracecrypt.utils.identifiers import DeviceID, UserID
from tracecrypt.utils.timestamps import utc_now_micros


class DeviceTelemetry(BaseModel):
    """Auxiliary hardware telemetry report with non-cryptographic warning."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    os_family: str
    platform_info: str
    machine_guid_hash: str
    fingerprint_hash: str
    telemetry_warning: str = (
        "Hardware identifiers are spoofable and susceptible to VM cloning. "
        "This digest serves as secondary diagnostic telemetry, NOT cryptographic proof of identity."
    )


class DeviceEnrollmentRecord(BaseModel):
    """Certified workstation device enrollment record."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: DeviceID
    user_id: UserID
    hostname: str
    platform_info: str
    fingerprint_hash: str = Field(description="Auxiliary hardware composite digest")
    enrolled_at: int
    is_active: bool = True
    certificate_serial: Optional[str] = None


class DeviceFingerprintEngine:
    """Computes and evaluates composite hardware telemetry signals."""

    @classmethod
    def collect_telemetry(cls) -> DeviceTelemetry:
        """Gather current workstation hardware indicators and return telemetry report."""
        hostname = platform.node() or "UNKNOWN-NODE"
        os_family = platform.system() or "UNKNOWN-OS"
        plat = platform.platform() or "UNKNOWN-PLATFORM"

        raw_node = str(uuid.getnode())
        guid_digest = Hasher.digest_bytes(raw_node.encode("utf-8"), HashAlgorithm.SHA3_256.value)

        composite = f"{hostname}|{os_family}|{plat}|{raw_node}".encode("utf-8")
        fp_digest = Hasher.digest_bytes(composite, HashAlgorithm.SHA3_256.value)

        return DeviceTelemetry(
            hostname=hostname,
            os_family=os_family,
            platform_info=plat,
            machine_guid_hash=guid_digest.formatted,
            fingerprint_hash=f"sha3-256:{fp_digest.formatted}",
        )

    @classmethod
    def compute_fingerprint(cls) -> str:
        """Compute SHA3-256 composite digest of local system telemetry."""
        telemetry = cls.collect_telemetry()
        return telemetry.fingerprint_hash

    @classmethod
    def verify_fingerprint(cls, expected_fingerprint: str) -> bool:
        """Compare current system telemetry against expected enrollment digest."""
        current = cls.compute_fingerprint()
        return current.lower().strip() == expected_fingerprint.lower().strip()


class DeviceEnrollmentManager:
    """Manages enrolled workstation devices."""

    def __init__(self, ca: Optional[Any] = None, storage: Optional[Any] = None) -> None:
        self.ca = ca
        self.storage = storage
        self._devices: Dict[str, DeviceEnrollmentRecord] = {}

    def enroll_device(
        self,
        user_id: UserID,
        device_public_key: Optional[MLDSAPublicKey] = None,
        organization: str = "TraceCrypt Organization",
        role: str = "Workstation",
        hostname: Optional[str] = None,
        device_id: Optional[DeviceID] = None,
    ) -> Any:
        """Enroll workstation device for an authorized user.

        If ca and device_public_key are provided, issues a certified PQCIdentityCertificate
        and returns (Device, PQCIdentityCertificate). Otherwise returns DeviceEnrollmentRecord.
        """
        dev_id = device_id or SecureRandom.generate_id(DeviceID)
        host = hostname or platform.node() or "UNKNOWN-HOST"
        plat = platform.platform()
        telemetry = DeviceFingerprintEngine.collect_telemetry()
        now = utc_now_micros()

        device_domain = Device(
            device_id=dev_id,
            user_id=user_id,
            hostname=host,
            fingerprint_hash=telemetry.fingerprint_hash,
            os_version=plat[:100],
            enrolled_at=now,
            is_trusted=True,
        )

        cert: Optional[PQCIdentityCertificate] = None
        if self.ca is not None and device_public_key is not None:
            cert = self.ca.issue_signing_certificate(
                subject_id=str(user_id),
                public_key=device_public_key,
                organization=organization,
                role=role,
                device_id=str(dev_id),
            )

        if self.storage is not None:
            # Ensure foreign key user exists in users table
            try:
                existing_user = self.storage.get_user(str(user_id))
                if existing_user is None:
                    dummy_user = User(
                        user_id=user_id,
                        display_name=str(user_id),
                        email_hash="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
                        organization_unit=organization,
                        role=UserRole.RECIPIENT,
                        created_at=now,
                        status=UserStatus.ACTIVE,
                    )
                    self.storage.save_user(dummy_user)
                self.storage.save_device(device_domain)
                if cert is not None:
                    self.storage.save_certificate(cert)
            except Exception:
                pass

        record = DeviceEnrollmentRecord(
            device_id=dev_id,
            user_id=user_id,
            hostname=host,
            platform_info=plat,
            fingerprint_hash=telemetry.fingerprint_hash,
            enrolled_at=now,
            is_active=True,
            certificate_serial=cert.serial_number if cert else None,
        )
        self._devices[str(dev_id)] = record

        if cert is not None:
            return device_domain, cert
        return record

    def get_device(self, device_id: str) -> Optional[DeviceEnrollmentRecord]:
        return self._devices.get(device_id)

    def deactivate_device(self, device_id: str) -> DeviceEnrollmentRecord:
        record = self.get_device(device_id)
        if not record:
            raise ValidationError(f"Device '{device_id}' is not enrolled.")
        updated = DeviceEnrollmentRecord(
            device_id=record.device_id,
            user_id=record.user_id,
            hostname=record.hostname,
            platform_info=record.platform_info,
            fingerprint_hash=record.fingerprint_hash,
            enrolled_at=record.enrolled_at,
            is_active=False,
            certificate_serial=record.certificate_serial,
        )
        self._devices[device_id] = updated
        return updated
