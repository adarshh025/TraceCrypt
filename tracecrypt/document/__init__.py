"""Encrypted document distribution subsystem (.tcdist) for TraceCrypt.

Provides single-pass AES-256-GCM content encryption, multi-recipient
ML-KEM-768 key encapsulation, versioned binary container packaging,
17-point offline validation, and authenticated recipient decapsulation.
"""

from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
    WatermarkedDocumentRelease,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.package import DistributionPackage
from tracecrypt.document.reader import DocumentReader
from tracecrypt.document.release_gate import (
    DocumentReleaseGate,
    ReleaseDecision,
    ReleaseGateResult,
)
from tracecrypt.document.types import (
    DistributionPackageHeader,
    PackageValidationResult,
    RecipientEnvelope,
    SecureDocumentBuffer,
)
from tracecrypt.document.validator import PackageValidator

__all__ = [
    "DistributionPackage",
    "DistributionPackageHeader",
    "RecipientEnvelope",
    "SecureDocumentBuffer",
    "PackageValidationResult",
    "DocumentHasher",
    "DocumentReader",
    "ContentEncryption",
    "KeyWrapEngine",
    "PackageValidator",
    "DistributionService",
    "RecipientSpec",
    "RecipientAttributionPipeline",
    "RecipientCredentials",
    "WatermarkedDocumentRelease",
    "DocumentReleaseGate",
    "ReleaseDecision",
    "ReleaseGateResult",
]
