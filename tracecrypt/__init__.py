"""TraceCrypt: Offline Forensic Document Attribution Platform.

A production-grade, post-quantum, air-gapped document distribution and
attribution system with per-session invisible forensic watermarking and
permissioned distributed ledger audibility.
"""

from tracecrypt.version import (
    APPLICATION_VERSION as __version__,
    PROTOCOL_VERSION,
    get_system_versions,
)

__author__ = "TraceCrypt Core Architecture Team"
__all__ = ["__version__", "__author__", "PROTOCOL_VERSION", "get_system_versions"]
