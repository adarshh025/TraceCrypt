"""Forensic investigation and verification subsystem for TraceCrypt.

Phase 5 introduces:
- ForensicAttributionLink: cryptographic bridge connecting extracted watermark payloads
  to committed signed ledger events and certificate verification.

Phase 7 will introduce:
- Full automated leaked document normalization and blind extraction engine
- Deterministic 9-state verdict engine
- Cryptographically verifiable tamper-evident forensic reporting
"""

from tracecrypt.forensics.preparation import ForensicAttributionLink

__all__ = ["ForensicAttributionLink"]
