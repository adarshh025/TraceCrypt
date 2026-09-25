"""Structured local logging and audit foundation with automated secret redaction.

NOTE ON IMMUTABILITY:
Local disk logs are NOT tamper-proof or immutable. Operating system administrators or
compromised endpoints can truncate or modify local log files. Cryptographic audit
immutability is achieved exclusively through the permissioned BFT ledger implemented
in Phase 6.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Mapping, Optional

from tracecrypt.utils.timestamps import utc_now_iso


class SensitivePatternRedactor:
    """Detects and redacts cryptographic keys, passphrases, tokens, and raw secrets."""

    REDACTION_MARKER = "[REDACTED_SECRET]"

    PATTERNS = [
        # PEM private keys
        re.compile(
            r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----",
            re.DOTALL | re.IGNORECASE,
        ),
        # Passphrase / password parameters in query strings or logs
        re.compile(
            r"(passphrase|password|secret|bearer|token|private_key|doc_key)\s*[:=]\s*['\"]?([^'\"&\s,]+)",
            re.IGNORECASE,
        ),
        # Authorization headers
        re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
        # Raw 64+ char hex strings (potential unhashed symmetric keys or private seeds)
        re.compile(r"\b([a-fA-F0-9]{64})\b"),
    ]

    @classmethod
    def redact_string(cls, text: str) -> str:
        """Scan string and replace all detected secret patterns with redaction marker."""
        if not isinstance(text, str):
            return text

        result = text
        # Redact PEM keys
        result = cls.PATTERNS[0].sub(cls.REDACTION_MARKER, result)
        # Redact key-value secrets
        result = cls.PATTERNS[1].sub(r"\1=" + cls.REDACTION_MARKER, result)
        # Redact Bearer tokens
        result = cls.PATTERNS[2].sub(r"\1" + cls.REDACTION_MARKER, result)

        # Note: Do not blindly redact 64-char hex if it is an explicit SHA3 hash prefix
        # We only redact raw hex that doesn't follow 'sha3-256:' or similar algorithm prefix
        def hex_replacer(match: re.Match[str]) -> str:
            start_pos = match.start()
            if start_pos >= 9 and result[start_pos - 9:start_pos] in ("sha3-256:", "sha3-512:", "sha-256:"):
                return match.group(0)  # Keep valid public hash digests
            return cls.REDACTION_MARKER

        result = cls.PATTERNS[3].sub(hex_replacer, result)
        return result

    @classmethod
    def redact_value(cls, val: Any) -> Any:
        """Recursively redact dictionary or list values."""
        if isinstance(val, str):
            return cls.redact_string(val)
        elif isinstance(val, dict):
            clean_dict: Dict[str, Any] = {}
            for k, v in val.items():
                k_lower = str(k).lower()
                if any(sec in k_lower for sec in ("pass", "secret", "private", "key_bytes", "plaintext", "token")):
                    clean_dict[k] = cls.REDACTION_MARKER
                else:
                    clean_dict[k] = cls.redact_value(v)
            return clean_dict
        elif isinstance(val, (list, tuple)):
            return [cls.redact_value(item) for item in val]
        return val


class SecurityAuditLogger:
    """Structured security audit logger with fail-closed secret redaction."""

    def __init__(self, component_name: str, logger: Optional[logging.Logger] = None) -> None:
        self.component_name = component_name
        self.logger = logger or logging.getLogger(f"tracecrypt.{component_name}")

    def log_event(
        self,
        level: int,
        operation: str,
        status: str,
        message: str,
        event_id: Optional[str] = None,
        tx_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a structured security audit entry."""
        entry: Dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "component": self.component_name,
            "operation": operation,
            "status": status,
            "message": SensitivePatternRedactor.redact_string(message),
        }
        if event_id:
            entry["event_id"] = event_id
        if tx_id:
            entry["tx_id"] = tx_id
        if details:
            entry["details"] = SensitivePatternRedactor.redact_value(dict(details))

        log_msg = json.dumps(entry, sort_keys=True)
        self.logger.log(level, log_msg)
        return entry

    def info(self, operation: str, status: str, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log_event(logging.INFO, operation, status, message, **kwargs)

    def warning(self, operation: str, status: str, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log_event(logging.WARNING, operation, status, message, **kwargs)

    def error(self, operation: str, status: str, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log_event(logging.ERROR, operation, status, message, **kwargs)


def get_security_logger(component: str) -> SecurityAuditLogger:
    """Obtain a component-specific security audit logger."""
    return SecurityAuditLogger(component)
