"""UTC timestamp policy and utilities for TraceCrypt.

Policy Specifications:
- Timezone: Strictly UTC (tzinfo=timezone.utc). Naive datetime objects are rejected.
- Representation: POSIX microseconds (integer since UNIX epoch 1970-01-01T00:00:00Z)
  for canonical event hashing, and ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SS.ffffffZ)
  for human-readable diagnostic display.
- Clock Assumptions: System clock is assumed monotonic or NTP-disciplined within local LAN.
- Anti-Replay: Timestamps are NEVER used alone for anti-replay; they are always combined
  with a 128-bit CSPRNG nonce and ledger state uniqueness verification.
- Clock Skew: Decryption events allow a configurable maximum future drift tolerance
  (default: 60 seconds) to accommodate minor LAN clock skew without compromising security.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Final

from tracecrypt.errors import ValidationError

# Maximum allowed future drift in seconds (tolerates small LAN clock skew)
DEFAULT_MAX_CLOCK_SKEW_SECONDS: Final[int] = 60


class TimestampPolicy:
    """Enforces strict UTC timestamp standards across all TraceCrypt components."""

    @staticmethod
    def now_micros() -> int:
        """Return the current UTC time in microseconds since UNIX epoch."""
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp() * 1_000_000)

    @staticmethod
    def now_iso() -> str:
        """Return the current UTC time in ISO 8601 format with microsecond precision and Z suffix."""
        dt = datetime.now(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def micros_to_iso(micros: int) -> str:
        """Convert POSIX microsecond integer to ISO 8601 UTC string."""
        if not isinstance(micros, int):
            raise ValidationError(f"Timestamp microseconds must be int, got {type(micros).__name__}")
        if micros < 0:
            raise ValidationError(f"Timestamp microseconds cannot be negative: {micros}")
        dt = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def iso_to_micros(iso_str: str) -> int:
        """Parse ISO 8601 UTC string into POSIX microseconds integer."""
        if not isinstance(iso_str, str):
            raise ValidationError(f"Timestamp ISO string must be str, got {type(iso_str).__name__}")
        cleaned = iso_str.strip()
        if not (cleaned.endswith("Z") or cleaned.endswith("+00:00")):
            raise ValidationError(f"Timestamp must be explicitly in UTC (ending with 'Z' or '+00:00'): {iso_str!r}")
        try:
            # Normalize Z to +00:00 for fromisoformat
            norm = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
            dt = datetime.fromisoformat(norm)
            if dt.tzinfo != timezone.utc:
                dt = dt.astimezone(timezone.utc)
            return int(dt.timestamp() * 1_000_000)
        except Exception as e:
            raise ValidationError(f"Invalid ISO 8601 UTC timestamp format '{iso_str}': {e}") from e

    @staticmethod
    def validate_freshness(event_timestamp_micros: int, max_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS) -> None:
        """Validate that a timestamp is not excessively in the future."""
        current_micros = TimestampPolicy.now_micros()
        max_future_micros = current_micros + (max_skew_seconds * 1_000_000)
        if event_timestamp_micros > max_future_micros:
            skew_seconds = (event_timestamp_micros - current_micros) / 1_000_000
            raise ValidationError(
                f"Event timestamp is too far in the future ({skew_seconds:.1f}s > {max_skew_seconds}s allowed). "
                f"Clock skew or replay suspected."
            )


def utc_now_micros() -> int:
    """Convenience helper to obtain current UTC time in microseconds."""
    return TimestampPolicy.now_micros()


def utc_now_iso() -> str:
    """Convenience helper to obtain current UTC time in ISO 8601 string."""
    return TimestampPolicy.now_iso()
