"""RFC 8785: JSON Canonicalization Scheme (JCS) Implementation.

Provides deterministic, byte-for-byte identical canonical serialization and
canonical hashing for security-critical event structures and signatures.

Conforms strictly to RFC 8785:
- UTF-8 encoding without Byte Order Mark (BOM).
- Object keys sorted lexicographically by their UTF-16 code units.
- No whitespace between tokens (delimiters: ',' and ':').
- Numbers serialized according to ECMA-262 (Section 7.1.12.1).
- Minimal string escaping: only double-quote, backslash, and control characters (U+0000 - U+001F).
  Forward slashes and non-ASCII Unicode characters are NOT escaped.
"""

from __future__ import annotations

import math
from typing import Any, List

from pydantic import BaseModel

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import CanonicalizationError


def _utf16_sort_key(s: str) -> bytes:
    """Return UTF-16BE bytes for lexicographical sorting by UTF-16 code units (RFC 8785 Section 3.2.3)."""
    return s.encode("utf-16be")


def _format_ecma_number(val: float) -> str:
    """Format IEEE 754 float according to ECMA-262 / RFC 8785 Section 3.2.2.3."""
    if math.isnan(val) or math.isinf(val):
        raise CanonicalizationError(f"NaN and Infinity are not permitted in RFC 8785 JSON: {val}")
    if val == 0.0:
        return "0"

    # Python str(val) produces shortest round-tripping string (dtoa / Grisu3)
    s = str(val)
    if "e" in s:
        mantissa, exp_part = s.split("e")
        sign = exp_part[0]
        exp_val = int(exp_part)
        # ECMAScript: if -6 <= exp_val < 21, use fixed point
        if -6 <= exp_val < 0:
            digits = mantissa.replace(".", "").replace("-", "")
            is_neg = mantissa.startswith("-")
            zero_count = -exp_val - 1
            res = ("-" if is_neg else "") + "0." + ("0" * zero_count) + digits
            return res
        elif 0 <= exp_val < 21:
            digits = mantissa.replace(".", "").replace("-", "")
            parts = mantissa.replace("-", "").split(".")
            int_part = parts[0]
            frac_part = parts[1] if len(parts) > 1 else ""
            all_digits = int_part + frac_part
            shift = exp_val - len(frac_part)
            if shift >= 0:
                res = all_digits + ("0" * shift)
            else:
                dot_idx = len(int_part) + exp_val
                res = all_digits[:dot_idx] + "." + all_digits[dot_idx:]
            return ("-" if mantissa.startswith("-") else "") + res
        else:
            # Exponential: format as 1e-7 or 1e+21 (no leading zero on exponent)
            exp_str = f"e{sign}{abs(exp_val)}"
            return f"{mantissa}{exp_str}"
    else:
        if s.endswith(".0"):
            return s[:-2]
        return s


def _serialize_string(s: str) -> str:
    """Serialize string with minimal escaping as required by RFC 8785 Section 3.2.2.2."""
    out: List[str] = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_value(val: Any) -> str:
    """Recursively serialize a Python object into canonical JSON string."""
    # Convert Pydantic models to dict if passed
    if isinstance(val, BaseModel):
        val = val.model_dump(mode="json")

    # Order matters: check bool before int because bool is subclass of int in Python
    if val is None:
        return "null"
    elif isinstance(val, bool):
        return "true" if val else "false"
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return _format_ecma_number(val)
    elif isinstance(val, str):
        return _serialize_string(val)
    elif isinstance(val, (list, tuple)):
        items = [_serialize_value(item) for item in val]
        return "[" + ",".join(items) + "]"
    elif isinstance(val, dict):
        # Validate that all keys are strings
        for k in val.keys():
            if not isinstance(k, str):
                raise CanonicalizationError(f"RFC 8785 requires all object keys to be strings, got {type(k).__name__}")

        # Sort keys lexicographically by UTF-16 code units
        sorted_keys = sorted(val.keys(), key=_utf16_sort_key)
        items = [f"{_serialize_string(k)}:{_serialize_value(val[k])}" for k in sorted_keys]
        return "{" + ",".join(items) + "}"
    else:
        raise CanonicalizationError(f"Unsupported data type for RFC 8785 canonicalization: {type(val).__name__}")


def canonicalize(value: Any) -> bytes:
    """Canonicalize a JSON-compatible Python value or Pydantic model into UTF-8 bytes.

    Args:
        value: Primitive types (dict, list, str, int, float, bool, None) or Pydantic BaseModel.

    Returns:
        Canonical UTF-8 encoded bytes according to RFC 8785.

    Raises:
        CanonicalizationError: If value contains unsupported types, invalid floats, or non-string keys.
    """
    try:
        canonical_str = _serialize_value(value)
        return canonical_str.encode("utf-8")
    except CanonicalizationError:
        raise
    except Exception as e:
        raise CanonicalizationError(f"Failed to canonicalize value: {e}") from e


def canonical_hash(value: Any, algorithm: str = HashAlgorithm.SHA3_256.value) -> str:
    """Compute the deterministic cryptographic hash of a canonicalized value.

    Args:
        value: Target object to canonicalize and hash.
        algorithm: Hash algorithm name (default: 'sha3-256').

    Returns:
        Canonical formatted digest string (e.g. 'sha3-256:<hex>').
    """
    canonical_bytes = canonicalize(value)
    digest = Hasher.digest_canonical(canonical_bytes, algorithm)
    return digest.formatted
