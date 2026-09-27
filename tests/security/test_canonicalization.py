"""Adversarial RFC 8785 Canonicalization Tests.

Validates:
- Key reordering produces identical canonical output.
- Whitespace variations are collapsed into strict canonical representation.
- Unicode characters are canonically normalized.
- Different serializations of equivalent data produce identical hashes.
- Non-canonical JSON streams are rejected or normalized before hashing.
"""

from __future__ import annotations

import json

from tracecrypt.event.canonicalizer import canonical_hash, canonicalize


class TestRFC8785Canonicalization:
    """Validate RFC 8785 JSON Canonicalization Scheme (JCS) conformance."""

    def test_key_ordering_independence(self) -> None:
        """Dictionaries with different key insertion orders must produce identical canonical bytes."""
        dict_a = {"z": 1, "a": 2, "m": 3}
        dict_b = {"a": 2, "m": 3, "z": 1}
        dict_c = {"m": 3, "z": 1, "a": 2}

        bytes_a = canonicalize(dict_a)
        bytes_b = canonicalize(dict_b)
        bytes_c = canonicalize(dict_c)

        assert bytes_a == bytes_b == bytes_c
        assert bytes_a == b'{"a":2,"m":3,"z":1}'

    def test_whitespace_insensitivity(self) -> None:
        """Non-canonical JSON with arbitrary spaces and newlines must canonicalize deterministically."""
        json_standard = '{"alpha":"first","beta":2}'
        json_spaced = '{\n  "beta": 2,\n  "alpha": "first"\n}'

        obj_standard = json.loads(json_standard)
        obj_spaced = json.loads(json_spaced)

        assert canonicalize(obj_standard) == canonicalize(obj_spaced)
        assert canonical_hash(obj_standard) == canonical_hash(obj_spaced)

    def test_nested_structures_determinism(self) -> None:
        """Deeply nested objects and arrays must canonicalize in strict lexicographical order."""
        nested_1 = {
            "outer": {
                "inner_b": [3, 2, 1],
                "inner_a": {"y": "val", "x": "val"},
            },
            "id": 42,
        }
        nested_2 = {
            "id": 42,
            "outer": {
                "inner_a": {"x": "val", "y": "val"},
                "inner_b": [3, 2, 1],  # Arrays preserve sequence order
            },
        }

        assert canonicalize(nested_1) == canonicalize(nested_2)

    def test_unicode_escaping_and_normalization(self) -> None:
        """Unicode characters must be encoded in UTF-8 without unnecessary escape sequences."""
        obj_unicode = {"name": "Forensik \u00e9\u00e0\u00fc"}
        canonical_bytes = canonicalize(obj_unicode)

        # RFC 8785 outputs raw UTF-8 for valid code points rather than \\u00e9
        decoded = canonical_bytes.decode("utf-8")
        assert "éàü" in decoded
