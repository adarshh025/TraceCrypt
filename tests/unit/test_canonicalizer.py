"""Comprehensive unit tests for RFC 8785 JSON Canonicalization Scheme (JCS)."""

import json
import pytest

from tracecrypt.errors import CanonicalizationError
from tracecrypt.event.canonicalizer import canonical_hash, canonicalize


@pytest.mark.unit
def test_key_ordering_independence():
    """Verify that different dictionary insertion orders yield identical canonical bytes."""
    obj1 = {"b": 2, "a": 1, "c": 3}
    obj2 = {"c": 3, "b": 2, "a": 1}
    obj3 = {"a": 1, "c": 3, "b": 2}

    b1 = canonicalize(obj1)
    b2 = canonicalize(obj2)
    b3 = canonicalize(obj3)

    assert b1 == b2 == b3
    assert b1 == b'{"a":1,"b":2,"c":3}'


@pytest.mark.unit
def test_utf16_code_unit_sorting():
    """Verify lexicographical sorting by UTF-16 code units (RFC 8785 Section 3.2.3)."""
    # Keys with ASCII, high BMP, and non-BMP characters
    obj = {
        "\u00e9": "accent",
        "\U0001f600": "emoji",
        "a": "ascii-a",
        "z": "ascii-z",
        "\u0000": "null-char",
    }
    canon = canonicalize(obj).decode("utf-8")
    parsed = json.loads(canon)
    keys_in_output = list(parsed.keys())

    # In UTF-16 code units:
    # \u0000 (0x0000) < 'a' (0x0061) < 'z' (0x007a) < \u00e9 (0x00e9) < \U0001f600 (surrogate pair: 0xD83D 0xDE00)
    expected_order = ["\u0000", "a", "z", "\u00e9", "\U0001f600"]
    assert keys_in_output == expected_order


@pytest.mark.unit
def test_whitespace_omission():
    """Whitespace outside strings must be strictly eliminated."""
    data = {"list": [1, 2, {"nested": True}], "str": "value with spaces"}
    canon = canonicalize(data)
    assert b" " not in canon.replace(b"value with spaces", b"")
    assert canon == b'{"list":[1,2,{"nested":true}],"str":"value with spaces"}'


@pytest.mark.unit
def test_primitive_values():
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(None) == b"null"
    assert canonicalize(0) == b"0"
    assert canonicalize(-0.0) == b"0"
    assert canonicalize(100) == b"100"
    assert canonicalize(-50) == b"-50"
    assert canonicalize(1.25) == b"1.25"


@pytest.mark.unit
def test_number_formatting():
    """Test ECMA-262 / RFC 8785 number serialization edge cases."""
    assert canonicalize(1e-5) == b"0.00001"
    assert canonicalize(1e-6) == b"0.000001"
    assert canonicalize(1e-7) == b"1e-7"
    assert canonicalize(1e20) == b"100000000000000000000"
    assert canonicalize(1e21) == b"1e+21"
    assert canonicalize(0.000001) == b"0.000001"
    assert canonicalize(0.0000001) == b"1e-7"


@pytest.mark.unit
def test_string_escaping_rules():
    """Test minimal escaping: only quote, backslash, and control chars are escaped."""
    # Slashes and unicode must NOT be escaped
    data = {
        "slash": "a/b/c",
        "quotes": 'hello "world"',
        "newline": "line1\nline2",
        "tab": "col1\tcol2",
        "unicode": "\u00e9lite \U0001f512",
    }
    canon = canonicalize(data)
    # Forward slash '/' must not be escaped as '\/'
    assert b"\\/" not in canon
    # Raw UTF-8 bytes for unicode
    assert "élite 🔒".encode("utf-8") in canon
    # Explicit escapes for quote, newline, tab
    assert b'hello \\"world\\"' in canon
    assert b"line1\\nline2" in canon
    assert b"col1\\tcol2" in canon


@pytest.mark.unit
def test_invalid_types_rejection():
    # NaN and Infinity are forbidden
    with pytest.raises(CanonicalizationError):
        canonicalize(float("nan"))
    with pytest.raises(CanonicalizationError):
        canonicalize(float("inf"))
    with pytest.raises(CanonicalizationError):
        canonicalize(float("-inf"))
    # Sets are not supported in JSON
    with pytest.raises(CanonicalizationError):
        canonicalize({"a", "b"})
    # Non-string dictionary keys are forbidden
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "integer-key"})


@pytest.mark.unit
def test_canonical_hash_determinism():
    obj1 = {"doc_id": "doc-1", "user_id": "usr-1", "session_id": "ses-1"}
    obj2 = {"session_id": "ses-1", "doc_id": "doc-1", "user_id": "usr-1"}

    h1 = canonical_hash(obj1)
    h2 = canonical_hash(obj2)

    assert h1 == h2
    assert h1.startswith("sha3-256:")
