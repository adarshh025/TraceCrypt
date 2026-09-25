# RFC 8785: JSON Canonicalization Scheme (JCS) Implementation

## 1. Specification Overview
Cryptographic signatures over JSON data require a 100% deterministic, byte-for-byte identical serialization regardless of runtime language, operating system, or dictionary key ordering.

TraceCrypt implements **RFC 8785 (JCS)** in `tracecrypt.event.canonicalizer`:
1. **UTF-16 Key Sorting (Section 3.2.3):** Object keys are sorted lexicographically by their UTF-16 code unit representation (`key.encode("utf-16be")`).
2. **Whitespace (Section 3.2.1):** Zero whitespace around delimiters (no spaces after `:` or `,`).
3. **Number Serialization (Section 3.2.2.3):** Strict adherence to ECMA-262 / IEEE 754 float rules:
   * `0` and `-0` serialize as `"0"`.
   * Floating-point numbers that are integers serialize without decimal point.
   * Exponents between $[-6, 21)$ serialize in fixed-point decimal format (e.g., `0.00001`).
   * Exponents outside that range serialize in exponential notation without leading zeros (e.g., `1e-7`, `1e+21`).
   * `NaN` and `Infinity` raise `CanonicalizationError`.
4. **String Escaping (Section 3.2.2.2):** Minimal escaping:
   * Only `"`, `\`, and control characters (`U+0000` to `U+001F`) are escaped.
   * Forward slashes `/` and non-ASCII Unicode characters (e.g. `\u00e9`, emoji) are NOT escaped and are encoded directly as raw UTF-8 bytes.

## 2. API Usage
```python
from tracecrypt.event.canonicalizer import canonicalize, canonical_hash

# 1. Obtain canonical UTF-8 bytes
canonical_bytes = canonicalize(data)

# 2. Compute canonical digest
digest_str = canonical_hash(data, algorithm="sha3-256")
# Result: 'sha3-256:<64-char-hex>'
```
