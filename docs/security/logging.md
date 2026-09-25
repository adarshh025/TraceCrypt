# Secure Logging and Audit Trail Policy

## 1. Principles
* **Local Logs are Mutable:** Logs stored on local disk files are not cryptographically immutable. System administrators or attackers with host access could alter them. True immutability is achieved when decryption events commit to the distributed ledger in Phase 6.
* **Zero Secret Leakage:** Logs must never under any circumstances contain private keys, passphrases, symmetric document keys, unencrypted document text, or raw secrets.

## 2. Automated Redaction Engine
`tracecrypt.security.logging.SensitivePatternRedactor` automatically intercepts and sanitizes log entries:
1. **Private Key Markers:** `-----BEGIN ... PRIVATE KEY-----` strings are replaced with `[REDACTED_SECRET]`.
2. **Sensitive Parameters:** Variables named `passphrase`, `password`, `secret`, `bearer`, `token`, `private_key` are replaced with `[REDACTED_SECRET]`.
3. **Raw Hex Seeds:** 64-character hex strings that are not explicitly prefixed as public digests (e.g. `sha3-256:`) are redacted.

## 3. Allowed Log Fields
* Event IDs (`evt-...`)
* Transaction IDs (`tx-...`)
* Document IDs (`doc-...`)
* Component and operation names
* ISO 8601 UTC timestamps
* High-level operational status codes (`SUCCESS`, `FAILED`, `BLOCKED`)
