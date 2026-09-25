"""Unit tests for secure logging and automated secret redaction."""

import pytest

from tracecrypt.security.logging import SensitivePatternRedactor, get_security_logger


@pytest.mark.unit
def test_private_key_redaction():
    fake_pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n"
        "-----END PRIVATE KEY-----"
    )
    log_text = f"Decryption session initiated with key: {fake_pem}"
    redacted = SensitivePatternRedactor.redact_string(log_text)
    assert "-----BEGIN" not in redacted
    assert "[REDACTED_SECRET]" in redacted


@pytest.mark.unit
def test_passphrase_redaction():
    msg = "User entered passphrase: 'SuperSecretPassphrase123' for session"
    redacted = SensitivePatternRedactor.redact_string(msg)
    assert "SuperSecretPassphrase123" not in redacted
    assert "[REDACTED_SECRET]" in redacted


@pytest.mark.unit
def test_bearer_token_redaction():
    msg = "Request headers: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
    redacted = SensitivePatternRedactor.redact_string(msg)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "[REDACTED_SECRET]" in redacted


@pytest.mark.unit
def test_public_hash_preservation():
    """Verify that public SHA3-256 hashes are NOT destroyed by the hex redactor."""
    public_hash = "sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    msg = f"Document verified against public hash {public_hash}"
    redacted = SensitivePatternRedactor.redact_string(msg)
    assert public_hash in redacted


@pytest.mark.unit
def test_structured_logger_redaction():
    logger = get_security_logger("test_component")
    entry = logger.info(
        operation="KEY_GEN",
        status="SUCCESS",
        message="Created key with password=SecretKeyPassword",
        details={"private_key_bytes": "secret_bytes_here", "doc_id": "doc-0123456789abcdef0123456789abcdef"},
    )
    assert entry["component"] == "test_component"
    assert "SecretKeyPassword" not in entry["message"]
    assert entry["details"]["private_key_bytes"] == "[REDACTED_SECRET]"
    assert entry["details"]["doc_id"] == "doc-0123456789abcdef0123456789abcdef"
