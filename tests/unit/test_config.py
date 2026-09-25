"""Unit tests for configuration subsystem and security invariant enforcement."""

import pytest

from tracecrypt.config.settings import (
    AirGapConfig,
    AppMode,
    ConfigurationError,
    Settings,
    reset_settings,
)


@pytest.fixture(autouse=True)
def clean_settings():
    reset_settings(None)
    yield
    reset_settings(None)


@pytest.mark.unit
def test_default_production_settings():
    settings = Settings()
    assert settings.mode == AppMode.PRODUCTION
    assert settings.airgap.enforce_airgap is True
    assert settings.airgap.allow_dns is False
    assert settings.logging.redact_secrets is True
    # Should validate without error
    settings.validate_security_invariants()


@pytest.mark.unit
def test_production_fails_closed_if_airgap_disabled():
    with pytest.raises(ConfigurationError, match="enforce_airgap"):
        Settings(
            mode=AppMode.PRODUCTION,
            airgap=AirGapConfig(enforce_airgap=False),
        ).validate_security_invariants()


@pytest.mark.unit
def test_production_fails_closed_if_dns_enabled():
    with pytest.raises(ConfigurationError, match="allow_dns"):
        Settings(
            mode=AppMode.PRODUCTION,
            airgap=AirGapConfig(enforce_airgap=True, allow_dns=True),
        ).validate_security_invariants()


@pytest.mark.unit
def test_development_mode_allows_relaxed_settings():
    dev_settings = Settings(
        mode=AppMode.DEVELOPMENT,
        airgap=AirGapConfig(enforce_airgap=False, allow_dns=True),
    )
    # Should not raise in DEVELOPMENT
    dev_settings.validate_security_invariants()
