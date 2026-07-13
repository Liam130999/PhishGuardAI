"""Unit tests for configuration loading (phish_guard.config)."""

import pytest

from phish_guard.config import Config, ConfigError


def _base_env(monkeypatch, **overrides):
    env = {
        "IMAP_HOST": "imap.example.com",
        "IMAP_PORT": "993",
        "IMAP_USERNAME": "user@example.com",
        "IMAP_PASSWORD": "secret",
        "RISK_THRESHOLD": "70",
    }
    env.update(overrides)
    for key in [
        "IMAP_HOST", "IMAP_PORT", "IMAP_USERNAME", "IMAP_PASSWORD", "IMAP_MAILBOX",
        "IMAP_USE_SSL", "MARK_AS_READ",
        "POLL_INTERVAL", "RISK_THRESHOLD", "LOG_FILE",
    ]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_from_env_valid(monkeypatch):
    _base_env(monkeypatch)
    config = Config.from_env()
    assert config.imap_host == "imap.example.com"
    assert config.imap_port == 993
    assert config.risk_threshold == 70
    assert config.imap_use_ssl is True  # default


def test_missing_required_raises(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.delenv("IMAP_PASSWORD", raising=False)
    with pytest.raises(ConfigError) as exc:
        Config.from_env()
    assert "IMAP_PASSWORD" in str(exc.value)


def test_bad_threshold_raises(monkeypatch):
    _base_env(monkeypatch, RISK_THRESHOLD="500")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_bad_int_raises(monkeypatch):
    _base_env(monkeypatch, IMAP_PORT="not-a-number")
    with pytest.raises(ValueError):
        Config.from_env()


def test_bool_parsing(monkeypatch):
    _base_env(monkeypatch, MARK_AS_READ="yes", IMAP_USE_SSL="false")
    config = Config.from_env()
    assert config.mark_as_read is True
    assert config.imap_use_ssl is False
