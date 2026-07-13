"""Configuration loading for Phish-Guard AI.

All settings come from environment variables (loaded from a local .env file via
python-dotenv). Keeping secrets out of the source tree means the project is safe
to push to git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load .env once at import time. Real environment variables always win over the
# file, which is what you want in CI or a container.
load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {value!r}") from exc


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Immutable snapshot of all runtime settings."""

    # IMAP
    imap_host: str
    imap_port: int
    imap_username: str
    imap_password: str
    imap_mailbox: str
    imap_use_ssl: bool
    mark_as_read: bool

    # Runtime
    poll_interval: int
    risk_threshold: int
    log_file: str

    @classmethod
    def from_env(cls, require_imap: bool = True) -> "Config":
        """Build a Config from environment variables and validate it.

        Set ``require_imap=False`` for offline modes that never open an IMAP
        connection.
        """
        cfg = cls(
            imap_host=os.getenv("IMAP_HOST", ""),
            imap_port=_get_int("IMAP_PORT", 993),
            imap_username=os.getenv("IMAP_USERNAME", ""),
            imap_password=os.getenv("IMAP_PASSWORD", ""),
            imap_mailbox=os.getenv("IMAP_MAILBOX", "INBOX"),
            imap_use_ssl=_get_bool("IMAP_USE_SSL", True),
            mark_as_read=_get_bool("MARK_AS_READ", False),
            poll_interval=_get_int("POLL_INTERVAL", 60),
            risk_threshold=_get_int("RISK_THRESHOLD", 70),
            log_file=os.getenv("LOG_FILE", "phish_guard.log"),
        )
        cfg.validate(require_imap=require_imap)
        return cfg

    def validate(self, require_imap: bool = True) -> None:
        required = {}
        if require_imap:
            required.update(
                {
                    "IMAP_HOST": self.imap_host,
                    "IMAP_USERNAME": self.imap_username,
                    "IMAP_PASSWORD": self.imap_password,
                }
            )
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigError(
                "Missing required configuration: "
                + ", ".join(missing)
                + ". Copy .env.example to .env and fill in the values."
            )
        if not 1 <= self.risk_threshold <= 100:
            raise ConfigError("RISK_THRESHOLD must be between 1 and 100.")
