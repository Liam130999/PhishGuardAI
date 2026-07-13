"""Shared pytest fixtures and lightweight fakes for the Phish-Guard AI tests."""

from __future__ import annotations

import email
from typing import List

import pytest

from phish_guard.config import Config


@pytest.fixture
def config() -> Config:
    """A valid in-memory config that never touches real services."""
    return Config(
        imap_host="imap.example.com",
        imap_port=993,
        imap_username="user@example.com",
        imap_password="secret",
        imap_mailbox="INBOX",
        imap_use_ssl=True,
        mark_as_read=False,
        poll_interval=1,
        risk_threshold=70,
        log_file="test.log",
    )


def build_raw_email(sender: str, subject: str, body: str) -> bytes:
    """Create a simple RFC-822 message as bytes, like IMAP would return."""
    msg = email.message.EmailMessage()
    msg["From"] = sender
    msg["Subject"] = subject
    msg.set_content(body)
    return msg.as_bytes()


class FakeIMAP:
    """Minimal stand-in for imaplib.IMAP4 driven by preloaded messages."""

    def __init__(self, messages: dict[bytes, bytes]):
        self._messages = messages  # uid -> raw bytes
        self.stored_flags: List[tuple] = []
        self.closed = False
        self.logged_out = False

    def select(self, mailbox):
        return "OK", [b"1"]

    def search(self, charset, criterion):
        return "OK", [b" ".join(self._messages.keys())]

    def fetch(self, uid, spec):
        raw = self._messages.get(uid)
        if raw is None:
            return "NO", [None]
        return "OK", [(b"1 (BODY[] {})", raw)]

    def store(self, uid, command, flags):
        self.stored_flags.append((uid, command, flags))
        return "OK", [b""]

    def close(self):
        self.closed = True

    def logout(self):
        self.logged_out = True
