"""IMAP integration: connect to a mailbox, fetch unread mail and extract the
sender, subject and plain-text body."""

from __future__ import annotations

import email
import imaplib
import logging
from email.header import decode_header, make_header
from email.message import Message
from types import TracebackType
from typing import List, Optional, Type

from .config import Config
from .models import EmailMessage

logger = logging.getLogger(__name__)


class EmailClientError(RuntimeError):
    """Raised for unrecoverable IMAP problems."""


def _decode(value: Optional[str]) -> str:
    """Decode a possibly RFC-2047 encoded header into a plain str."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:  # pragma: no cover - defensive, malformed headers
        return value.strip()


def extract_body(msg: Message) -> str:
    """Return the plain-text body of an email.

    Prefers text/plain parts; falls back to stripping tags from text/html if no
    plain part exists. Skips attachments.
    """
    if msg.is_multipart():
        html_fallback = ""
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition.lower():
                continue
            if content_type == "text/plain":
                return _decode_payload(part)
            if content_type == "text/html" and not html_fallback:
                html_fallback = _strip_html(_decode_payload(part))
        return html_fallback

    if msg.get_content_type() == "text/html":
        return _strip_html(_decode_payload(msg))
    return _decode_payload(msg)


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace").strip()
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace").strip()


def _strip_html(html: str) -> str:
    """Very small HTML-to-text helper (no external dependency)."""
    import re

    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+\n", "\n", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


class EmailClient:
    """Thin, testable wrapper around imaplib for reading unread email.

    Usable as a context manager::

        with EmailClient(config) as client:
            for message in client.fetch_unread():
                ...
    """

    def __init__(self, config: Config, connection: Optional[imaplib.IMAP4] = None) -> None:
        self._config = config
        # Dependency injection: tests pass a fake connection instead of a socket.
        self._conn = connection

    # -- connection lifecycle -------------------------------------------------
    def connect(self) -> None:
        if self._conn is not None:
            return
        cfg = self._config
        try:
            if cfg.imap_use_ssl:
                self._conn = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
            else:
                self._conn = imaplib.IMAP4(cfg.imap_host, cfg.imap_port)
            self._conn.login(cfg.imap_username, cfg.imap_password)
            logger.info("Connected to IMAP server %s as %s", cfg.imap_host, cfg.imap_username)
        except (imaplib.IMAP4.error, OSError) as exc:
            detail = str(exc)
            if "AUTHENTICATIONFAILED" in detail.upper() or "invalid credentials" in detail.lower():
                # Wrong username or app password is the most common failure.
                raise EmailClientError(
                    "IMAP login failed: invalid username or app password. Use a "
                    "16-character Gmail app password (not the account login) and "
                    "check the IMAP App Password in the sidebar."
                ) from exc
            raise EmailClientError(f"Failed to connect/login to IMAP server: {exc}") from exc

    def close(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.close()
        except Exception:  # pragma: no cover - close() fails if no mailbox selected
            pass
        try:
            self._conn.logout()
        except Exception:  # pragma: no cover
            pass
        finally:
            self._conn = None

    def __enter__(self) -> "EmailClient":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # -- reading --------------------------------------------------------------
    def fetch_unread(self) -> List[EmailMessage]:
        """Return all UNSEEN messages in the configured mailbox.

        If ``MARK_AS_READ`` is true the messages are flagged \\Seen so that a
        later poll will not reprocess them.
        """
        if self._conn is None:
            raise EmailClientError("Not connected. Call connect() first.")

        status, _ = self._conn.select(self._config.imap_mailbox)
        if status != "OK":
            raise EmailClientError(f"Could not select mailbox {self._config.imap_mailbox!r}")

        status, data = self._conn.search(None, "UNSEEN")
        if status != "OK":
            raise EmailClientError("IMAP search for UNSEEN messages failed")

        uids = data[0].split() if data and data[0] else []
        messages: List[EmailMessage] = []
        for uid in uids:
            message = self._fetch_one(uid)
            if message is not None:
                messages.append(message)
        logger.info("Fetched %d unread message(s)", len(messages))
        return messages

    def _fetch_one(self, uid: bytes) -> Optional[EmailMessage]:
        uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
        try:
            # BODY.PEEK[] fetches the message without setting the \Seen flag; we
            # only mark as read explicitly (and only if configured to).
            status, data = self._conn.fetch(uid, "(BODY.PEEK[])")
            if status != "OK" or not data or data[0] is None:
                logger.warning("Failed to fetch message uid=%s", uid_str)
                return None

            raw = data[0][1]
            msg = email.message_from_bytes(raw)
            body = extract_body(msg)
            if not body:
                # Attachment-only or bodiless mail: still analysed, but flag it.
                logger.warning("Message uid=%s has no readable text body", uid_str)
            message = EmailMessage(
                uid=uid_str,
                sender=_decode(msg.get("From")),
                subject=_decode(msg.get("Subject")),
                body=body,
            )
            if self._config.mark_as_read:
                self._conn.store(uid, "+FLAGS", "\\Seen")
            return message
        except (imaplib.IMAP4.error, OSError) as exc:
            # One bad message must not crash the whole poll cycle.
            logger.warning("Error while reading message uid=%s: %s", uid_str, exc)
            return None
