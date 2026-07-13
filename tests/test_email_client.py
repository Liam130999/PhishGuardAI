"""Unit tests for the IMAP email client (phish_guard.email_client)."""

import email

import pytest

from phish_guard.email_client import EmailClient, EmailClientError, extract_body
from tests.conftest import FakeIMAP, build_raw_email


def test_fetch_unread_extracts_fields(config):
    raw = build_raw_email("CEO <ceo@corp.com>", "Urgent wire", "Please send the payment now.")
    fake = FakeIMAP({b"1": raw})
    client = EmailClient(config, connection=fake)

    messages = client.fetch_unread()

    assert len(messages) == 1
    msg = messages[0]
    assert msg.sender == "CEO <ceo@corp.com>"
    assert msg.subject == "Urgent wire"
    assert "send the payment now" in msg.body


def test_mark_as_read_sets_seen_flag(config):
    cfg = config.__class__(**{**config.__dict__, "mark_as_read": True})
    raw = build_raw_email("a@b.com", "hi", "body")
    fake = FakeIMAP({b"1": raw})
    client = EmailClient(cfg, connection=fake)

    client.fetch_unread()

    assert fake.stored_flags == [(b"1", "+FLAGS", "\\Seen")]


def test_no_mark_as_read_leaves_unseen(config):
    raw = build_raw_email("a@b.com", "hi", "body")
    fake = FakeIMAP({b"1": raw})
    client = EmailClient(config, connection=fake)

    client.fetch_unread()

    assert fake.stored_flags == []


def test_context_manager_closes(config):
    fake = FakeIMAP({})
    with EmailClient(config, connection=fake):
        pass
    assert fake.closed and fake.logged_out


def test_extract_body_prefers_plain_text():
    msg = email.message.EmailMessage()
    msg["From"] = "a@b.com"
    msg["Subject"] = "s"
    msg.set_content("PLAIN version")
    msg.add_alternative("<html><body>HTML version</body></html>", subtype="html")
    assert extract_body(msg) == "PLAIN version"


def test_extract_body_falls_back_to_html():
    msg = email.message.EmailMessage()
    msg["From"] = "a@b.com"
    msg["Subject"] = "s"
    msg.set_content("<html><body>Click <b>here</b> now</body></html>", subtype="html")
    body = extract_body(msg)
    assert "Click" in body and "here" in body and "<b>" not in body


def test_decodes_encoded_subject_header(config):
    # RFC-2047 encoded subject: "=?utf-8?b?...?="
    raw = build_raw_email("=?utf-8?q?Bank?= <no-reply@bank.com>", "=?utf-8?b?VXJnZW50?=", "hi")
    fake = FakeIMAP({b"1": raw})
    client = EmailClient(config, connection=fake)
    msg = client.fetch_unread()[0]
    assert msg.subject == "Urgent"


def test_fetch_unread_empty_inbox(config):
    fake = FakeIMAP({})
    client = EmailClient(config, connection=fake)
    assert client.fetch_unread() == []


def test_extract_body_attachment_only_returns_empty():
    msg = email.message.EmailMessage()
    msg["From"] = "a@b.com"
    msg["Subject"] = "s"
    msg.add_attachment(b"binarydata", maintype="application", subtype="pdf", filename="x.pdf")
    assert extract_body(msg) == ""


def test_select_failure_raises(config):
    fake = FakeIMAP({})
    fake.select = lambda mailbox: ("NO", [b""])  # simulate bad mailbox
    client = EmailClient(config, connection=fake)
    with pytest.raises(EmailClientError):
        client.fetch_unread()


def test_missing_headers_are_blank(config):
    # Build a raw message with no From/Subject headers at all.
    raw = b"Content-Type: text/plain\r\n\r\nHello body only\r\n"
    fake = FakeIMAP({b"1": raw})
    client = EmailClient(config, connection=fake)
    msg = client.fetch_unread()[0]
    assert msg.sender == ""
    assert msg.subject == ""
    assert "Hello body only" in msg.body

