"""Typed data models shared across the Phish-Guard AI package."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EmailMessage:
    """A single email reduced to the fields we care about for analysis."""

    uid: str
    sender: str
    subject: str
    body: str
