"""One place to ask "what time is it?".

Why a separate file: the tests need to pretend it is 3 a.m. (off-hours alert) or
jump 20 minutes ahead (lockout expiry). They do that by setting `_fixed`.
All timestamps are stored as UTC text like 2026-01-15T09:30:00.000000Z, so the
text is identical on every machine. That matters because timestamps are part of
the data we HMAC.
"""
from __future__ import annotations

from datetime import datetime, timezone

_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_fixed: datetime | None = None  # tests set this


def utcnow() -> datetime:
    return _fixed if _fixed is not None else datetime.now(timezone.utc)


def to_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(_FORMAT)


def now_text() -> str:
    return to_text(utcnow())


def parse(text: str) -> datetime:
    return datetime.strptime(text, _FORMAT).replace(tzinfo=timezone.utc)
