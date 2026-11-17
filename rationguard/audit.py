"""Tamper-evident audit log + signed anchors.

HOW THE LOG PROTECTS ITSELF
1. Append-only: the app only ever INSERTs. Triggers block UPDATE/DELETE.
2. Hash chain: every entry stores the hash of the entry before it. Editing or
   removing entry N breaks the link at N (or N+1).
3. The hash is an HMAC with its own key, so an insider cannot re-forge links.
4. Anchors: every few entries we write "the chain head right now is X" to a
   file OUTSIDE the database, signed with Ed25519.

WHY ANCHORS ARE STILL NEEDED
A chain proves that what is there is consistent. It cannot prove nothing is
MISSING FROM THE END: delete the newest 10 entries and the remaining chain
is a perfectly valid, shorter chain. Restoring last week's backup of the DB
file looks valid too. The anchor remembers "there were at least N entries
and entry N had hash X", so both tricks are caught.
"""
from __future__ import annotations

import json
import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import clock
from .config import get_settings
from .crypto import GENESIS_HASH, canonical, hmac_hex, sha256_hex, sign
from .db import new_session
from .models import AnchorRecord, AuditLog, Transaction, User

AUDIT_FIELDS = (
    "seq", "ts", "actor_id", "actor_username", "actor_role", "action",
    "object_type", "object_id", "ip", "before_json", "after_json", "prev_hash",
)
ANCHOR_FIELDS = (
    "anchor_no", "created_at", "audit_seq", "audit_hash", "tx_seq", "tx_hash",
    "prev_anchor_hash",
)

# Any dictionary key containing one of these words is never written to the log.
_FORBIDDEN_WORDS = ("password", "passwd", "secret", "token", "cookie", "private_key",
                    "hmac_key", "fernet", "session")


def scrub(value: Any) -> Any:
    """Remove anything that looks like a credential before it is logged."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if any(word in str(key).lower() for word in _FORBIDDEN_WORDS):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = scrub(item)
        return clean
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    return value


def _json(value: dict | None) -> str:
    return json.dumps(scrub(value or {}), sort_keys=True, separators=(",", ":"))


def entry_hash(entry: Any) -> str:
    get = (lambda n: entry[n]) if isinstance(entry, dict) else (lambda n: getattr(entry, n))
    data = canonical("audit:v1", [(name, get(name)) for name in AUDIT_FIELDS])
    return hmac_hex(get_settings().audit_hmac_key, data)


def append(
    db: Session,
    *,
    actor: User | None,
    action: str,
    object_type: str = "",
    object_id: str = "",
    ip: str = "",
    before: dict | None = None,
    after: dict | None = None,
    actor_name: str | None = None,
) -> AuditLog:
    """Add one entry to the end of the chain. The caller commits, so the
    action and its log entry are saved together or not at all."""
    last = db.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)).scalar_one_or_none()
    entry = AuditLog(
        seq=(last.seq + 1) if last else 1,
        ts=clock.now_text(),
        actor_id=actor.id if actor else None,
        actor_username=(actor.username if actor else (actor_name or "anonymous"))[:50],
        actor_role=actor.role if actor else ("system" if actor_name == "system" else "none"),
        action=action,
        object_type=object_type,
        object_id=str(object_id)[:100],
        ip=ip[:64],
        before_json=_json(before),
        after_json=_json(after),
        prev_hash=last.entry_hash if last else GENESIS_HASH,
    )
    entry.entry_hash = entry_hash(entry)
    db.add(entry)
    db.flush()
    return entry


# --------------------------------------------------------------------------
# Anchors
# --------------------------------------------------------------------------
def anchor_message(anchor: dict) -> bytes:
    return canonical("anchor:v1", [(name, anchor[name]) for name in ANCHOR_FIELDS])


def _parse(lines) -> list[dict]:
    anchors = []
    for line in lines:
        if not line.strip():
            continue
        try:
            anchors.append(json.loads(line))
        except json.JSONDecodeError:
            anchors.append({"corrupt_line": line})
    return anchors


def _db_store() -> bool:
    return get_settings().anchor_store == "db"


def read_anchors(db: Session | None = None) -> list[dict]:
    """Pass `db` when the caller already has a transaction open, so we read
    through it instead of opening a second connection that would wait on it."""
    if _db_store():
        if db is not None:
            return _parse(db.execute(select(AnchorRecord.line).order_by(AnchorRecord.id)).scalars().all())
        with new_session() as own:
            lines = own.execute(select(AnchorRecord.line).order_by(AnchorRecord.id)).scalars().all()
            own.rollback()
        return _parse(lines)
    path = get_settings().anchor_file
    if not path.exists():
        return []
    return _parse(path.read_text().splitlines())


def _build_anchor(db: Session, previous: list[dict]) -> dict | None:
    audit_head = db.execute(
        select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)).scalar_one_or_none()
    tx_head = db.execute(
        select(Transaction).order_by(Transaction.seq.desc()).limit(1)).scalar_one_or_none()
    if audit_head is None:
        return None
    last = previous[-1] if previous else None
    anchor = {
        "anchor_no": len(previous) + 1,
        "created_at": clock.now_text(),
        "audit_seq": audit_head.seq,
        "audit_hash": audit_head.entry_hash,
        "tx_seq": tx_head.seq if tx_head else 0,
        "tx_hash": tx_head.hmac if tx_head else GENESIS_HASH,
        # Anchors are chained too, so one cannot be cut out of the middle.
        "prev_anchor_hash": sha256_hex(str(last.get("signature", "")).encode()) if last else GENESIS_HASH,
    }
    anchor["signature"] = sign(anchor_message(anchor))
    return anchor


def write_anchor() -> dict | None:
    """Sign the current heads of both chains and append them to the anchor store."""
    if _db_store():
        # One write transaction (BEGIN IMMEDIATE), so two copies of the app
        # running at once cannot both write "anchor #7".
        with new_session() as db:
            lines = db.execute(select(AnchorRecord.line).order_by(AnchorRecord.id)).scalars().all()
            anchor = _build_anchor(db, _parse(lines))
            if anchor is None:
                db.rollback()
                return None
            db.add(AnchorRecord(line=json.dumps(anchor, sort_keys=True)))
            db.commit()
        return anchor

    with new_session() as db:
        anchor = _build_anchor(db, read_anchors())
        db.rollback()
    if anchor is None:
        return None
    path = get_settings().anchor_file
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as handle:
        handle.write(json.dumps(anchor, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return anchor


def maybe_anchor() -> None:
    """Write an anchor when enough new entries have piled up."""
    anchors = read_anchors()
    last_seq = anchors[-1].get("audit_seq", 0) if anchors else 0
    with new_session() as db:
        head = db.execute(select(AuditLog.seq).order_by(AuditLog.seq.desc()).limit(1)).scalar()
    if head and head - last_seq >= get_settings().anchor_every:
        write_anchor()


def commit(db: Session) -> None:
    """Commit, then anchor. Anchoring AFTER the commit matters: if we signed
    first and the commit failed, the anchor would describe entries that do not
    exist and verification would raise a false alarm."""
    db.commit()
    maybe_anchor()
