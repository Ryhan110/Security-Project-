"""Database tables.

Things worth noticing for the viva:
* Quantities are whole kilograms (integers). Decimals like 2.50 vs 2.5 would
  make the "canonical" text we HMAC ambiguous, so we avoid them.
* Timestamps are stored as fixed-format UTC text for the same reason.
* `row_hmac` / `hmac` / `entry_hash` columns hold a keyed hash. The key is
  NOT in this database, so someone who edits a row cannot fix its hash.
* Name, address and phone are stored encrypted (`*_enc` columns).
"""
from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

ROLES = ("household", "dealer", "admin", "auditor")
COMMODITIES = ("rice", "wheat", "sugar")


class Shop(Base):
    __tablename__ = "shops"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True)
    name: Mapped[str] = mapped_column(String(100))


class Household(Base):
    __tablename__ = "households"
    id: Mapped[int] = mapped_column(primary_key=True)
    hh_code: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # HH-000123
    head_name_enc: Mapped[str] = mapped_column(Text)   # Fernet ciphertext
    address_enc: Mapped[str] = mapped_column(Text)     # Fernet ciphertext
    phone_enc: Mapped[str] = mapped_column(Text)       # Fernet ciphertext
    family_size: Mapped[int] = mapped_column(Integer)
    shop_id: Mapped[int] = mapped_column(ForeignKey("shops.id"))
    quota_rice_kg: Mapped[int] = mapped_column(Integer)
    quota_wheat_kg: Mapped[int] = mapped_column(Integer)
    quota_sugar_kg: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer, default=1)
    # The approved change request that produced the current values (None = as enrolled).
    last_change_request_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    row_hmac: Mapped[str] = mapped_column(String(64))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)  # Argon2id, never the password
    role: Mapped[str] = mapped_column(String(20))
    shop_id: Mapped[int | None] = mapped_column(ForeignKey("shops.id"), nullable=True)
    household_id: Mapped[int | None] = mapped_column(ForeignKey("households.id"), nullable=True)
    is_active: Mapped[int] = mapped_column(Integer, default=1)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[str | None] = mapped_column(String(40), nullable=True)
    row_hmac: Mapped[str] = mapped_column(String(64))


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    # SHA-256 of the cookie value. A thief who reads this table cannot log in
    # with it, because the cookie needs the original value, not its hash.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))
    ip: Mapped[str] = mapped_column(String(64))


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, unique=True, index=True)  # 1, 2, 3 ... no gaps
    household_id: Mapped[int] = mapped_column(ForeignKey("households.id"), index=True)
    shop_id: Mapped[int] = mapped_column(ForeignKey("shops.id"))
    dealer_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    commodity: Mapped[str] = mapped_column(String(20))
    quantity_kg: Mapped[int] = mapped_column(Integer)
    entitlement_month: Mapped[str] = mapped_column(String(7))  # YYYY-MM
    created_at: Mapped[str] = mapped_column(String(40))
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True)
    prev_hash: Mapped[str] = mapped_column(String(64))  # hmac of transaction seq-1
    hmac: Mapped[str] = mapped_column(String(64))       # HMAC-SHA256 over all fields above


class ChangeRequest(Base):
    """A proposed change to beneficiary data, waiting for a second admin."""
    __tablename__ = "change_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    household_id: Mapped[int] = mapped_column(ForeignKey("households.id"))
    field: Mapped[str] = mapped_column(String(30))
    old_value: Mapped[str] = mapped_column(String(50))
    new_value: Mapped[str] = mapped_column(String(50))
    reason: Mapped[str] = mapped_column(String(300))
    proposed_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    proposed_at: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(10), default="PENDING")  # PENDING/APPROVED/REJECTED
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    row_hmac: Mapped[str] = mapped_column(String(64))


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("seq"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[str] = mapped_column(String(40))                    # when
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # who
    actor_username: Mapped[str] = mapped_column(String(50))
    actor_role: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(40), index=True)    # what
    object_type: Mapped[str] = mapped_column(String(30))
    object_id: Mapped[str] = mapped_column(String(100))
    ip: Mapped[str] = mapped_column(String(64))                    # from where
    before_json: Mapped[str] = mapped_column(Text)                 # value before
    after_json: Mapped[str] = mapped_column(Text)                  # value after
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class AnchorRecord(Base):
    """Signed anchors, used ONLY when RG_ANCHOR_STORE=db (the hosted demo).

    On a laptop the anchors live in a file outside the database, which is the
    stronger design. A serverless host has no shared disk, so the hosted demo
    keeps them here instead. Each line is still Ed25519-signed, so a forged
    anchor is detected, but an insider who can delete rows here AND truncate
    the log would not be caught. README "Limitations" explains this.
    """
    __tablename__ = "anchors"
    id: Mapped[int] = mapped_column(primary_key=True)
    line: Mapped[str] = mapped_column(Text)
