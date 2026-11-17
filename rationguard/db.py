"""Database setup (SQLite through SQLAlchemy).

Security notes:
* Every query in this project goes through SQLAlchemy with bound parameters,
  so user input is never glued into SQL text (no SQL injection).
* Triggers make the audit log and the transactions table append-only. An
  insider who owns the file can drop a trigger, so this is only "defence in
  depth": the real protection is the HMAC + hash chain, which a dropped
  trigger does not help the attacker to beat.
"""
from __future__ import annotations

import time
from typing import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None


def engine_url_and_args() -> tuple[str, dict]:
    """Where the database lives.

    Default: a local SQLite file (what the laptop demo and attack scripts use).
    Hosted demo: a Turso database, which is SQLite run as a shared service.
    Serverless hosts start several short-lived copies of the app; a shared
    database is the only way they all see the same logins and records.
    """
    settings = get_settings()
    remote = settings.database_url
    if not remote:
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{settings.db_path}", {"check_same_thread": False, "timeout": 15}

    if remote.startswith("file:"):
        # Same Turso driver, but on a local file. Used by the tests to check
        # the hosted code path without a network or an account.
        return (f"sqlite+libsql:///{remote[5:]}",
                {"isolation_level": None, "check_same_thread": False})

    host = remote.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    if not host:
        raise RuntimeError("RG_DATABASE_URL is set but has no host name.")
    if not settings.database_auth_token:
        raise RuntimeError("RG_DATABASE_URL is set but RG_DATABASE_AUTH_TOKEN is missing.")
    # isolation_level=None: we send BEGIN ourselves (see below).
    return (f"sqlite+libsql://{host}?secure=true",
            {"auth_token": settings.database_auth_token, "isolation_level": None,
             "check_same_thread": False})


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url, args = engine_url_and_args()
        engine = create_engine(url, connect_args=args, pool_pre_ping=url.startswith("sqlite+libsql"))

        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_connection, _record):
            # We control BEGIN ourselves (see below). The Turso driver takes
            # this setting at connect time instead (see engine_url_and_args).
            if url.startswith("sqlite:///"):
                dbapi_connection.isolation_level = None
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def _on_begin(connection):
            # BEGIN IMMEDIATE takes the write lock straight away, so only one
            # writer runs at a time. That guarantees two transactions can never
            # be given the same sequence number in the hash chain.
            if url.startswith("sqlite:///"):
                connection.exec_driver_sql("BEGIN IMMEDIATE")   # sqlite3 waits up to `timeout`
                return
            # The Turso driver does not wait when another copy of the app holds
            # the write lock; it fails at once. So we wait and retry briefly.
            for attempt in range(40):
                try:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                    return
                except Exception as error:   # driver raises a plain ValueError
                    if "locked" not in str(error).lower() and "busy" not in str(error).lower():
                        raise
                    time.sleep(min(0.05 * (attempt + 1), 0.5))
            raise RuntimeError("Database stayed busy for too long; please retry.")

        _engine = engine
    return _engine


def reset_engine() -> None:
    """Forget the cached engine (used by tests that switch database files)."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def new_session() -> Session:
    return Session(get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one database session per request."""
    session = new_session()
    try:
        yield session
    finally:
        session.close()


# name -> SQL. The verification engine checks that every one of these exists.
TRIGGERS: dict[str, str] = {
    "audit_log_no_update": """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE blocked'); END""",
    "audit_log_no_delete": """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: DELETE blocked'); END""",
    "transactions_no_update": """
        CREATE TRIGGER IF NOT EXISTS transactions_no_update BEFORE UPDATE ON transactions
        BEGIN SELECT RAISE(ABORT, 'transactions are immutable: UPDATE blocked'); END""",
    "anchors_no_update": """
        CREATE TRIGGER IF NOT EXISTS anchors_no_update BEFORE UPDATE ON anchors
        BEGIN SELECT RAISE(ABORT, 'anchors are append-only: UPDATE blocked'); END""",
    "anchors_no_delete": """
        CREATE TRIGGER IF NOT EXISTS anchors_no_delete BEFORE DELETE ON anchors
        BEGIN SELECT RAISE(ABORT, 'anchors are append-only: DELETE blocked'); END""",
    "transactions_no_delete": """
        CREATE TRIGGER IF NOT EXISTS transactions_no_delete BEFORE DELETE ON transactions
        BEGIN SELECT RAISE(ABORT, 'transactions are immutable: DELETE blocked'); END""",
}


def init_db() -> None:
    from . import models  # noqa: F401  (registers the tables)

    engine = get_engine()
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        for sql in TRIGGERS.values():
            connection.execute(text(sql))


def existing_triggers(session: Session) -> set[str]:
    rows = session.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'"))
    return {row[0] for row in rows}
