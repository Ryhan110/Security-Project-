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

from typing import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        path = get_settings().db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            f"sqlite:///{path}", connect_args={"check_same_thread": False, "timeout": 15}
        )

        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_connection, _record):
            # We control BEGIN ourselves (see below).
            dbapi_connection.isolation_level = None
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def _on_begin(connection):
            # BEGIN IMMEDIATE takes the write lock straight away, so only one
            # writer runs at a time. That guarantees two transactions can never
            # be given the same sequence number in the hash chain.
            connection.exec_driver_sql("BEGIN IMMEDIATE")

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
