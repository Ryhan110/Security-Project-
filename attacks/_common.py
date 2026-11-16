"""Shared helpers for the attack scripts.

IMPORTANT FOR THE DEMO: the "direct edit" attacks use ONLY Python's built-in
sqlite3 module on the database file. They never load the secret keys. That is
exactly the position of an insider who can open the file but not read .env.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:          # allows `python attacks/xyz.py`
    sys.path.insert(0, str(ROOT))


def database_path(path: Path | str | None = None) -> Path:
    if path is not None:
        return Path(path)
    from rationguard.config import get_settings   # used for the file location only
    return get_settings().db_path


def say(text: str = "") -> None:
    print(f"  [attacker] {text}" if text else "")


def open_as_insider(path: Path | str | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path(path))
    connection.row_factory = sqlite3.Row
    return connection


def drop_triggers(connection: sqlite3.Connection, table: str) -> list[str]:
    """Remove the append-only triggers on a table and return their SQL, so
    the attacker can put them back afterwards and hide that they were gone."""
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?", (table,)).fetchall()
    for row in rows:
        connection.execute(f'DROP TRIGGER "{row["name"]}"')
    return [row["sql"] for row in rows]


def restore_triggers(connection: sqlite3.Connection, statements: list[str]) -> None:
    for sql in statements:
        connection.execute(sql)


# ---- helpers for the attacks that go through the web app -----------------
def form_token(html: str) -> str:
    """Read the CSRF token out of a page, like a browser submitting the form."""
    found = re.search(r'name="csrf_token" value="([^"]*)"', html)
    return found.group(1) if found else ""


def app_client():
    """An in-process browser for the real app (no server needs to be running)."""
    from fastapi.testclient import TestClient
    from rationguard.app import app
    return TestClient(app, follow_redirects=False)


def login(client, username: str, password: str | None = None):
    if password is None:
        from rationguard.config import seed_password
        password = seed_password()
    token = form_token(client.get("/login").text)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})
