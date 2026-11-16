"""Test setup.

Every test gets its OWN copy of a freshly seeded database file and its own
anchor file, with throw-away keys generated for this test run. Nothing here
touches the developer's real .env, keys or database.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "attacks"))

PASSWORD = "test-" + secrets.token_urlsafe(12)   # random per run, never hard-coded


def _configure(db_path: Path, anchor_file: Path) -> None:
    from rationguard import clock, db, security
    from rationguard.config import get_settings
    os.environ["RG_DB_PATH"] = str(db_path)
    os.environ["RG_ANCHOR_FILE"] = str(anchor_file)
    get_settings.cache_clear()
    db.reset_engine()
    security.login_limiter.reset()
    clock._fixed = None


@pytest.fixture(scope="session")
def template(tmp_path_factory):
    """Generate keys and build one seeded database to copy from."""
    base = tmp_path_factory.mktemp("rationguard")
    private_key = Ed25519PrivateKey.generate()
    (base / "private.pem").write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (base / "public.pem").write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.environ.update({
        "RG_TX_HMAC_KEY": secrets.token_hex(32), "RG_AUDIT_HMAC_KEY": secrets.token_hex(32),
        "RG_RECORD_HMAC_KEY": secrets.token_hex(32), "RG_SESSION_SECRET": secrets.token_hex(32),
        "RG_FERNET_KEY": Fernet.generate_key().decode(), "RG_SEED_PASSWORD": PASSWORD,
        "RG_SIGNING_PRIVATE_KEY": str(base / "private.pem"),
        "RG_SIGNING_PUBLIC_KEY": str(base / "public.pem"),
        "RG_ANCHOR_EVERY": "5", "RG_COOKIE_SECURE": "false",
        "RG_BUSINESS_START_HOUR": "6", "RG_BUSINESS_END_HOUR": "22", "RG_TZ_OFFSET_MINUTES": "0",
    })
    _configure(base / "template.db", base / "template.anchors.jsonl")
    from rationguard.db import init_db, new_session, reset_engine
    from rationguard.seed import seed
    init_db()
    with new_session() as session:
        seed(session)
    reset_engine()
    return base


@pytest.fixture(autouse=True)
def env(template, tmp_path):
    """Fresh database + anchors for each test. The clock starts at midday so
    the off-hours alert does not depend on when the tests are run."""
    from datetime import datetime, timezone
    from rationguard import clock, db
    shutil.copy(template / "template.db", tmp_path / "test.db")
    shutil.copy(template / "template.anchors.jsonl", tmp_path / "anchors.jsonl")
    _configure(tmp_path / "test.db", tmp_path / "anchors.jsonl")
    clock._fixed = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
    yield tmp_path
    clock._fixed = None
    db.reset_engine()


@pytest.fixture
def db_path(env) -> Path:
    return env / "test.db"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from rationguard.app import app
    return TestClient(app, follow_redirects=False)


# ---- helpers shared by the tests ------------------------------------------
def token_of(html: str) -> str:
    found = re.search(r'name="csrf_token" value="([^"]*)"', html)
    return found.group(1) if found else ""


def login(client, username: str, password: str = PASSWORD):
    page = client.get("/login")
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": token_of(page.text)})


def new_client(username: str | None = None):
    from fastapi.testclient import TestClient
    from rationguard.app import app
    browser = TestClient(app, follow_redirects=False)
    if username:
        assert login(browser, username).status_code == 303
    return browser


def csrf(client) -> str:
    """The CSRF token for the logged-in session (what the forms contain)."""
    from rationguard import security
    return security.csrf_token(client.cookies.get(security.SESSION_COOKIE))


def issue(client, hh_code: str = "HH-000101", commodity: str = "rice", kg: int = 5, key: str | None = None):
    return client.post("/transactions", data={
        "csrf_token": csrf(client), "hh_code": hh_code, "commodity": commodity,
        "quantity_kg": str(kg), "idempotency_key": key or secrets.token_urlsafe(24)})


def verify():
    from rationguard.db import new_session
    from rationguard.verify import run_verification
    with new_session() as session:
        return run_verification(session)


def alerts(report=None):
    from rationguard.db import new_session
    from rationguard.detection import compute_alerts
    with new_session() as session:
        return compute_alerts(session, report)


def audit_rows(db_path: Path, action: str | None = None) -> list[sqlite3.Row]:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    sql = "SELECT * FROM audit_log" + (" WHERE action = ?" if action else "") + " ORDER BY seq"
    rows = connection.execute(sql, (action,) if action else ()).fetchall()
    connection.close()
    return rows


def advance(minutes: float) -> None:
    from datetime import timedelta
    from rationguard import clock
    clock._fixed = clock._fixed + timedelta(minutes=minutes)


def sql(db_path: Path, statement: str, params: tuple = ()) -> list[tuple]:
    """Run raw SQL on the file, the way an insider (or a checking test) would."""
    connection = sqlite3.connect(db_path)
    rows = connection.execute(statement, params).fetchall()
    connection.commit()
    connection.close()
    return rows


def propose(admin, hh_code: str, field: str, value, reason: str = "documented family change"):
    return admin.post("/admin/changes", data={"csrf_token": csrf(admin), "hh_code": hh_code,
                                              "field": field, "new_value": str(value), "reason": reason})


def decide(admin, request_id: int, action: str = "approve"):
    return admin.post(f"/admin/changes/{request_id}/{action}", data={"csrf_token": csrf(admin)})


def kinds(items) -> list[str]:
    return [item.kind for item in items]
