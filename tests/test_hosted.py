"""The hosted (Vercel + Turso) configuration.

Vercel runs several short-lived copies of the app. They only behave like one
system if they share the database AND the anchors. These tests check both,
without a network: the Turso driver is pointed at a local file.
"""
import pytest

from conftest import csrf, issue, login, new_client, verify


@pytest.fixture
def hosted(env, monkeypatch):
    """Rebuild the test database through the Turso driver, anchors in the DB."""
    from rationguard import db
    from rationguard.config import get_settings
    from rationguard.seed import seed
    monkeypatch.setenv("RG_DATABASE_URL", f"file:{env / 'hosted.db'}")
    monkeypatch.setenv("RG_ANCHOR_STORE", "db")
    get_settings.cache_clear()
    db.reset_engine()
    db.init_db()
    with db.new_session() as session:
        seed(session)
    yield env
    db.reset_engine()
    monkeypatch.undo()
    get_settings.cache_clear()


def test_engine_uses_the_turso_driver(hosted):
    from rationguard.db import get_engine
    assert get_engine().url.drivername == "sqlite+libsql"


def test_remote_url_needs_a_token(monkeypatch):
    from rationguard.config import get_settings
    from rationguard.db import engine_url_and_args
    monkeypatch.setenv("RG_DATABASE_URL", "libsql://demo-db.turso.io")
    monkeypatch.delenv("RG_DATABASE_AUTH_TOKEN", raising=False)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="AUTH_TOKEN"):
        engine_url_and_args()
    monkeypatch.setenv("RG_DATABASE_AUTH_TOKEN", "t")
    get_settings.cache_clear()
    url, args = engine_url_and_args()
    assert url == "sqlite+libsql://demo-db.turso.io?secure=true" and args["auth_token"] == "t"
    monkeypatch.undo()
    get_settings.cache_clear()


def test_login_survives_across_app_copies(hosted):
    """The reported bug: a session made by one copy must work in another.
    Two separate engines play the role of two Vercel instances."""
    from rationguard import db
    dealer = new_client("dealer1")
    db.reset_engine()                       # "a different instance" now serves the request
    assert dealer.get("/dealer").status_code == 200
    assert issue(dealer, "HH-000101", "rice", 5).status_code == 201
    db.reset_engine()
    auditor = new_client("auditor1")
    page = auditor.get("/auditor/transactions").text
    assert "5 kg" in page                   # the other copy sees the transaction


def test_everything_verifies_green_through_the_turso_driver(hosted):
    dealer = new_client("dealer1")
    for code in ("HH-000101", "HH-000104", "HH-000107"):
        assert issue(dealer, code).status_code == 201
    from rationguard import audit
    audit.write_anchor()
    report = verify()
    assert report.ok, [f.message for f in report.findings]


def test_anchors_are_stored_in_the_database_and_append_only(hosted):
    import sqlite3
    from rationguard import audit
    anchor = audit.write_anchor()
    connection = sqlite3.connect(hosted / "hosted.db")
    count = connection.execute("SELECT COUNT(*) FROM anchors").fetchone()[0]
    assert count >= 1 and audit.read_anchors()[-1]["signature"] == anchor["signature"]
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        connection.execute("DELETE FROM anchors")
    connection.close()


def test_tampering_is_still_detected_in_hosted_mode(hosted):
    import sqlite3
    issue(new_client("dealer1"), "HH-000101", "rice", 5)
    connection = sqlite3.connect(hosted / "hosted.db")
    connection.execute("DROP TRIGGER transactions_no_update")
    connection.execute("UPDATE transactions SET quantity_kg = 25 WHERE seq = 1")
    connection.commit()
    connection.close()
    kinds = {(f.kind, f.record) for f in verify().findings}
    assert ("MODIFIED", "transaction seq 1") in kinds


def test_forged_anchor_row_is_detected(hosted):
    import json
    import sqlite3
    from rationguard import audit
    audit.write_anchor()
    connection = sqlite3.connect(hosted / "hosted.db")
    connection.execute("DROP TRIGGER anchors_no_update")
    row_id, line = connection.execute("SELECT id, line FROM anchors ORDER BY id DESC LIMIT 1").fetchone()
    forged = json.loads(line)
    forged["audit_seq"] -= 3
    connection.execute("UPDATE anchors SET line = ? WHERE id = ?", (json.dumps(forged), row_id))
    connection.commit()
    connection.close()
    assert any(f.kind == "ANCHOR_INVALID" for f in verify().findings)


def test_csrf_and_rbac_still_hold_in_hosted_mode(hosted):
    household = new_client("hh000101")
    assert household.get("/households/HH-000102/history").status_code == 403
    dealer = new_client("dealer1")
    assert dealer.post("/transactions", data={"hh_code": "HH-000101"}).status_code == 403
    assert csrf(dealer) and login(new_client(), "dealer1", "wrong-password-x").status_code == 401


def test_vercel_entry_boots_seeds_once_and_shares_state(env, monkeypatch):
    """Start the real Vercel entry point twice against one shared database:
    the second start must not seed again, and a login made through the first
    must work through the second."""
    import base64
    import importlib.util
    import os
    from pathlib import Path
    from fastapi.testclient import TestClient
    from rationguard import db
    from rationguard.config import get_settings
    for which in ("PRIVATE", "PUBLIC"):
        pem = Path(os.environ[f"RG_SIGNING_{which}_KEY"]).read_bytes()
        monkeypatch.setenv(f"RG_SIGNING_{which}_KEY_B64", base64.b64encode(pem).decode())
    monkeypatch.setenv("RG_DATABASE_URL", f"file:{env / 'shared.db'}")
    monkeypatch.delenv("RG_ANCHOR_STORE", raising=False)
    monkeypatch.delenv("RG_DEMO_BANNER", raising=False)

    def start_copy():
        get_settings.cache_clear()
        db.reset_engine()
        spec = importlib.util.spec_from_file_location("vercel_entry", Path(__file__).parent.parent / "vercel_entry.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return TestClient(module.app, follow_redirects=False)

    first = start_copy()
    assert login(first, "dealer1").status_code == 303
    assert get_settings().anchor_store == "db"
    second = start_copy()                                  # seeding must not run twice
    import sqlite3
    users = sqlite3.connect(env / "shared.db").execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert users == 18
    second.cookies.update(first.cookies)                   # same browser, other copy
    assert second.get("/dealer").status_code == 200
    assert verify().ok
    db.reset_engine()
    monkeypatch.undo()
    get_settings.cache_clear()
