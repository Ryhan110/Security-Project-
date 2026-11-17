"""Phase 4 - tamper-evident audit log, triggers and signed anchors."""
import json
import sqlite3

import pytest

from conftest import audit_rows, issue, new_client, sql, verify


def test_sensitive_action_is_logged_with_who_what_when_where_and_values(db_path):
    issue(new_client("dealer1"), "HH-000101", "rice", 5)
    entry = audit_rows(db_path, "TRANSACTION_CREATED")[-1]
    assert entry["actor_username"] == "dealer1" and entry["actor_role"] == "dealer"   # who
    assert entry["object_type"] == "transaction" and entry["object_id"] == "1"       # what
    assert entry["ts"].startswith("2026-03-10T12:00")                                 # when
    assert entry["ip"] == "testclient"                                                # from where
    after = json.loads(entry["after_json"])
    assert after["quantity_kg"] == 5 and after["commodity"] == "rice"                 # values


def test_audit_log_is_hash_chained(db_path):
    issue(new_client("dealer1"))
    rows = audit_rows(db_path)
    assert rows[0]["prev_hash"] == "0" * 64
    for previous, current in zip(rows, rows[1:]):
        assert current["seq"] == previous["seq"] + 1
        assert current["prev_hash"] == previous["entry_hash"]


@pytest.mark.parametrize("statement", [
    "UPDATE audit_log SET actor_username = 'nobody' WHERE seq = 1",
    "DELETE FROM audit_log WHERE seq = 1",
    "DELETE FROM audit_log",
])
def test_triggers_block_update_and_delete_on_audit_log(db_path, statement):
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        sql(db_path, statement)


@pytest.mark.parametrize("statement", [
    "UPDATE transactions SET quantity_kg = 25",
    "DELETE FROM transactions",
])
def test_triggers_block_update_and_delete_on_transactions(db_path, statement):
    issue(new_client("dealer1"))
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        sql(db_path, statement)


def test_dropped_trigger_is_reported(db_path):
    sql(db_path, "DROP TRIGGER audit_log_no_update")
    findings = verify().findings
    assert [f.kind for f in findings] == ["TRIGGER_MISSING"]
    assert "audit_log_no_update" in findings[0].record


def test_anchors_are_written_periodically_outside_the_database(env, db_path):
    from rationguard import audit
    start = len(audit.read_anchors())
    browser = new_client("dealer1")
    for code in ("HH-000101", "HH-000104", "HH-000107", "HH-000110"):
        issue(browser, code)
        issue(browser, code, "wheat", 1)
    anchors = audit.read_anchors()
    assert len(anchors) > start
    assert (env / "anchors.jsonl").exists()
    assert sql(db_path, "SELECT COUNT(*) FROM anchors")[0][0] == 0   # laptop mode: nothing in the DB
    newest = anchors[-1]
    assert audit_rows(db_path)[newest["audit_seq"] - 1]["entry_hash"] == newest["audit_hash"]


def test_anchor_signature_is_ed25519_and_verifies_with_public_key_only():
    from rationguard import audit
    from rationguard.crypto import signature_ok
    anchor = audit.write_anchor()
    assert len(bytes.fromhex(anchor["signature"])) == 64          # Ed25519 signatures are 64 bytes
    assert signature_ok(audit.anchor_message(anchor), anchor["signature"])
    forged = dict(anchor, audit_seq=anchor["audit_seq"] - 1)
    assert not signature_ok(audit.anchor_message(forged), anchor["signature"])


def test_edited_anchor_file_is_detected(env):
    from rationguard import audit
    audit.write_anchor()
    path = env / "anchors.jsonl"
    lines = path.read_text().splitlines()
    last = json.loads(lines[-1])
    last["audit_seq"] -= 3                                  # attacker lowers the recorded length
    path.write_text("\n".join(lines[:-1] + [json.dumps(last)]) + "\n")
    findings = verify().findings
    assert any(f.kind == "ANCHOR_INVALID" and "signature" in f.message for f in findings)


def test_deleted_anchor_file_is_detected(env):
    (env / "anchors.jsonl").unlink()
    assert [f.kind for f in verify().findings] == ["ANCHOR_INVALID"]


def test_removed_anchor_from_the_middle_is_detected(env):
    from rationguard import audit
    audit.write_anchor()
    audit.write_anchor()
    path = env / "anchors.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert any(f.kind == "ANCHOR_INVALID" and "out of sequence" in f.message for f in verify().findings)


def test_restoring_an_old_database_copy_is_caught_by_anchors(env, db_path):
    """Roll-back attack: every chain in the old copy is valid, only the anchor knows better."""
    import shutil
    from rationguard import audit, db
    shutil.copy(db_path, env / "old_copy.db")
    issue(new_client("dealer1"), kg=9)                       # the transaction to be 'forgotten'
    audit.write_anchor()
    db.reset_engine()
    shutil.copy(env / "old_copy.db", db_path)                # insider restores yesterday's file
    found = [f.kind for f in verify().findings]
    assert "LOG_TRUNCATED" in found and "DELETED" in found
