"""ATTACK 5 - IDOR: a household user changes the ID in the URL.

This attack goes through the real web app (no database access needed): the
user logs in normally, then asks for ANOTHER household's history.

Usage: python attacks/idor_attempt.py
"""
from __future__ import annotations

from _common import app_client, login, open_as_insider, say


def run(db_path=None, username: str = "hh000101", own: str = "HH-000101",
        victim: str = "HH-000102", password: str | None = None) -> dict:
    client = app_client()
    login(client, username, password)
    say(f"Logged in as {username} (household {own}).")

    mine = client.get(f"/households/{own}/history")
    say(f"GET /households/{own}/history     -> HTTP {mine.status_code} (my own data: allowed)")
    theirs = client.get(f"/households/{victim}/history")
    say(f"GET /households/{victim}/history     -> HTTP {theirs.status_code} (changed the ID in the URL)")
    record = client.get(f"/households/{victim}")
    say(f"GET /households/{victim}             -> HTTP {record.status_code} (their personal record)")
    ghost = client.get("/households/HH-999999/history")
    say(f"GET /households/HH-999999/history     -> HTTP {ghost.status_code} (an ID that does not exist: "
        "same answer, so I cannot tell which IDs are real)")

    connection = open_as_insider(db_path)   # read-only peek, to show the denial was logged
    logged = connection.execute(
        "SELECT seq, actor_username, object_id, after_json FROM audit_log "
        "WHERE action = 'ACCESS_DENIED' ORDER BY seq DESC LIMIT 3").fetchall()
    connection.close()
    print()
    print("  What the audit log recorded:")
    for entry in reversed(logged):
        print(f"    #{entry['seq']} ACCESS_DENIED by {entry['actor_username']} on {entry['object_id']}")
    return {"own_status": mine.status_code, "victim_status": theirs.status_code,
            "victim_record_status": record.status_code, "ghost_status": ghost.status_code,
            "denials_logged": len(logged)}


if __name__ == "__main__":
    run()
