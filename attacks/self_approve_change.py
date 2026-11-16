"""ATTACK 6 - one admin tries to raise a quota without a second person.

Try 1 (through the app): admin1 proposes a change, then approves it himself.
Try 2 (app + database):  admin1 edits the change-request row so that it looks
                         as if admin2 proposed it, then approves it.

Usage: python attacks/self_approve_change.py
"""
from __future__ import annotations

from _common import app_client, form_token, login, open_as_insider, say


def run(db_path=None, hh_code: str = "HH-000101", new_quota: int = 60,
        password: str | None = None) -> dict:
    client = app_client()
    login(client, "admin1", password)
    page = client.get(f"/households/{hh_code}")
    token = form_token(page.text)

    proposed = client.post("/admin/changes", data={
        "csrf_token": token, "hh_code": hh_code, "field": "quota_rice_kg",
        "new_value": str(new_quota), "reason": "family grew (fabricated reason)"})
    say(f"admin1 proposes: {hh_code} rice quota -> {new_quota} kg      HTTP {proposed.status_code}")

    connection = open_as_insider(db_path)
    request_id = connection.execute("SELECT MAX(id) FROM change_requests").fetchone()[0]
    quota_before = connection.execute(
        "SELECT quota_rice_kg FROM households WHERE hh_code = ?", (hh_code,)).fetchone()[0]

    first = client.post(f"/admin/changes/{request_id}/approve", data={"csrf_token": token})
    say(f"Try 1: admin1 approves own request #{request_id}              HTTP {first.status_code} "
        "(blocked: two-person rule)")

    other_admin = connection.execute("SELECT id FROM users WHERE username = 'admin2'").fetchone()[0]
    connection.execute("UPDATE change_requests SET proposed_by = ? WHERE id = ?", (other_admin, request_id))
    connection.commit()
    say("Edited the database: the request now claims admin2 proposed it.")
    second = client.post(f"/admin/changes/{request_id}/approve", data={"csrf_token": token})
    say(f"Try 2: admin1 approves the doctored request      HTTP {second.status_code} "
        "(blocked: the request row failed its HMAC check)")

    quota_after = connection.execute(
        "SELECT quota_rice_kg FROM households WHERE hh_code = ?", (hh_code,)).fetchone()[0]
    connection.close()
    print()
    print(f"  Rice quota of {hh_code}: before {quota_before} kg, after both attempts {quota_after} kg (unchanged).")
    return {"request_id": request_id, "propose_status": proposed.status_code,
            "self_approve_status": first.status_code, "doctored_approve_status": second.status_code,
            "quota_before": quota_before, "quota_after": quota_after}


if __name__ == "__main__":
    run()
