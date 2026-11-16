"""BONUS ATTACK - remove the newest transaction AND every audit entry from
that point on.

Why this one is special: nothing is left "broken". The transaction chain and
the audit chain that remain are both perfectly valid, just shorter. Hash
chains alone cannot see this. Only the signed anchor (outside the database)
remembers that the chains used to be longer.

Usage: python attacks/truncate_log_tail.py
"""
from __future__ import annotations

from _common import drop_triggers, open_as_insider, restore_triggers, say


def run(db_path=None) -> dict:
    connection = open_as_insider(db_path)
    tx = connection.execute("SELECT * FROM transactions ORDER BY seq DESC LIMIT 1").fetchone()
    if tx is None:
        raise SystemExit("No transaction to remove. Create one first.")
    entry = connection.execute(
        "SELECT seq FROM audit_log WHERE action = 'TRANSACTION_CREATED' AND object_id = ?",
        (str(tx["seq"]),)).fetchone()
    cut_from = entry["seq"] if entry else None

    say(f"Removing transaction seq {tx['seq']} and all audit entries from #{cut_from} onwards.")
    triggers = drop_triggers(connection, "transactions") + drop_triggers(connection, "audit_log")
    connection.execute("DELETE FROM transactions WHERE seq = ?", (tx["seq"],))
    removed = 0
    if cut_from is not None:
        removed = connection.execute("DELETE FROM audit_log WHERE seq >= ?", (cut_from,)).rowcount
    restore_triggers(connection, triggers)
    connection.commit()
    connection.close()
    say(f"Removed 1 transaction and {removed} audit entries. Both chains still link up perfectly.")
    return {"tx_seq": tx["seq"], "audit_cut_from": cut_from, "audit_entries_removed": removed}


if __name__ == "__main__":
    run()
