"""ATTACK 2 - delete a transaction row directly from the database file.

Story: a distribution that should never have happened is made to "disappear".

Usage: python attacks/delete_transaction.py [--seq N]
"""
from __future__ import annotations

import argparse

from _common import drop_triggers, open_as_insider, restore_triggers, say


def run(db_path=None, seq: int | None = None) -> dict:
    connection = open_as_insider(db_path)
    if seq is None:   # default: the second transaction if there is one (a row from the middle)
        row = connection.execute(
            "SELECT * FROM transactions ORDER BY (seq = 2) DESC, seq DESC LIMIT 1").fetchone()
    else:
        row = connection.execute("SELECT * FROM transactions WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        raise SystemExit("No transaction to delete. Create one first.")

    say(f"Target: transaction seq {row['seq']} ({row['quantity_kg']} kg {row['commodity']}).")
    triggers = drop_triggers(connection, "transactions")
    connection.execute("DELETE FROM transactions WHERE seq = ?", (row["seq"],))
    restore_triggers(connection, triggers)
    connection.commit()
    connection.close()
    say("Row deleted, triggers restored. The table looks tidy again.")
    return {"seq": row["seq"], "commodity": row["commodity"], "quantity_kg": row["quantity_kg"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int)
    run(seq=parser.parse_args().seq)
