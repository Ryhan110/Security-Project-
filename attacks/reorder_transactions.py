"""BONUS ATTACK - swap the positions (sequence numbers) of two transactions.

Usage: python attacks/reorder_transactions.py [--a N --b M]
"""
from __future__ import annotations

import argparse

from _common import drop_triggers, open_as_insider, restore_triggers, say


def run(db_path=None, a: int | None = None, b: int | None = None) -> dict:
    connection = open_as_insider(db_path)
    highest = connection.execute("SELECT MAX(seq) FROM transactions").fetchone()[0] or 0
    if highest < 2:
        raise SystemExit("Need at least two transactions to reorder.")
    a, b = a or highest - 1, b or highest
    say(f"Swapping the sequence numbers of transactions {a} and {b}.")
    triggers = drop_triggers(connection, "transactions")
    connection.execute("UPDATE transactions SET seq = -1 WHERE seq = ?", (a,))
    connection.execute("UPDATE transactions SET seq = ? WHERE seq = ?", (a, b))
    connection.execute("UPDATE transactions SET seq = ? WHERE seq = -1", (b,))
    restore_triggers(connection, triggers)
    connection.commit()
    connection.close()
    return {"a": a, "b": b}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a", type=int)
    parser.add_argument("--b", type=int)
    args = parser.parse_args()
    run(a=args.a, b=args.b)
