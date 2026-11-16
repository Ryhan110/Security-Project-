"""ATTACK 1 - change a transaction's quantity directly in the database file.

Story: the dealer gave out 5 kg of rice but wants the books to say 25 kg, so
the missing 20 kg can be sold on the side.

Usage: python attacks/tamper_transaction.py [--seq N] [--to KG]
"""
from __future__ import annotations

import argparse

from _common import drop_triggers, open_as_insider, restore_triggers, say


def run(db_path=None, seq: int | None = None, new_quantity: int = 25) -> dict:
    connection = open_as_insider(db_path)
    if seq is None:   # prefer a 5 kg rice transaction, else the newest one
        row = connection.execute(
            "SELECT * FROM transactions ORDER BY (commodity = 'rice' AND quantity_kg = 5) DESC, "
            "seq DESC LIMIT 1").fetchone()
    else:
        row = connection.execute("SELECT * FROM transactions WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        raise SystemExit("No transaction to tamper with. Create one first.")

    say(f"Opening the SQLite file directly. Target: transaction seq {row['seq']} "
        f"({row['quantity_kg']} kg {row['commodity']}).")
    triggers = drop_triggers(connection, "transactions")
    say(f"Dropped {len(triggers)} protective trigger(s) on 'transactions'.")
    connection.execute("UPDATE transactions SET quantity_kg = ? WHERE seq = ?", (new_quantity, row["seq"]))
    restore_triggers(connection, triggers)
    say("Put the triggers back to cover my tracks.")
    connection.commit()
    connection.close()
    say(f"Done: quantity_kg {row['quantity_kg']} -> {new_quantity}. I did not touch the hmac column "
        "(I cannot compute a valid one).")
    return {"seq": row["seq"], "field": "quantity_kg", "before": row["quantity_kg"], "after": new_quantity}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int)
    parser.add_argument("--to", type=int, default=25)
    args = parser.parse_args()
    run(seq=args.seq, new_quantity=args.to)
