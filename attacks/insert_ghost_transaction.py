"""BONUS ATTACK - insert a "ghost" transaction that never happened.

Story: the dealer invents a distribution to a real household to explain
missing stock. The attacker copies the chain link correctly, but still
cannot produce a valid HMAC.

Usage: python attacks/insert_ghost_transaction.py
"""
from __future__ import annotations

import secrets

from _common import open_as_insider, say


def run(db_path=None, quantity_kg: int = 10) -> dict:
    connection = open_as_insider(db_path)
    last = connection.execute("SELECT * FROM transactions ORDER BY seq DESC LIMIT 1").fetchone()
    if last is None:
        raise SystemExit("Need at least one real transaction to copy from.")
    seq = last["seq"] + 1
    connection.execute(
        "INSERT INTO transactions (seq, household_id, shop_id, dealer_id, commodity, quantity_kg, "
        "entitlement_month, created_at, idempotency_key, prev_hash, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (seq, last["household_id"], last["shop_id"], last["dealer_id"], "wheat", quantity_kg,
         last["entitlement_month"], last["created_at"], secrets.token_urlsafe(24),
         last["hmac"], secrets.token_hex(32)))   # prev_hash is right; the hmac is a guess
    connection.commit()
    connection.close()
    say(f"Inserted fake transaction seq {seq}: {quantity_kg} kg wheat, with a made-up hmac.")
    return {"seq": seq}


if __name__ == "__main__":
    run()
