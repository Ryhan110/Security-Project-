"""ATTACK 3 - the smarter insider: change the row AND recompute its hash.

The attacker has read the source code, so they know EXACTLY how a record is
serialised before hashing (the algorithm is not a secret, and should not need
to be). What they do not have is the HMAC key from .env.

So they do the best they can: SHA-256 over the correct serialisation.
If the system used a plain hash, this would work perfectly and the tampering
would be invisible. Because the system uses an HMAC, it fails.

Usage: python attacks/tamper_and_recompute_hash.py [--seq N] [--to KG]
"""
from __future__ import annotations

import argparse
import hashlib

from _common import drop_triggers, open_as_insider, restore_triggers, say

from rationguard.crypto import canonical      # public algorithm, no key involved
from rationguard.integrity import TX_FIELDS   # public field order


def run(db_path=None, seq: int | None = None, new_quantity: int = 25) -> dict:
    connection = open_as_insider(db_path)
    if seq is None:
        row = connection.execute("SELECT * FROM transactions ORDER BY seq DESC LIMIT 1").fetchone()
    else:
        row = connection.execute("SELECT * FROM transactions WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        raise SystemExit("No transaction to tamper with. Create one first.")

    record = dict(row)
    record["quantity_kg"] = new_quantity
    serialised = canonical("tx:v1", [(name, record[name]) for name in TX_FIELDS])
    forged = hashlib.sha256(serialised).hexdigest()   # no key: all the attacker can do

    say(f"Target: transaction seq {row['seq']}, quantity_kg {row['quantity_kg']} -> {new_quantity}.")
    say("I know the serialisation format from the source code. Recomputing the hash...")
    say(f"  stored value (real HMAC) : {row['hmac'][:32]}...")
    say(f"  my recomputed SHA-256    : {forged[:32]}...")
    triggers = drop_triggers(connection, "transactions")
    connection.execute("UPDATE transactions SET quantity_kg = ?, hmac = ? WHERE seq = ?",
                       (new_quantity, forged, row["seq"]))
    restore_triggers(connection, triggers)
    connection.commit()
    connection.close()
    say("Row and hash column both updated. With a plain hash this would now look valid.")
    say("But the real value needs the secret key from .env, which is not in this file.")
    return {"seq": row["seq"], "before": row["quantity_kg"], "after": new_quantity,
            "original_hmac": row["hmac"], "forged_hash": forged}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int)
    parser.add_argument("--to", type=int, default=25)
    args = parser.parse_args()
    run(seq=args.seq, new_quantity=args.to)
