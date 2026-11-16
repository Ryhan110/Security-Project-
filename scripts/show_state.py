"""Demo helper: print the transactions table exactly as it is in the SQLite
file right now (plain sqlite3, no keys, no checks)."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rationguard.config import get_settings  # noqa: E402


def main() -> None:
    connection = sqlite3.connect(get_settings().db_path)
    rows = connection.execute(
        "SELECT t.seq, h.hh_code, t.commodity, t.quantity_kg, t.dealer_id, t.hmac "
        "FROM transactions t JOIN households h ON h.id = t.household_id ORDER BY t.seq").fetchall()
    connection.close()
    print(f"    {'seq':>3}  {'household':<10} {'commodity':<9} {'kg':>3}  {'dealer':>6}  hmac")
    for seq, code, commodity, quantity, dealer, mac in rows:
        print(f"    {seq:>3}  {code:<10} {commodity:<9} {quantity:>3}  {dealer:>6}  {mac[:16]}...")
    if not rows:
        print("    (no transactions)")


if __name__ == "__main__":
    main()
