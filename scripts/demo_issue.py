"""Demo helper: a dealer records one distribution through the REAL web app
(login, CSRF token, permission checks and all), without starting a server.

Usage: python scripts/demo_issue.py [dealer] [household] [commodity] [kg]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "attacks"))

from _common import app_client, form_token, login  # noqa: E402


def issue(dealer: str, hh_code: str, commodity: str, quantity_kg: int) -> int:
    client = app_client()
    login(client, dealer)
    page = client.get("/dealer").text
    key = re.search(r'name="idempotency_key" value="([^"]*)"', page).group(1)
    response = client.post("/transactions", data={
        "csrf_token": form_token(page), "idempotency_key": key, "hh_code": hh_code,
        "commodity": commodity, "quantity_kg": str(quantity_kg)})
    note = re.search(r'class="banner (?:good|bad)">([^<]*)<', response.text)
    print(f"  {dealer} -> {hh_code}: {quantity_kg} kg {commodity}   HTTP {response.status_code}   "
          f"{note.group(1) if note else ''}")
    return response.status_code


if __name__ == "__main__":
    args = sys.argv[1:]
    dealer, hh_code, commodity, kg = (args + ["dealer1", "HH-000101", "rice", "5"][len(args):])[:4]
    raise SystemExit(0 if issue(dealer, hh_code, commodity, int(kg)) == 201 else 1)
