"""Entry point for the hosted demo on Vercel.

pyproject.toml tells Vercel to serve `app` from this file.

Vercel runs the app as short-lived "serverless functions", often several
copies at once, each with only a temporary /tmp folder. A database in /tmp
would be private to one copy: you would log in on one copy and be sent back
to the login page by the next. So:

  * With RG_DATABASE_URL set (a Turso database), every copy shares one
    database, and the signed anchors are stored there too.
  * Without it, each copy falls back to its own /tmp database (only good for
    a quick look; logins and data are not shared).

Either way the direct-file attack scripts cannot run against the hosted copy.
The full demo is meant to be run locally with ./demo.sh.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SHARED_DB = bool(os.environ.get("RG_DATABASE_URL"))

os.environ.setdefault("RG_DB_PATH", "/tmp/rationguard.db")
os.environ.setdefault("RG_ANCHOR_FILE", "/tmp/anchors.jsonl")
# With a shared database the anchors must be shared too, so they go there.
os.environ.setdefault("RG_ANCHOR_STORE", "db" if SHARED_DB else "file")
os.environ.setdefault("RG_COOKIE_SECURE", "true")      # Vercel always serves HTTPS
os.environ.setdefault(
    "RG_DEMO_BANNER",
    "Hosted demo with fictional data. The insider-attack demo runs locally (see README)."
    if SHARED_DB else
    "Hosted demo with fictional data. Everything resets periodically; "
    "the insider-attack demo runs locally (see README).")

import time  # noqa: E402

from sqlalchemy import func, select  # noqa: E402

from rationguard.db import init_db, new_session  # noqa: E402
from rationguard.models import User  # noqa: E402


def _bootstrap() -> None:
    """Create the tables and, if the database is empty, the fictional data.

    Several copies of the app can start at the same moment. The check and the
    seeding happen inside ONE write transaction (BEGIN IMMEDIATE), so only the
    first copy seeds; the others then find the users already there.
    """
    init_db()
    with new_session() as db:
        empty = db.execute(select(func.count()).select_from(User)).scalar_one() == 0
        if empty:
            from rationguard.seed import seed
            seed(db)            # commits the same transaction
        else:
            db.rollback()


for _attempt in range(5):
    try:
        _bootstrap()
        break
    except Exception:          # another copy was creating tables at the same moment
        if _attempt == 4:
            raise
        time.sleep(1 + _attempt)

from rationguard.app import app  # noqa: E402,F401  (Vercel serves this object)
