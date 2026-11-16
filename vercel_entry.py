"""Entry point for the hosted demo on Vercel.

pyproject.toml tells Vercel to serve `app` from this file.

Vercel runs the app as a short-lived "serverless function": there is no
permanent disk, only a temporary /tmp folder that is wiped whenever a fresh
copy of the function starts. So this file:
  1. points the database and the anchor file at /tmp, and
  2. creates and seeds the database if it is not there yet.

Consequences (also shown as a banner on every page): data resets from time
to time, and the direct-file attack scripts cannot be run against the hosted
copy. The full demo is meant to be run locally with ./demo.sh.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault("RG_DB_PATH", "/tmp/rationguard.db")
os.environ.setdefault("RG_ANCHOR_FILE", "/tmp/anchors.jsonl")
os.environ.setdefault("RG_COOKIE_SECURE", "true")      # Vercel always serves HTTPS
os.environ.setdefault("RG_DEMO_BANNER",
                      "Hosted demo with fictional data. Everything resets periodically; "
                      "the insider-attack demo runs locally (see README).")

from sqlalchemy import func, select  # noqa: E402

from rationguard.db import init_db, new_session  # noqa: E402
from rationguard.models import User  # noqa: E402

init_db()
with new_session() as _db:
    _empty = _db.execute(select(func.count()).select_from(User)).scalar_one() == 0
    _db.rollback()
    if _empty:
        from rationguard.seed import seed
        seed(_db)

from rationguard.app import app  # noqa: E402,F401  (Vercel serves this object)
