"""Command line:  python -m rationguard <command>

  init-db            create tables and append-only triggers
  seed               load fictional demo data
  verify             re-check every HMAC, both chains and the anchors
  anchor             sign the current chain heads now
  set-role USER ROLE change a user's role (audit-logged, raises an alert)
  serve              start the web app on http://127.0.0.1:8000
  reset --yes        delete the demo database and anchor file
"""
from __future__ import annotations

import argparse
import json
import sys

from . import accounts, audit
from .config import ConfigError, get_settings
from .db import init_db, new_session


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rationguard", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("seed")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--json", action="store_true", help="machine-readable output")
    verify_parser.add_argument("--no-colour", action="store_true")
    sub.add_parser("anchor")
    role_parser = sub.add_parser("set-role")
    role_parser.add_argument("username")
    role_parser.add_argument("role")
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--port", type=int, default=8000)
    reset_parser = sub.add_parser("reset")
    reset_parser.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)

    try:
        settings = get_settings()
    except ConfigError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2

    if args.command == "reset":
        if not args.yes:
            print("This deletes the database and anchors. Re-run with --yes.")
            return 2
        for path in (settings.db_path, settings.anchor_file):
            path.unlink(missing_ok=True)
        print("Database and anchor file removed.")
        return 0

    if args.command == "init-db":
        init_db()
        print(f"Database ready at {settings.db_path}")
        return 0

    if args.command == "seed":
        from .seed import seed
        init_db()
        with new_session() as db:
            print("Seeded fictional data:", seed(db))
        return 0

    if args.command == "anchor":
        anchor = audit.write_anchor()
        print("Nothing to anchor yet." if anchor is None else
              f"Anchor #{anchor['anchor_no']} signed: audit entry #{anchor['audit_seq']}, "
              f"transaction seq {anchor['tx_seq']}")
        return 0

    if args.command == "set-role":
        with new_session() as db:
            try:
                user = accounts.set_role(db, args.username, args.role)
            except ValueError as error:
                print(error, file=sys.stderr)
                return 2
            audit.commit(db)
            print(f"{user.username} is now '{user.role}' (logged as ROLE_CHANGED).")
        return 0

    if args.command == "verify":
        from .verify import format_report, record_run, run_verification
        with new_session() as db:
            report = run_verification(db)
            record_run(db, report, actor=None, ip="local-cli")
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_report(report, colour=not args.no_colour and sys.stdout.isatty()))
        return 0 if report.ok else 1     # exit code 1 = tampering found

    if args.command == "serve":
        import uvicorn
        init_db()
        # Bound to localhost only: the demo has no TLS, so do not expose it.
        uvicorn.run("rationguard.app:app", host="127.0.0.1", port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
