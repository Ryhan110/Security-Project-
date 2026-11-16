"""The verification engine - the heart of RationGuard.

It trusts NOTHING in the database. It re-computes every HMAC with the keys
from .env, re-walks both hash chains, and compares against the signed
anchors. It only reads; it never repairs anything (evidence must stay as the
attacker left it).

Order of checks (each one feeds the next):
  1. audit log chain      -> tells us which log entries can be trusted
  2. transactions         -> HMAC, chain, and comparison with log snapshots
  3. anchors              -> catches truncation / whole-history rewrites
  4. households, users, change requests -> row HMACs (unauthorised changes)
  5. schema               -> are the protective triggers still installed?

When a record fails, the ORIGINAL values come from the audit log snapshot
that was written when the record was created. That snapshot is only used if
its own log entry passed check 1.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, clock
from .crypto import GENESIS_HASH, same, sha256_hex, signature_ok
from .db import TRIGGERS, existing_triggers
from .integrity import (HOUSEHOLD_SNAPSHOT_FIELDS, TX_FIELDS, USER_SNAPSHOT_FIELDS,
                        change_request_hmac, household_hmac, tx_hmac, user_hmac)
from .models import AuditLog, ChangeRequest, Household, Transaction, User

# Kinds of failure the report can name.
MODIFIED = "MODIFIED"
DELETED = "DELETED"
REORDERED = "REORDERED"
INSERTED = "INSERTED"
LOG_TAMPERED = "LOG_TAMPERED"
LOG_TRUNCATED = "LOG_TRUNCATED"
ANCHOR_INVALID = "ANCHOR_INVALID"
UNAUTHORISED_CHANGE = "UNAUTHORISED_CHANGE"
TRIGGER_MISSING = "TRIGGER_MISSING"


@dataclass
class FieldChange:
    field: str
    original: Any
    current: Any


@dataclass
class Finding:
    check: str            # transactions / audit_log / anchors / households / users / ...
    kind: str             # one of the constants above
    record: str           # exactly which record, e.g. "transaction seq 3"
    message: str
    changes: list[FieldChange] = field(default_factory=list)
    evidence: str = ""    # where the original values came from


@dataclass
class CheckResult:
    name: str
    checked: int = 0
    failures: int = 0


@dataclass
class Report:
    started_at: str
    checks: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict:
        return {"ok": self.ok, "started_at": self.started_at,
                "checks": [asdict(c) for c in self.checks],
                "findings": [asdict(f) for f in self.findings]}


def _diff(original: dict, current: dict, fields) -> list[FieldChange]:
    return [FieldChange(name, original.get(name), current.get(name))
            for name in fields if original.get(name) != current.get(name)]


def _row(record: Any, fields) -> dict:
    return {name: getattr(record, name) for name in fields}


class _Run:
    """One verification run. Split into small methods so each check is easy
    to read and explain on its own."""

    def __init__(self, db: Session):
        self.db = db
        self.report = Report(started_at=clock.now_text())
        self.trusted_log: list[AuditLog] = []   # entries whose own hash verified

    def add(self, check: CheckResult, finding: Finding) -> None:
        check.failures += 1
        self.report.findings.append(finding)

    # ------------------------------------------------------------------
    # 1. Audit log chain
    # ------------------------------------------------------------------
    def check_audit_log(self) -> None:
        check = CheckResult("audit_log")
        self.report.checks.append(check)
        entries = self.db.execute(select(AuditLog).order_by(AuditLog.seq)).scalars().all()
        self.audit_by_seq = {entry.seq: entry for entry in entries}
        previous: AuditLog | None = None
        for entry in entries:
            check.checked += 1
            name = f"audit entry #{entry.seq}"
            expected_seq = previous.seq + 1 if previous else 1
            gap = entry.seq != expected_seq

            if gap:
                missing = (f"#{expected_seq}" if entry.seq - expected_seq == 1
                           else f"#{expected_seq} to #{entry.seq - 1}")
                self.add(check, Finding("audit_log", LOG_TAMPERED, f"audit entry {missing}",
                                        f"Audit entry {missing} is missing: the log jumps from "
                                        f"#{previous.seq if previous else 0} to #{entry.seq}. "
                                        "Log entries were deleted."))
            # (a) does the entry's content still match its own keyed hash?
            if not same(entry.entry_hash, audit.entry_hash(entry)):
                self.add(check, Finding("audit_log", LOG_TAMPERED, name,
                                        f"{name} ({entry.action} by {entry.actor_username}) was "
                                        "modified: its content no longer matches its hash."))
            else:
                self.trusted_log.append(entry)
                # (b) does it point at the entry before it?
                expected_prev = previous.entry_hash if previous else GENESIS_HASH
                if not gap and not same(entry.prev_hash, expected_prev):
                    self.add(check, Finding("audit_log", LOG_TAMPERED, name,
                                            f"{name} does not link to the entry before it: "
                                            "the chain is broken here."))
            previous = entry

    def _snapshots(self, actions: tuple[str, ...]) -> list[tuple[AuditLog, dict, dict]]:
        result = []
        for entry in self.trusted_log:
            if entry.action in actions:
                result.append((entry, json.loads(entry.before_json), json.loads(entry.after_json)))
        return result

    # ------------------------------------------------------------------
    # 2. Transactions: HMAC + chain + comparison with the log
    # ------------------------------------------------------------------
    def check_transactions(self) -> None:
        check = CheckResult("transactions")
        self.report.checks.append(check)
        fields = TX_FIELDS + ("hmac",)

        snap_by_seq: dict[int, tuple[dict, int]] = {}
        snap_by_hmac: dict[str, tuple[dict, int]] = {}
        for entry, _before, after in self._snapshots(("TRANSACTION_CREATED",)):
            snap_by_seq[after["seq"]] = (after, entry.seq)
            snap_by_hmac[after["hmac"]] = (after, entry.seq)

        rows = self.db.execute(select(Transaction).order_by(Transaction.seq)).scalars().all()
        self.tx_by_seq = {row.seq: row for row in rows}
        valid = {row.seq: same(row.hmac, tx_hmac(row)) for row in rows}
        moved_from: set[int] = set()

        for row in rows:
            check.checked += 1
            name = f"transaction seq {row.seq}"
            current = _row(row, fields)

            if not valid[row.seq]:
                # Find the original: first by the stored hmac (finds a row that
                # was moved), otherwise by its sequence number.
                found = snap_by_hmac.get(row.hmac) or snap_by_seq.get(row.seq)
                if found is None:
                    self.add(check, Finding(
                        "transactions", INSERTED, name,
                        f"{name} has no valid HMAC and no trusted audit entry. It was inserted "
                        "directly into the database (a forged record), or its audit entry was destroyed."))
                    continue
                original, audit_seq = found
                changes = _diff(original, current, fields)
                evidence = f"original values from audit entry #{audit_seq} (hash verified)"
                if changes and {c.field for c in changes} <= {"seq", "prev_hash"}:
                    moved_from.add(original["seq"])
                    self.add(check, Finding(
                        "transactions", REORDERED, name,
                        f"{name} was REORDERED: this record was created as seq {original['seq']} "
                        f"but now sits at seq {row.seq}.", changes, evidence))
                else:
                    if original["seq"] != row.seq:
                        moved_from.add(original["seq"])
                    described = "; ".join(f"{c.field}: {c.original!r} -> {c.current!r}" for c in changes)
                    self.add(check, Finding(
                        "transactions", MODIFIED, name,
                        f"{name} was MODIFIED after it was created ({described or 'HMAC does not verify'}).",
                        changes, evidence))
                continue

            # HMAC is valid, so prev_hash is authentic. Does it match the row before?
            before = self.tx_by_seq.get(row.seq - 1)
            if row.seq == 1 and row.prev_hash != GENESIS_HASH:
                self.add(check, Finding("transactions", REORDERED, name,
                                        f"{name} should be the start of the chain but is not."))
            elif before is not None and valid[before.seq] and not same(row.prev_hash, before.hmac):
                self.add(check, Finding("transactions", REORDERED, name,
                                        f"{name} does not link to seq {before.seq}: chain order is broken."))

        # Missing sequence numbers. We know how long the chain should be from
        # three independent places: valid rows, log snapshots, and anchors.
        anchored = [a.get("tx_seq", 0) for a in audit.read_anchors() if _anchor_signature_ok(a)]
        highest = max([s for s, ok in valid.items() if ok] + list(snap_by_seq) + anchored + [0])
        for seq in range(1, highest + 1):
            if seq in self.tx_by_seq or seq in moved_from:
                continue
            check.checked += 1
            found = snap_by_seq.get(seq)
            if found:
                original, audit_seq = found
                self.add(check, Finding(
                    "transactions", DELETED, f"transaction seq {seq}",
                    f"transaction seq {seq} was DELETED. It recorded {original['quantity_kg']} kg of "
                    f"{original['commodity']} for {original.get('household', 'household ' + str(original['household_id']))} "
                    f"on {original['created_at'][:10]}.",
                    [FieldChange(n, original.get(n), "(row deleted)") for n in ("commodity", "quantity_kg", "dealer_id")],
                    f"original values from audit entry #{audit_seq} (hash verified)"))
            else:
                self.add(check, Finding(
                    "transactions", DELETED, f"transaction seq {seq}",
                    f"transaction seq {seq} was DELETED, and no trusted audit snapshot of it remains."))

    # ------------------------------------------------------------------
    # 3. Anchors
    # ------------------------------------------------------------------
    def check_anchors(self) -> None:
        check = CheckResult("anchors")
        self.report.checks.append(check)
        anchors = audit.read_anchors()
        if not anchors:
            if self.audit_by_seq:
                self.add(check, Finding("anchors", ANCHOR_INVALID, "anchor file",
                                        "No anchors found although the audit log has entries. "
                                        "The anchor file was deleted or never written."))
            return

        good: list[dict] = []
        previous_signature: str | None = None
        for index, anchor in enumerate(anchors, start=1):
            check.checked += 1
            name = f"anchor #{index}"
            expected_prev = (sha256_hex(previous_signature.encode())
                             if previous_signature is not None else GENESIS_HASH)
            if not _anchor_signature_ok(anchor):
                self.add(check, Finding("anchors", ANCHOR_INVALID, name,
                                        f"{name} has an invalid Ed25519 signature: the anchor file was edited."))
            elif anchor["anchor_no"] != index or anchor["prev_anchor_hash"] != expected_prev:
                self.add(check, Finding("anchors", ANCHOR_INVALID, name,
                                        f"{name} is out of sequence: an anchor was removed or reordered."))
            else:
                good.append(anchor)
            previous_signature = str(anchor.get("signature", ""))

        # Rewritten history: the earliest anchor whose recorded hash no longer matches.
        for anchor in good:
            entry = self.audit_by_seq.get(anchor["audit_seq"])
            if entry is not None and not same(entry.entry_hash, anchor["audit_hash"]):
                self.add(check, Finding(
                    "anchors", LOG_TAMPERED, f"audit entry #{anchor['audit_seq']}",
                    f"Audit log history was REWRITTEN: anchor #{anchor['anchor_no']} (signed "
                    f"{anchor['created_at'][:19]}) recorded a different hash for audit entry "
                    f"#{anchor['audit_seq']}."))
                break
        for anchor in good:
            row = self.tx_by_seq.get(anchor["tx_seq"])
            if row is not None and not same(row.hmac, anchor["tx_hash"]):
                self.add(check, Finding(
                    "anchors", MODIFIED, f"transaction seq {anchor['tx_seq']}",
                    f"Transaction chain was REWRITTEN: anchor #{anchor['anchor_no']} recorded a "
                    f"different hash for transaction seq {anchor['tx_seq']}."))
                break

        # Truncation: the newest anchor says the log was at least this long.
        if good:
            newest = good[-1]
            last_seq = max(self.audit_by_seq) if self.audit_by_seq else 0
            if last_seq < newest["audit_seq"]:
                self.add(check, Finding(
                    "anchors", LOG_TRUNCATED, f"audit entries #{last_seq + 1} to #{newest['audit_seq']}",
                    f"Audit log was TRUNCATED: anchor #{newest['anchor_no']} (signed "
                    f"{newest['created_at'][:19]}) proves the log reached entry #{newest['audit_seq']}, "
                    f"but it now ends at #{last_seq}. The newest entries were deleted, or an old "
                    "copy of the database was restored."))

    # ------------------------------------------------------------------
    # 4. Row HMACs: households, users, change requests
    # ------------------------------------------------------------------
    def check_households(self) -> None:
        check = CheckResult("households")
        self.report.checks.append(check)
        latest: dict[str, tuple[dict, int]] = {}
        for entry, _before, after in self._snapshots(("HOUSEHOLD_ENROLLED", "CHANGE_APPROVED")):
            latest[entry.object_id] = (after, entry.seq)   # later entries overwrite earlier

        seen = set()
        for household in self.db.execute(select(Household).order_by(Household.id)).scalars():
            check.checked += 1
            seen.add(household.hh_code)
            if same(household.row_hmac, household_hmac(household)):
                continue
            name = f"household {household.hh_code}"
            found = latest.get(household.hh_code)
            changes = _diff(found[0], _row(household, HOUSEHOLD_SNAPSHOT_FIELDS),
                            HOUSEHOLD_SNAPSHOT_FIELDS) if found else []
            if changes:
                described = "; ".join(f"{c.field}: {c.original!r} -> {c.current!r}" for c in changes)
                message = (f"{name} has an UNAUTHORISED CHANGE with no approved change request "
                           f"({described}).")
            else:
                message = (f"{name} failed its integrity check. No quota/size/shop field differs "
                           "from the last approved state, so an encrypted personal field or the "
                           "HMAC itself was altered.")
            self.add(check, Finding("households", UNAUTHORISED_CHANGE, name, message, changes,
                                    f"last approved state from audit entry #{found[1]} (hash verified)"
                                    if found else ""))
        for hh_code in sorted(set(latest) - seen):
            self.add(check, Finding("households", DELETED, f"household {hh_code}",
                                    f"household {hh_code} exists in the audit log but its row is gone."))

    def check_users(self) -> None:
        check = CheckResult("users")
        self.report.checks.append(check)
        latest: dict[str, tuple[dict, int]] = {}
        for entry, _before, after in self._snapshots(("USER_CREATED", "ROLE_CHANGED")):
            latest[entry.object_id] = (after, entry.seq)

        for user in self.db.execute(select(User).order_by(User.id)).scalars():
            check.checked += 1
            if same(user.row_hmac, user_hmac(user)):
                continue
            name = f"user {user.username}"
            found = latest.get(user.username)
            changes = _diff(found[0], _row(user, USER_SNAPSHOT_FIELDS),
                            USER_SNAPSHOT_FIELDS) if found else []
            if any(c.field == "role" for c in changes):
                role = next(c for c in changes if c.field == "role")
                message = (f"{name}: role was changed directly in the database "
                           f"({role.original!r} -> {role.current!r}). Possible privilege escalation.")
            elif changes:
                message = f"{name}: account fields were changed directly in the database."
            else:
                message = (f"{name} failed its integrity check with no visible field change: "
                           "the password hash (or the HMAC) was replaced.")
            self.add(check, Finding("users", UNAUTHORISED_CHANGE, name, message, changes,
                                    f"last known state from audit entry #{found[1]} (hash verified)"
                                    if found else ""))

    def check_change_requests(self) -> None:
        check = CheckResult("change_requests")
        self.report.checks.append(check)
        proposer = {entry.object_id: (entry.actor_id, entry.seq)
                    for entry, _b, _a in self._snapshots(("CHANGE_PROPOSED",))}
        for request in self.db.execute(select(ChangeRequest).order_by(ChangeRequest.id)).scalars():
            check.checked += 1
            if same(request.row_hmac, change_request_hmac(request)):
                continue
            name = f"change request #{request.id}"
            changes, evidence = [], ""
            logged = proposer.get(str(request.id))
            if logged and logged[0] != request.proposed_by:
                changes.append(FieldChange("proposed_by", logged[0], request.proposed_by))
                evidence = f"original proposer from audit entry #{logged[1]} (hash verified)"
            message = (f"{name} was edited directly in the database"
                       + (f" (proposed_by: {changes[0].original!r} -> {changes[0].current!r}; "
                          "an attempt to get around the two-person rule)." if changes else "."))
            self.add(check, Finding("change_requests", UNAUTHORISED_CHANGE, name, message,
                                    changes, evidence))

    # ------------------------------------------------------------------
    # 5. Triggers
    # ------------------------------------------------------------------
    def check_triggers(self) -> None:
        check = CheckResult("schema")
        self.report.checks.append(check)
        present = existing_triggers(self.db)
        for name in TRIGGERS:
            check.checked += 1
            if name not in present:
                self.add(check, Finding("schema", TRIGGER_MISSING, f"trigger {name}",
                                        f"Protective trigger '{name}' has been dropped from the database."))


def _anchor_signature_ok(anchor: dict) -> bool:
    try:
        return signature_ok(audit.anchor_message(anchor), anchor["signature"])
    except (KeyError, TypeError):
        return False


def run_verification(db: Session) -> Report:
    """Run every check. Read-only."""
    run = _Run(db)
    run.check_audit_log()
    run.check_transactions()
    run.check_anchors()
    run.check_households()
    run.check_users()
    run.check_change_requests()
    run.check_triggers()
    db.rollback()   # we only read; release the lock
    return run.report


def record_run(db: Session, report: Report, *, actor: User | None, ip: str) -> None:
    """Note in the audit log that a verification happened and what it found."""
    kinds: dict[str, int] = {}
    for finding in report.findings:
        kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
    audit.append(db, actor=actor, actor_name=None if actor else "system", action="VERIFICATION_RUN",
                 object_type="system", object_id="verify", ip=ip,
                 after={"ok": report.ok, "findings": len(report.findings), "by_kind": kinds})
    audit.commit(db)


# --------------------------------------------------------------------------
# Text output for the CLI
# --------------------------------------------------------------------------
_GREEN, _RED, _BOLD, _DIM, _RESET = "\033[32m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"

_CHECK_TITLES = {
    "audit_log": "Audit log hash chain",
    "transactions": "Transaction HMACs and chain",
    "anchors": "Signed anchors (Ed25519)",
    "households": "Household records (HMAC)",
    "users": "User accounts (HMAC)",
    "change_requests": "Change requests (HMAC)",
    "schema": "Append-only triggers",
}


def format_report(report: Report, colour: bool = True) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    lines = [paint(_BOLD, "RationGuard verification report"), f"run at {report.started_at}", ""]
    for check in report.checks:
        status = paint(_GREEN, "PASS") if check.failures == 0 else paint(_RED, "FAIL")
        lines.append(f"  [{status}] {_CHECK_TITLES.get(check.name, check.name):<32} "
                     f"{check.checked} checked, {check.failures} failed")
    lines.append("")
    if report.ok:
        lines.append(paint(_GREEN + _BOLD, "RESULT: ALL GREEN - no tampering detected."))
        return "\n".join(lines)

    lines.append(paint(_RED + _BOLD, f"RESULT: TAMPERING DETECTED - {len(report.findings)} finding(s)"))
    for number, finding in enumerate(report.findings, start=1):
        lines.append("")
        lines.append(paint(_RED, f"  {number}. [{finding.kind}] {finding.record}"))
        lines.append(f"     {finding.message}")
        for change in finding.changes:
            lines.append(f"       field {paint(_BOLD, change.field)}: "
                         f"was {change.original!r}  ->  now {change.current!r}")
        if finding.evidence:
            lines.append(paint(_DIM, f"     ({finding.evidence})"))
    return "\n".join(lines)
