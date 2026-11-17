"""Fraud rules and insider-threat alerts.

Alerts are NOT stored in a table. Every time the auditor opens the dashboard
they are re-computed from the tamper-evident audit log (and the verification
report). Reason: a stored alert is one more row an insider could delete. An
alert that is re-derived from protected evidence cannot be made to disappear
without breaking the log chain, which raises a CRITICAL alert of its own.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import clock
from .config import get_settings
from .models import AuditLog, Household, Transaction
from .verify import TRIGGER_MISSING, Report

CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# Thresholds (module constants so they are easy to find and to tune).
RAPID_REPEAT_WINDOW = timedelta(minutes=5)
DEALER_MAX_HOUSEHOLDS_PER_HOUR = 20
DENIED_BURST_COUNT, DENIED_BURST_WINDOW = 5, timedelta(minutes=10)
FAILED_LOGIN_COUNT, FAILED_LOGIN_WINDOW = 5, timedelta(minutes=15)
CSRF_FAILURE_COUNT, CSRF_FAILURE_WINDOW = 3, timedelta(minutes=10)
RAISE_THEN_ISSUE_WINDOW = timedelta(hours=24)
OFF_HOURS_ACTIONS = ("TRANSACTION_CREATED", "CHANGE_PROPOSED", "CHANGE_APPROVED", "CHANGE_REJECTED")


@dataclass
class Alert:
    severity: str
    kind: str
    when: str
    title: str
    detail: str = ""


def _bursts(times: list, count: int, window: timedelta) -> list[tuple]:
    """Find groups of at least `count` events inside `window`.
    Returns (first_time, last_time, how_many) per burst, without overlaps."""
    times = sorted(times)
    found, start = [], 0
    while start < len(times):
        end = start
        while end + 1 < len(times) and times[end + 1] - times[start] <= window:
            end += 1
        size = end - start + 1
        if size >= count:
            found.append((times[start], times[end], size))
            start = end + 1
        else:
            start += 1
    return found


def compute_alerts(db: Session, report: Report | None = None) -> list[Alert]:
    alerts: list[Alert] = []
    log = db.execute(select(AuditLog).order_by(AuditLog.seq)).scalars().all()
    txs = db.execute(select(Transaction).order_by(Transaction.seq)).scalars().all()
    households = {h.id: h for h in db.execute(select(Household)).scalars()}

    def code(household_id: int) -> str:
        return households[household_id].hh_code if household_id in households else f"#{household_id}"

    # ---- A. Integrity failures = direct database edits (CRITICAL) ----
    # The app never edits these records, so a failed check means someone
    # changed the database behind the app's back: no audit entry explains it.
    if report is not None:
        for finding in report.findings:
            severity = HIGH if finding.kind == TRIGGER_MISSING else CRITICAL
            alerts.append(Alert(severity, "DIRECT_DATABASE_EDIT", report.started_at,
                                f"Integrity failure with no matching audit entry: {finding.record} "
                                f"[{finding.kind}]", finding.message))

    by_action: dict[str, list[AuditLog]] = defaultdict(list)
    for entry in log:
        by_action[entry.action].append(entry)

    # ---- B. One-to-one alerts straight from log entries ----
    simple = {
        "ROLE_CHANGED": (HIGH, "ROLE_CHANGE", "Role changed for user {object_id}"),
        "ACCOUNT_LOCKED": (MEDIUM, "ACCOUNT_LOCKED", "Account {object_id} locked after repeated failed logins"),
        "SELF_APPROVAL_BLOCKED": (HIGH, "SELF_APPROVAL_ATTEMPT",
                                  "{actor} tried to approve their own change request #{object_id}"),
        "CHANGE_BLOCKED_TAMPERED_REQUEST": (CRITICAL, "TAMPERED_CHANGE_REQUEST",
                                            "{actor} tried to approve a tampered change request #{object_id}"),
        "LOGIN_BLOCKED_TAMPERED_USER": (CRITICAL, "TAMPERED_ACCOUNT_LOGIN",
                                        "Login attempted on tampered account {object_id}"),
        "SESSION_KILLED_TAMPERED_USER": (CRITICAL, "TAMPERED_ACCOUNT_SESSION",
                                         "Session ended: account {object_id} was modified in the database"),
    }
    for action, (severity, kind, title) in simple.items():
        for entry in by_action[action]:
            detail = ""
            if action == "ROLE_CHANGED":
                before, after = json.loads(entry.before_json), json.loads(entry.after_json)
                detail = f"{before.get('role')} -> {after.get('role')}"
            alerts.append(Alert(severity, kind, entry.ts,
                                title.format(object_id=entry.object_id, actor=entry.actor_username), detail))

    for entry in by_action["TX_REJECTED"]:
        reason = json.loads(entry.after_json).get("reason", "")
        kind = "OVER_QUOTA_ATTEMPT" if reason.startswith("over quota") else "TRANSACTION_REJECTED"
        alerts.append(Alert(MEDIUM, kind, entry.ts,
                            f"Dealer {entry.actor_username}: blocked transaction for {entry.object_id}", reason))

    # ---- C. Bursts ----
    denied: dict[str, list] = defaultdict(list)
    for entry in by_action["ACCESS_DENIED"]:
        denied[entry.actor_username].append(clock.parse(entry.ts))
    for actor, times in denied.items():
        for first, last, size in _bursts(times, DENIED_BURST_COUNT, DENIED_BURST_WINDOW):
            alerts.append(Alert(MEDIUM, "DENIED_ACCESS_BURST", clock.to_text(last),
                                f"{actor}: {size} denied access attempts in a short time",
                                f"between {clock.to_text(first)[:19]} and {clock.to_text(last)[:19]}"))

    failed: dict[str, list] = defaultdict(list)
    for entry in by_action["LOGIN_FAILED"]:
        failed[entry.ip].append(clock.parse(entry.ts))
    for ip, times in failed.items():
        for first, last, size in _bursts(times, FAILED_LOGIN_COUNT, FAILED_LOGIN_WINDOW):
            alerts.append(Alert(MEDIUM, "REPEATED_FAILED_LOGINS", clock.to_text(last),
                                f"{size} failed logins from address {ip}",
                                f"between {clock.to_text(first)[:19]} and {clock.to_text(last)[:19]}"))

    csrf_failures: dict[str, list] = defaultdict(list)
    for entry in by_action["ACCESS_DENIED"]:
        try:
            reason = json.loads(entry.after_json).get("reason", "")
        except (TypeError, json.JSONDecodeError):
            reason = ""
        if reason == "CSRF check failed":
            csrf_failures[entry.ip].append(clock.parse(entry.ts))
    for ip, times in csrf_failures.items():
        for first, last, size in _bursts(times, CSRF_FAILURE_COUNT, CSRF_FAILURE_WINDOW):
            alerts.append(Alert(HIGH, "CSRF_PROBE_BURST", clock.to_text(last),
                                f"{size} invalid form-token attempts from address {ip}",
                                f"between {clock.to_text(first)[:19]} and {clock.to_text(last)[:19]}"))

    # ---- D. Off-hours activity (one alert per person per day) ----
    settings = get_settings()
    offset = timedelta(minutes=settings.tz_offset_minutes)
    off_hours: dict[tuple, list[AuditLog]] = defaultdict(list)
    for action in OFF_HOURS_ACTIONS:
        for entry in by_action[action]:
            local = clock.parse(entry.ts) + offset
            if not settings.business_start_hour <= local.hour < settings.business_end_hour:
                off_hours[(entry.actor_username, local.date())].append(entry)
    for (actor, day), entries in off_hours.items():
        alerts.append(Alert(LOW, "OFF_HOURS_ACTIVITY", entries[-1].ts,
                            f"{actor}: {len(entries)} sensitive action(s) outside business hours on {day}",
                            ", ".join(sorted({e.action for e in entries}))))

    # ---- E. Entitlement raised, then cashed in soon after ----
    for entry in by_action["CHANGE_APPROVED"]:
        before, after = json.loads(entry.before_json), json.loads(entry.after_json)
        field = after.get("changed_field", "")
        if not field.startswith("quota_") or after.get(field, 0) <= before.get(field, 0):
            continue
        commodity = field.split("_")[1]
        approved_at = clock.parse(entry.ts)
        running = 0
        for tx in txs:
            if code(tx.household_id) != entry.object_id or tx.commodity != commodity \
                    or tx.entitlement_month != approved_at.strftime("%Y-%m"):
                continue
            running += tx.quantity_kg
            created = clock.parse(tx.created_at)
            # "Large" = more than the OLD quota would ever have allowed.
            if approved_at <= created <= approved_at + RAISE_THEN_ISSUE_WINDOW and running > before[field]:
                alerts.append(Alert(
                    HIGH, "ENTITLEMENT_RAISED_BEFORE_LARGE_TRANSACTION", tx.created_at,
                    f"{entry.object_id}: {commodity} quota raised {before[field]} -> {after[field]} kg, "
                    f"then transaction seq {tx.seq} took the month total to {running} kg",
                    f"approved by {entry.actor_username}; issue came "
                    f"{int((created - approved_at).total_seconds() // 60)} min later"))
                break

    # ---- F. Transaction fraud rules ----
    groups: dict[tuple, list[Transaction]] = defaultdict(list)
    for tx in txs:
        groups[(tx.household_id, tx.commodity, tx.entitlement_month)].append(tx)
    for (household_id, commodity, month), items in groups.items():
        seqs = ", ".join(str(t.seq) for t in items)
        if len(items) > 1:
            alerts.append(Alert(LOW, "DUPLICATE_ISSUE", items[-1].created_at,
                                f"{code(household_id)}: {commodity} issued {len(items)} times for {month}",
                                f"transaction seq {seqs}"))
        total = sum(t.quantity_kg for t in items)
        household = households.get(household_id)
        if household is not None and total > getattr(household, f"quota_{commodity}_kg", 0):
            alerts.append(Alert(HIGH, "ISSUED_ABOVE_QUOTA", items[-1].created_at,
                                f"{code(household_id)}: {total} kg {commodity} issued for {month}, "
                                f"above the quota of {getattr(household, f'quota_{commodity}_kg')} kg",
                                f"transaction seq {seqs}"))
        for earlier, later in zip(items, items[1:]):
            if clock.parse(later.created_at) - clock.parse(earlier.created_at) <= RAPID_REPEAT_WINDOW:
                alerts.append(Alert(MEDIUM, "RAPID_REPEAT_TRANSACTION", later.created_at,
                                    f"{code(household_id)}: {commodity} issued twice within minutes",
                                    f"transaction seq {earlier.seq} and {later.seq}"))

    by_dealer: dict[int, list[Transaction]] = defaultdict(list)
    for tx in txs:
        by_dealer[tx.dealer_id].append(tx)
    for dealer_id, items in by_dealer.items():
        start = 0
        for end, tx in enumerate(items):
            while clock.parse(tx.created_at) - clock.parse(items[start].created_at) > timedelta(hours=1):
                start += 1
            served = {t.household_id for t in items[start:end + 1]}
            if len(served) > DEALER_MAX_HOUSEHOLDS_PER_HOUR:
                alerts.append(Alert(HIGH, "DEALER_VELOCITY", tx.created_at,
                                    f"Dealer #{dealer_id} served {len(served)} households within one hour",
                                    f"limit is {DEALER_MAX_HOUSEHOLDS_PER_HOUR}; ends at transaction seq {tx.seq}"))
                break

    db.rollback()
    alerts.sort(key=lambda a: a.when, reverse=True)      # newest first ...
    alerts.sort(key=lambda a: _ORDER[a.severity])        # ... within each severity
    return alerts
