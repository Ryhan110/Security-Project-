"""Phases 6 and 8 - fraud rules and insider-threat alerts."""
from datetime import datetime, timezone

from conftest import (advance, alerts, decide, issue, kinds, login, new_client,
                      propose, verify)

SHOP1 = ["HH-000101", "HH-000104", "HH-000107", "HH-000110"]


def by_kind(kind):
    return [a for a in alerts(verify()) if a.kind == kind]


def test_quiet_system_has_no_alerts():
    issue(new_client("dealer1"))
    assert alerts(verify()) == []


def test_same_household_same_commodity_same_month_is_flagged():
    dealer = new_client("dealer1")
    issue(dealer, kg=2)
    advance(20)
    issue(dealer, kg=2)
    found = by_kind("DUPLICATE_ISSUE")
    assert len(found) == 1 and "HH-000101" in found[0].title and found[0].severity == "LOW"
    assert by_kind("RAPID_REPEAT_TRANSACTION") == []          # 20 minutes apart is not "rapid"


def test_repeat_within_minutes_is_flagged():
    dealer = new_client("dealer1")
    issue(dealer, kg=2)
    advance(2)
    issue(dealer, kg=2)
    assert len(by_kind("RAPID_REPEAT_TRANSACTION")) == 1


def test_over_quota_attempt_raises_alert():
    dealer = new_client("dealer1")
    issue(dealer, kg=8)
    issue(dealer, kg=8)
    found = by_kind("OVER_QUOTA_ATTEMPT")
    assert len(found) == 1 and found[0].severity == "MEDIUM" and "dealer1" in found[0].title


def test_dealer_velocity_is_flagged(monkeypatch):
    from rationguard import detection
    monkeypatch.setattr(detection, "DEALER_MAX_HOUSEHOLDS_PER_HOUR", 2)
    dealer = new_client("dealer1")
    for code in SHOP1[:2]:
        issue(dealer, code)
    assert by_kind("DEALER_VELOCITY") == []
    issue(dealer, SHOP1[2])
    found = by_kind("DEALER_VELOCITY")
    assert len(found) == 1 and found[0].severity == "HIGH"


def test_dealer_velocity_ignores_households_spread_over_hours(monkeypatch):
    from rationguard import detection
    monkeypatch.setattr(detection, "DEALER_MAX_HOUSEHOLDS_PER_HOUR", 2)
    dealer = new_client("dealer1")
    for code in SHOP1[:3]:
        issue(dealer, code)
        advance(45)
        dealer = new_client("dealer1")
    assert by_kind("DEALER_VELOCITY") == []


def test_off_hours_activity_is_flagged():
    from rationguard import clock
    clock._fixed = datetime(2026, 3, 10, 2, 30, tzinfo=timezone.utc)     # 02:30, shops are shut
    issue(new_client("dealer1"))
    found = by_kind("OFF_HOURS_ACTIVITY")
    assert len(found) == 1 and "dealer1" in found[0].title and found[0].severity == "LOW"


def test_burst_of_denied_access_is_flagged():
    browser = new_client("hh000101")
    for number in range(2, 6):
        browser.get(f"/households/HH-00010{number}/history")
    assert by_kind("DENIED_ACCESS_BURST") == []               # 4 is under the threshold
    browser.get("/auditor")
    found = by_kind("DENIED_ACCESS_BURST")
    assert len(found) == 1 and "hh000101: 5 denied" in found[0].title


def test_repeated_failed_logins_are_flagged():
    browser = new_client()
    for _ in range(5):
        login(browser, "admin1", "wrong-password-x")
    found = kinds(alerts())
    assert "REPEATED_FAILED_LOGINS" in found and "ACCOUNT_LOCKED" in found


def test_role_change_is_logged_and_flagged_but_verifies(capsys):
    from rationguard.__main__ import main
    assert main(["set-role", "dealer2", "auditor"]) == 0
    report = verify()
    assert report.ok                                          # a legitimate change keeps a valid HMAC
    found = by_kind("ROLE_CHANGE")
    assert len(found) == 1 and found[0].severity == "HIGH" and found[0].detail == "dealer -> auditor"


def test_entitlement_raised_shortly_before_large_transaction_is_flagged():
    propose(new_client("admin1"), "HH-000101", "quota_rice_kg", 40)     # was 10
    decide(new_client("admin2"), 1)
    advance(30)
    assert issue(new_client("dealer1"), kg=35).status_code == 201
    found = by_kind("ENTITLEMENT_RAISED_BEFORE_LARGE_TRANSACTION")
    assert len(found) == 1 and found[0].severity == "HIGH"
    assert "10 -> 40" in found[0].title and "admin2" in found[0].detail


def test_raise_followed_by_a_normal_sized_issue_is_not_flagged():
    propose(new_client("admin1"), "HH-000101", "quota_rice_kg", 40)
    decide(new_client("admin2"), 1)
    advance(30)
    issue(new_client("dealer1"), kg=5)                         # the old quota allowed this anyway
    assert by_kind("ENTITLEMENT_RAISED_BEFORE_LARGE_TRANSACTION") == []


def test_alerts_are_sorted_most_severe_first(db_path):
    from conftest import sql
    browser = new_client()
    for _ in range(5):
        login(browser, "admin1", "wrong-password-x")
    sql(db_path, "UPDATE households SET family_size = 9 WHERE hh_code = 'HH-000103'")
    severities = [a.severity for a in alerts(verify())]
    assert severities[0] == "CRITICAL"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert severities == sorted(severities, key=order.index)


def test_alerts_cannot_be_deleted_because_they_are_not_stored(db_path):
    from conftest import sql
    tables = {row[0] for row in sql(db_path, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert not any("alert" in name for name in tables)
