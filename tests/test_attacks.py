"""Phases 5 and 7 - every attack script must be detected or blocked, and the
verification report must name the exact record, the kind of failure, and the
field that changed (original value -> current value)."""
import delete_transaction
import idor_attempt
import insert_ghost_transaction
import reorder_transactions
import self_approve_change
import tamper_and_recompute_hash
import tamper_audit_log
import tamper_transaction
import truncate_log_tail

from conftest import PASSWORD, alerts, audit_rows, issue, kinds, new_client, sql, verify

SHOP1 = ["HH-000101", "HH-000104", "HH-000107", "HH-000110"]


def three_transactions():
    dealer = new_client("dealer1")
    for code in SHOP1[:3]:
        assert issue(dealer, code, "rice", 5).status_code == 201


def changes_of(finding) -> dict:
    return {c.field: (c.original, c.current) for c in finding.changes}


def test_clean_database_is_all_green():
    three_transactions()
    report = verify()
    assert report.ok and report.findings == []
    assert {c.name: c.failures for c in report.checks} == {
        "audit_log": 0, "transactions": 0, "anchors": 0, "households": 0, "users": 0,
        "change_requests": 0, "schema": 0}
    assert next(c for c in report.checks if c.name == "transactions").checked == 3


# ---- attack 1 --------------------------------------------------------------
def test_tamper_transaction_is_detected_with_exact_field(db_path):
    three_transactions()
    result = tamper_transaction.run(db_path, seq=2, new_quantity=25)
    assert sql(db_path, "SELECT quantity_kg FROM transactions WHERE seq = 2")[0][0] == 25   # attack worked
    report = verify()
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "MODIFIED" and finding.record == "transaction seq 2"
    assert changes_of(finding) == {"quantity_kg": (5, 25)}
    assert "audit entry" in finding.evidence and result["before"] == 5
    critical = [a for a in alerts(report) if a.severity == "CRITICAL"]
    assert critical and critical[0].kind == "DIRECT_DATABASE_EDIT"


# ---- attack 2 --------------------------------------------------------------
def test_delete_transaction_from_the_middle_is_detected(db_path):
    three_transactions()
    delete_transaction.run(db_path, seq=2)
    report = verify()
    assert [(f.kind, f.record) for f in report.findings] == [("DELETED", "transaction seq 2")]
    assert "5 kg of rice" in report.findings[0].message and "HH-000104" in report.findings[0].message


def test_delete_the_last_transaction_is_detected(db_path):
    """The chain that remains is valid; the audit log snapshot gives it away."""
    three_transactions()
    delete_transaction.run(db_path, seq=3)
    assert [(f.kind, f.record) for f in verify().findings] == [("DELETED", "transaction seq 3")]


# ---- attack 3 --------------------------------------------------------------
def test_tamper_and_recompute_hash_fails_without_the_key(db_path):
    three_transactions()
    result = tamper_and_recompute_hash.run(db_path, seq=1, new_quantity=25)
    assert result["forged_hash"] != result["original_hmac"]
    report = verify()
    finding = next(f for f in report.findings if f.check == "transactions")
    assert finding.kind == "MODIFIED" and finding.record == "transaction seq 1"
    found = changes_of(finding)
    assert found["quantity_kg"] == (5, 25)
    assert found["hmac"] == (result["original_hmac"], result["forged_hash"])


# ---- attack 4 --------------------------------------------------------------
def test_tamper_audit_log_trigger_blocks_then_chain_detects(db_path):
    three_transactions()
    result = tamper_audit_log.run(db_path)
    assert result["trigger_blocked_first_try"] and "append-only" in result["trigger_message"]
    report = verify()
    assert [(f.kind, f.record) for f in report.findings] == [
        ("LOG_TAMPERED", f"audit entry #{result['seq']}")]
    assert "modified" in report.findings[0].message


def test_deleting_an_audit_entry_is_detected(db_path):
    three_transactions()
    target = audit_rows(db_path, "TRANSACTION_CREATED")[0]["seq"]
    sql(db_path, "DROP TRIGGER audit_log_no_delete")
    sql(db_path, "DELETE FROM audit_log WHERE seq = ?", (target,))
    found = {(f.kind, f.record) for f in verify().findings}
    assert ("LOG_TAMPERED", f"audit entry #{target}") in found


def test_rewriting_an_entry_hash_breaks_the_next_link(db_path):
    three_transactions()
    target = audit_rows(db_path, "TRANSACTION_CREATED")[0]["seq"]
    sql(db_path, "DROP TRIGGER audit_log_no_update")
    sql(db_path, "UPDATE audit_log SET actor_username = 'x', entry_hash = ? WHERE seq = ?", ("a" * 64, target))
    records = [f.record for f in verify().findings if f.kind == "LOG_TAMPERED"]
    assert f"audit entry #{target}" in records and f"audit entry #{target + 1}" in records


# ---- attack 5 --------------------------------------------------------------
def test_idor_attempt_is_blocked_and_logged(db_path):
    result = idor_attempt.run(db_path, password=PASSWORD)
    assert result["own_status"] == 200
    assert result["victim_status"] == result["victim_record_status"] == result["ghost_status"] == 403
    denied = audit_rows(db_path, "ACCESS_DENIED")
    assert len(denied) == 3 and {row["actor_username"] for row in denied} == {"hh000101"}


# ---- attack 6 --------------------------------------------------------------
def test_self_approval_is_blocked_both_ways(db_path):
    result = self_approve_change.run(db_path, password=PASSWORD)
    assert result["propose_status"] == 201
    assert result["self_approve_status"] == 403            # two-person rule
    assert result["doctored_approve_status"] == 409        # HMAC on the request row
    assert result["quota_before"] == result["quota_after"] == 10
    report = verify()
    finding = next(f for f in report.findings if f.check == "change_requests")
    assert finding.kind == "UNAUTHORISED_CHANGE" and "proposed_by" in changes_of(finding)
    found = kinds(alerts(report))
    assert "SELF_APPROVAL_ATTEMPT" in found and "TAMPERED_CHANGE_REQUEST" in found


# ---- bonus attacks ---------------------------------------------------------
def test_reordered_transactions_are_detected(db_path):
    three_transactions()
    reorder_transactions.run(db_path, a=2, b=3)
    report = verify()
    assert [(f.kind, f.record) for f in report.findings] == [
        ("REORDERED", "transaction seq 2"), ("REORDERED", "transaction seq 3")]
    assert changes_of(report.findings[0])["seq"] == (3, 2)


def test_truncated_tail_is_caught_only_by_the_anchor(db_path):
    from rationguard import audit
    three_transactions()
    audit.write_anchor()
    result = truncate_log_tail.run(db_path)
    rows = audit_rows(db_path)                                 # what is left is a VALID chain ...
    assert all(b["prev_hash"] == a["entry_hash"] for a, b in zip(rows, rows[1:]))
    report = verify()                                          # ... and it is still caught
    found = {(f.kind, f.check) for f in report.findings}
    assert ("LOG_TRUNCATED", "anchors") in found
    assert ("DELETED", "transactions") in found and result["tx_seq"] == 3


def test_ghost_transaction_is_detected(db_path):
    three_transactions()
    insert_ghost_transaction.run(db_path)
    assert [(f.kind, f.record) for f in verify().findings] == [("INSERTED", "transaction seq 4")]


# ---- direct edits to beneficiary and user data ------------------------------
def test_household_quota_edited_in_database_is_flagged_as_unauthorised(db_path):
    sql(db_path, "UPDATE households SET quota_rice_kg = 50, family_size = 9 WHERE hh_code = 'HH-000102'")
    report = verify()
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "UNAUTHORISED_CHANGE" and finding.record == "household HH-000102"
    assert changes_of(finding) == {"quota_rice_kg": (15, 50), "family_size": (3, 9)}
    assert "no approved change request" in finding.message


def test_role_edited_in_database_is_flagged(db_path):
    sql(db_path, "UPDATE users SET role = 'admin' WHERE username = 'dealer2'")
    finding = verify().findings[0]
    assert finding.kind == "UNAUTHORISED_CHANGE" and finding.record == "user dealer2"
    assert changes_of(finding) == {"role": ("dealer", "admin")}


def test_swapped_password_hash_is_flagged_and_login_refused(db_path):
    from conftest import login
    sql(db_path, "UPDATE users SET password_hash = (SELECT password_hash FROM users WHERE "
                 "username = 'dealer1') WHERE username = 'admin1'")
    assert login(new_client(), "admin1").status_code == 401
    finding = next(f for f in verify().findings if f.check == "users")
    assert finding.record == "user admin1" and "password hash" in finding.message


# ---- the two front ends of the engine ---------------------------------------
def test_cli_exit_code_and_output(db_path, capsys):
    from rationguard.__main__ import main
    three_transactions()
    assert main(["verify", "--no-colour"]) == 0
    assert "ALL GREEN" in capsys.readouterr().out
    tamper_transaction.run(db_path, seq=1)
    capsys.readouterr()
    assert main(["verify", "--no-colour"]) == 1
    output = capsys.readouterr().out
    assert "[MODIFIED] transaction seq 1" in output
    assert "field quantity_kg: was 5  ->  now 25" in output


def test_auditor_dashboard_shows_the_same_finding(db_path):
    three_transactions()
    tamper_transaction.run(db_path, seq=1)
    page = new_client("auditor1").get("/auditor").text
    assert "TAMPERING DETECTED" in page and "transaction seq 1" in page
    assert "DIRECT_DATABASE_EDIT" in page and "CRITICAL" in page


def test_verification_is_read_only_and_runs_are_logged(db_path):
    three_transactions()
    tamper_transaction.run(db_path, seq=1)
    auditor = new_client("auditor1")
    from conftest import csrf
    assert auditor.post("/auditor/verify", data={"csrf_token": csrf(auditor)}).status_code == 200
    assert sql(db_path, "SELECT quantity_kg FROM transactions WHERE seq = 1")[0][0] == 25   # evidence untouched
    run = audit_rows(db_path, "VERIFICATION_RUN")[-1]
    assert run["actor_username"] == "auditor1" and '"ok":false' in run["after_json"]
