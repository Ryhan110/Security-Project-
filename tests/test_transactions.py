"""Phase 3 - transaction integrity: HMAC, hash chain, idempotency, quota."""
import hashlib
import secrets

from conftest import issue, new_client, sql, verify

SHOP1 = ["HH-000101", "HH-000104", "HH-000107", "HH-000110"]


def test_transaction_gets_hmac_and_chain_links(db_path):
    dealer = new_client("dealer1")
    for code in SHOP1[:3]:
        assert issue(dealer, code).status_code == 201
    rows = sql(db_path, "SELECT seq, prev_hash, hmac FROM transactions ORDER BY seq")
    assert [r[0] for r in rows] == [1, 2, 3]
    assert rows[0][1] == "0" * 64                    # genesis
    assert rows[1][1] == rows[0][2] and rows[2][1] == rows[1][2]   # each links to the one before
    assert verify().ok


def test_hmac_is_keyed_not_a_plain_hash(db_path):
    """Anyone can compute SHA-256 of the row. Nobody without the key can compute the stored value."""
    from rationguard.crypto import canonical
    from rationguard.db import new_session
    from rationguard.integrity import TX_FIELDS, tx_hmac
    from rationguard.models import Transaction
    issue(new_client("dealer1"))
    with new_session() as session:
        tx = session.query(Transaction).one()
        plain = hashlib.sha256(canonical("tx:v1", [(f, getattr(tx, f)) for f in TX_FIELDS])).hexdigest()
        assert tx.hmac == tx_hmac(tx) and tx.hmac != plain


def test_hmac_key_is_not_stored_in_the_database(db_path):
    from rationguard.config import get_settings
    settings = get_settings()
    data = db_path.read_bytes()
    for key in (settings.tx_hmac_key, settings.audit_hmac_key, settings.record_hmac_key):
        assert key not in data and key.hex().encode() not in data


def test_canonical_form_has_fixed_order_and_no_ambiguity():
    from rationguard.crypto import canonical
    assert canonical("t", [("a", "ab"), ("b", "c")]) != canonical("t", [("a", "a"), ("b", "bc")])
    assert canonical("t", [("a", 1)]) != canonical("u", [("a", 1)])        # type label matters
    assert canonical("t", [("a", 1), ("b", 2)]) == canonical("t", [("a", 1), ("b", 2)])


def test_idempotency_key_stops_double_submission(db_path):
    dealer, key = new_client("dealer1"), secrets.token_urlsafe(24)
    first = issue(dealer, key=key)
    second = issue(dealer, key=key)                       # double click / browser retry
    assert first.status_code == 201 and second.status_code == 200
    assert "nothing new was recorded" in second.text
    assert sql(db_path, "SELECT COUNT(*) FROM transactions")[0][0] == 1


def test_idempotency_key_cannot_be_reused_for_different_data(db_path):
    dealer, key = new_client("dealer1"), secrets.token_urlsafe(24)
    assert issue(dealer, kg=2, key=key).status_code == 201
    assert issue(dealer, kg=3, key=key).status_code == 409
    assert sql(db_path, "SELECT COUNT(*) FROM transactions")[0][0] == 1


def test_missing_idempotency_key_is_rejected():
    dealer = new_client("dealer1")
    assert issue(dealer, key="short").status_code == 400


def test_over_quota_is_blocked_and_logged(db_path):
    dealer = new_client("dealer1")                         # HH-000101 rice quota is 10 kg
    assert issue(dealer, kg=8).status_code == 201
    blocked = issue(dealer, kg=5)
    assert blocked.status_code == 400 and "Over quota" in blocked.text
    assert sql(db_path, "SELECT SUM(quantity_kg) FROM transactions")[0][0] == 8
    assert sql(db_path, "SELECT COUNT(*) FROM audit_log WHERE action = 'TX_REJECTED'")[0][0] == 1


def test_bad_input_is_rejected(db_path):
    dealer = new_client("dealer1")
    assert issue(dealer, commodity="gold").status_code == 400
    assert issue(dealer, kg=0).status_code == 400
    assert issue(dealer, kg=-5).status_code == 400
    bad = dealer.post("/transactions", data={"csrf_token": __import__("conftest").csrf(dealer),
                                             "hh_code": "HH-000101", "commodity": "rice",
                                             "quantity_kg": "2.5", "idempotency_key": "k" * 24})
    assert bad.status_code == 400
    assert sql(db_path, "SELECT COUNT(*) FROM transactions")[0][0] == 0


def test_entitlement_month_comes_from_server_clock(db_path):
    dealer = new_client("dealer1")
    dealer.post("/transactions", data={"csrf_token": __import__("conftest").csrf(dealer),
                                       "hh_code": "HH-000101", "commodity": "rice", "quantity_kg": "1",
                                       "idempotency_key": "k" * 24, "entitlement_month": "2020-01"})
    assert sql(db_path, "SELECT entitlement_month FROM transactions")[0][0] == "2026-03"


def test_issue_is_blocked_when_household_record_was_tampered(db_path):
    """A quota raised by a direct DB edit cannot be 'cashed in' through the app."""
    sql(db_path, "UPDATE households SET quota_rice_kg = 90 WHERE hh_code = 'HH-000101'")
    response = issue(new_client("dealer1"), kg=50)
    assert response.status_code == 409 and "integrity check" in response.text
    assert sql(db_path, "SELECT COUNT(*) FROM transactions")[0][0] == 0
