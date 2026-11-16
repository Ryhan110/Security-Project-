"""Phase 2 - authentication: Argon2, lockout, rate limit, sessions, CSRF."""
import sqlite3

from conftest import PASSWORD, advance, audit_rows, csrf, login, new_client, token_of


def test_passwords_are_stored_as_argon2id_hashes(db_path):
    connection = sqlite3.connect(db_path)
    hashes = [row[0] for row in connection.execute("SELECT password_hash FROM users")]
    connection.close()
    assert hashes and all(h.startswith("$argon2id$") for h in hashes)
    assert PASSWORD.encode() not in db_path.read_bytes()      # plaintext is nowhere in the file
    assert len(set(hashes)) == len(hashes)                    # unique salt per user


def test_short_passwords_are_refused():
    import pytest
    from rationguard.security import hash_password
    with pytest.raises(ValueError):
        hash_password("short")


def test_login_success_sets_hardened_cookie(client):
    response = login(client, "dealer1")
    assert response.status_code == 303
    cookie = response.headers["set-cookie"].lower()
    assert "rg_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie


def test_wrong_password_and_unknown_user_look_identical(client):
    wrong = login(client, "dealer1", "not-the-password")
    unknown = login(client, "no-such-user", "not-the-password")
    assert wrong.status_code == unknown.status_code == 401
    text = "Login failed. Check your username and password"
    assert text in wrong.text and text in unknown.text
    assert "rg_session" not in wrong.headers.get("set-cookie", "")


def test_account_locks_after_five_failures_and_unlocks_later(client, db_path):
    for _ in range(5):
        assert login(client, "dealer1", "wrong-password-x").status_code == 401
    assert login(client, "dealer1").status_code == 401          # correct password, but locked
    assert audit_rows(db_path, "ACCOUNT_LOCKED")
    advance(16)                                                  # lockout is 15 minutes
    assert login(client, "dealer1").status_code == 303


def test_login_rate_limit_per_ip(client, db_path):
    statuses = [login(client, f"user{i}", "wrong-password-x").status_code for i in range(12)]
    assert statuses[:10] == [401] * 10 and statuses[10:] == [429, 429]
    assert audit_rows(db_path, "LOGIN_RATE_LIMITED")


def test_login_requires_csrf_token(client):
    client.get("/login")
    response = client.post("/login", data={"username": "dealer1", "password": PASSWORD})
    assert response.status_code == 403


def test_post_without_csrf_token_is_rejected_and_logged(db_path):
    dealer = new_client("dealer1")
    response = dealer.post("/transactions", data={"hh_code": "HH-000101", "commodity": "rice",
                                                  "quantity_kg": "5", "idempotency_key": "k" * 24})
    assert response.status_code == 403
    forged = dealer.post("/transactions", data={"csrf_token": "0" * 64, "hh_code": "HH-000101",
                                                "commodity": "rice", "quantity_kg": "5",
                                                "idempotency_key": "k" * 24})
    assert forged.status_code == 403
    connection = sqlite3.connect(db_path)
    assert connection.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 0
    connection.close()
    assert any("CSRF" in row["after_json"] for row in audit_rows(db_path, "ACCESS_DENIED"))


def test_csrf_token_is_bound_to_the_session():
    first, second = new_client("dealer1"), new_client("dealer1")
    assert csrf(first) != csrf(second)


def test_session_token_changes_at_login_and_only_its_hash_is_stored(db_path):
    browser = new_client()
    page = browser.get("/login")
    # Session fixation attempt: the request arrives with a cookie the attacker chose.
    response = browser.post("/login", headers={"cookie": f"rg_session=attacker-chosen-value; "
                                               f"rg_login_csrf={browser.cookies.get('rg_login_csrf')}"},
                            data={"username": "dealer1", "password": PASSWORD,
                                  "csrf_token": token_of(page.text)})
    assert response.status_code == 303
    token = response.cookies.get("rg_session")
    assert token != "attacker-chosen-value" and len(token) >= 40
    assert token.encode() not in db_path.read_bytes()              # raw token is not in the DB


def test_logout_kills_the_session_on_the_server():
    browser = new_client("dealer1")
    token = browser.cookies.get("rg_session")
    assert browser.get("/dealer").status_code == 200
    assert browser.post("/logout", data={"csrf_token": csrf(browser)}).status_code == 303
    browser.cookies.set("rg_session", token)                        # replay the old cookie
    assert browser.get("/dealer").status_code == 303


def test_idle_session_expires():
    browser = new_client("dealer1")
    advance(31)
    response = browser.get("/dealer")
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_security_headers_present(client):
    headers = client.get("/login").headers
    assert headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_passwords_and_tokens_never_reach_the_audit_log(db_path):
    browser = new_client()
    login(browser, "dealer1", "a-wrong-secret-password")
    login(browser, "dealer1")
    token = browser.cookies.get("rg_session")
    dump = " ".join(" ".join(str(v) for v in tuple(row)) for row in audit_rows(db_path))
    assert "a-wrong-secret-password" not in dump and PASSWORD not in dump and token not in dump


def test_audit_scrubber_redacts_secret_looking_fields():
    from rationguard.audit import scrub
    cleaned = scrub({"username": "x", "password": "p", "nested": {"session_token": "t", "hmac_key": "k"}})
    assert cleaned == {"username": "x", "password": "[REDACTED]",
                       "nested": {"session_token": "[REDACTED]", "hmac_key": "[REDACTED]"}}


def test_sql_injection_in_login_is_harmless(client, db_path):
    assert login(client, "admin1' OR '1'='1' --", "x' OR '1'='1").status_code == 401
    assert login(client, "admin1").status_code == 303            # table still intact


def test_login_page_token_helper(client):
    assert len(token_of(client.get("/login").text)) == 64
