"""Admin unlock: ends a lockout early, under strict rules, with evidence."""
from conftest import PASSWORD, alerts, audit_rows, csrf, kinds, login, new_client


def lock(username: str) -> None:
    browser = new_client()
    for _ in range(5):
        login(browser, username, "wrong-password-x")
    assert login(browser, username).status_code == 401      # locked: even the right password fails


def unlock(admin, username: str):
    return admin.post(f"/admin/accounts/{username}/unlock", data={"csrf_token": csrf(admin)})


def test_admin_unlock_lets_the_user_back_in(db_path):
    lock("hh000111")
    admin = new_client("admin1")
    page = admin.get("/admin/accounts").text
    assert "hh000111" in page and "LOCKED" in page
    response = unlock(admin, "hh000111")
    assert response.status_code == 200 and "hh000111 unlocked" in response.text
    assert login(new_client(), "hh000111").status_code == 303
    entry = audit_rows(db_path, "ACCOUNT_UNLOCKED")[-1]
    assert entry["actor_username"] == "admin1" and entry["object_id"] == "hh000111"
    assert '"failed_logins":0' in entry["after_json"] and "locked_until" in entry["before_json"]


def test_unlock_raises_an_alert_for_the_auditor():
    lock("hh000111")
    unlock(new_client("admin1"), "hh000111")
    found = [a for a in alerts() if a.kind == "ACCOUNT_UNLOCKED"]
    assert len(found) == 1 and "admin1 unlocked account hh000111" in found[0].title


def test_cannot_unlock_an_account_that_is_not_locked():
    response = unlock(new_client("admin1"), "hh000110")
    assert response.status_code == 400 and "not locked" in response.text


def test_admin_cannot_unlock_own_account(db_path):
    admin = new_client("admin1")                      # session survives the lock
    lock("admin1")
    response = unlock(admin, "admin1")
    assert response.status_code == 403 and "own account" in response.text
    assert "SELF_UNLOCK_ATTEMPT" in kinds(alerts())
    assert login(new_client(), "admin1").status_code == 401   # still locked


def test_other_roles_cannot_unlock():
    lock("hh000111")
    for role_user in ("dealer1", "auditor1", "hh000101"):
        assert unlock(new_client(role_user), "hh000111").status_code == 403
    assert login(new_client(), "hh000111", PASSWORD).status_code == 401


def test_unlock_requires_a_form_token():
    lock("hh000111")
    admin = new_client("admin1")
    assert admin.post("/admin/accounts/hh000111/unlock", data={}).status_code == 403
    assert login(new_client(), "hh000111").status_code == 401


def test_accounts_page_shows_no_secrets(db_path):
    page = new_client("admin1").get("/admin/accounts").text
    assert "$argon2" not in page and "row_hmac" not in page
