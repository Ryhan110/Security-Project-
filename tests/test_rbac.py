"""Phase 2 - RBAC for every role on every route, deny by default, IDOR."""
import pytest
from fastapi.routing import APIRoute

from conftest import audit_rows, csrf, new_client

# Households: HH-000101 belongs to SHOP-01 (dealer1). HH-000102 belongs to SHOP-02 (dealer2).
OWN, OTHER = "HH-000101", "HH-000102"
ROLE_USER = {"household": "hh000101", "dealer": "dealer1", "admin": "admin1", "auditor": "auditor1"}

# (method, path, roles that are allowed). Every other role must get 403.
ROUTES = [
    ("GET", "/", {"household", "dealer", "admin", "auditor"}),
    ("POST", "/logout", {"household", "dealer", "admin", "auditor"}),
    ("GET", f"/households/{OWN}/history", {"household", "dealer", "auditor"}),
    ("GET", f"/households/{OWN}", {"household", "admin"}),
    ("GET", "/dealer", {"dealer"}),
    ("POST", "/transactions", {"dealer"}),
    ("GET", "/admin/households", {"admin"}),
    ("GET", "/admin/changes", {"admin", "auditor"}),
    ("POST", "/admin/changes", {"admin"}),
    ("POST", "/admin/changes/1/approve", {"admin"}),
    ("POST", "/admin/changes/1/reject", {"admin"}),
    ("GET", "/auditor", {"auditor"}),
    ("POST", "/auditor/verify", {"auditor"}),
    ("GET", "/auditor/audit-log", {"auditor"}),
    ("GET", "/auditor/transactions", {"auditor"}),
]
CASES = [(method, path, role, role in allowed)
         for method, path, allowed in ROUTES for role in ROLE_USER]


def _call(browser, method, path, token=""):
    if method == "GET":
        return browser.get(path)
    return browser.post(path, data={"csrf_token": token})


@pytest.mark.parametrize("method,path,role,allowed", CASES)
def test_role_matrix(method, path, role, allowed):
    browser = new_client(ROLE_USER[role])
    response = _call(browser, method, path, csrf(browser))
    if allowed:
        # Allowed = the permission check passed. (Empty forms may still be a
        # 400/404 from input validation, which is not an access decision.)
        assert response.status_code != 403, f"{role} should be allowed on {method} {path}"
    else:
        assert response.status_code == 403, f"{role} must be denied on {method} {path}"


@pytest.mark.parametrize("method,path", [(m, p) for m, p, _ in ROUTES])
def test_anonymous_users_are_sent_to_login(client, method, path):
    client.get("/login")
    response = _call(client, method, path)
    # GET -> redirect to the login page. POST -> rejected by the CSRF check.
    assert response.status_code in (303, 403)
    if response.status_code == 303:
        assert response.headers["location"] == "/login"


def test_every_route_is_protected_or_explicitly_public():
    """Deny by default: adding a route without require(...) fails this test."""
    from rationguard.app import PUBLIC_PATHS, app
    unprotected = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in PUBLIC_PATHS:
            continue
        guarded = any(hasattr(dep.call, "required_permission") for dep in route.dependant.dependencies)
        if not guarded:
            unprotected.append(route.path)
    assert unprotected == []


def test_the_route_matrix_above_covers_every_route():
    from rationguard.app import PUBLIC_PATHS, app
    declared = {(m, p.replace(OWN, "{hh_code}").replace("/1/", "/{request_id}/")) for m, p, _ in ROUTES}
    actual = {(method, route.path) for route in app.routes if isinstance(route, APIRoute)
              and route.path not in PUBLIC_PATHS for method in route.methods}
    assert actual == declared


def test_unknown_role_has_no_permissions():
    from rationguard.rbac import ROLE_PERMISSIONS
    assert ROLE_PERMISSIONS.get("superuser", frozenset()) == frozenset()


def test_auditor_has_no_permission_that_changes_business_data():
    from rationguard.rbac import ROLE_PERMISSIONS, Perm
    forbidden = {Perm.TX_CREATE, Perm.CHANGE_PROPOSE, Perm.CHANGE_DECIDE}
    assert not ROLE_PERMISSIONS["auditor"] & forbidden


# ---- object-level checks (IDOR) -------------------------------------------
def test_household_cannot_read_another_households_history(db_path):
    browser = new_client("hh000101")
    assert browser.get(f"/households/{OWN}/history").status_code == 200
    response = browser.get(f"/households/{OTHER}/history")
    assert response.status_code == 403
    assert OTHER not in response.text
    assert browser.get(f"/households/{OTHER}").status_code == 403


def test_missing_and_forbidden_households_are_indistinguishable():
    browser = new_client("hh000101")
    forbidden = browser.get(f"/households/{OTHER}/history")
    missing = browser.get("/households/HH-999999/history")
    assert forbidden.status_code == missing.status_code == 403
    assert forbidden.text == missing.text


def test_dealer_cannot_see_or_serve_households_of_another_shop(db_path):
    from conftest import issue
    dealer = new_client("dealer1")
    assert dealer.get(f"/households/{OTHER}/history").status_code == 403
    assert issue(dealer, OTHER).status_code == 403
    assert issue(dealer, OWN).status_code == 201


def test_dealer_page_only_lists_own_shop():
    from conftest import issue
    assert issue(new_client("dealer2"), OTHER, kg=4).status_code == 201
    page = new_client("dealer1").get("/dealer").text
    assert "4 kg" not in page


def test_every_denied_attempt_is_logged(db_path):
    before = len(audit_rows(db_path, "ACCESS_DENIED"))
    browser = new_client("hh000101")
    browser.get("/auditor")                                  # function-level denial
    browser.get(f"/households/{OTHER}/history")              # object-level denial
    rows = audit_rows(db_path, "ACCESS_DENIED")[before:]
    assert len(rows) == 2
    assert rows[0]["actor_username"] == "hh000101" and rows[0]["object_id"] == "/auditor"
    assert rows[0]["ip"] and "dashboard" not in rows[0]["after_json"]
    assert OTHER in rows[1]["after_json"]


def test_role_edited_in_database_does_not_grant_access(db_path):
    """Elevation of privilege by editing the users table directly."""
    import sqlite3
    browser = new_client("dealer1")
    connection = sqlite3.connect(db_path)
    connection.execute("UPDATE users SET role = 'admin' WHERE username = 'dealer1'")
    connection.commit()
    connection.close()
    assert browser.get("/admin/households").status_code == 303     # session killed
    from conftest import login
    assert login(browser, "dealer1").status_code == 401            # and login refused
    assert audit_rows(db_path, "SESSION_KILLED_TAMPERED_USER")
    assert audit_rows(db_path, "LOGIN_BLOCKED_TAMPERED_USER")
