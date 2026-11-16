"""Phase 6 - maker-checker (two-person rule) for beneficiary changes."""
from conftest import alerts, audit_rows, decide, kinds, new_client, propose, sql, verify

HH = "HH-000101"   # rice quota 10, family size 2, shop 1


def quota(db_path):
    return sql(db_path, "SELECT quota_rice_kg, version FROM households WHERE hh_code = ?", (HH,))[0]


def test_proposal_alone_changes_nothing(db_path):
    assert propose(new_client("admin1"), HH, "quota_rice_kg", 20).status_code == 201
    assert quota(db_path) == (10, 1)
    assert sql(db_path, "SELECT status FROM change_requests")[0][0] == "PENDING"


def test_different_admin_can_approve_and_everything_still_verifies(db_path):
    propose(new_client("admin1"), HH, "quota_rice_kg", 20)
    assert decide(new_client("admin2"), 1).status_code == 200
    assert quota(db_path) == (20, 2)
    assert verify().ok                                     # the household HMAC was refreshed properly
    entry = audit_rows(db_path, "CHANGE_APPROVED")[-1]
    assert entry["actor_username"] == "admin2"
    assert '"quota_rice_kg":10' in entry["before_json"] and '"quota_rice_kg":20' in entry["after_json"]


def test_self_approval_is_rejected_and_logged(db_path):
    admin = new_client("admin1")
    propose(admin, HH, "quota_rice_kg", 20)
    response = decide(admin, 1)
    assert response.status_code == 403 and "cannot approve your own request" in response.text
    assert quota(db_path) == (10, 1)
    assert audit_rows(db_path, "SELF_APPROVAL_BLOCKED")[-1]["actor_username"] == "admin1"
    assert "SELF_APPROVAL_ATTEMPT" in kinds(alerts())


def test_request_cannot_be_decided_twice(db_path):
    propose(new_client("admin1"), HH, "quota_rice_kg", 20)
    admin2 = new_client("admin2")
    assert decide(admin2, 1, "reject").status_code == 200
    assert decide(admin2, 1, "approve").status_code == 409
    assert quota(db_path) == (10, 1)


def test_status_flipped_to_approved_in_database_changes_nothing(db_path):
    """Marking the request APPROVED by hand does not apply it, and is detected."""
    propose(new_client("admin1"), HH, "quota_rice_kg", 20)
    sql(db_path, "UPDATE change_requests SET status = 'APPROVED' WHERE id = 1")
    assert quota(db_path) == (10, 1)
    assert [(f.kind, f.record) for f in verify().findings] == [("UNAUTHORISED_CHANGE", "change request #1")]


def test_invalid_proposals_are_rejected(db_path):
    admin = new_client("admin1")
    assert propose(admin, HH, "row_hmac", 1).status_code == 400            # not a changeable field
    assert propose(admin, HH, "hh_code", 1).status_code == 400
    assert propose(admin, HH, "quota_rice_kg", 5000).status_code == 400    # out of range
    assert propose(admin, HH, "quota_rice_kg", "lots").status_code == 400
    assert propose(admin, HH, "shop_id", 999).status_code == 400           # no such shop
    assert propose(admin, HH, "quota_rice_kg", 20, reason="x").status_code == 400
    assert sql(db_path, "SELECT COUNT(*) FROM change_requests")[0][0] == 0


def test_stale_request_is_not_applied(db_path):
    admin1, admin2 = new_client("admin1"), new_client("admin2")
    propose(admin1, HH, "quota_rice_kg", 20)        # request 1: 10 -> 20
    propose(admin2, HH, "quota_rice_kg", 30)        # request 2: 10 -> 30
    assert decide(admin2, 1).status_code == 200     # now 20
    assert decide(admin1, 2).status_code == 409     # request 2 was based on 10
    assert quota(db_path) == (20, 2)


def test_auditor_can_read_but_not_decide(db_path):
    propose(new_client("admin1"), HH, "quota_rice_kg", 20)
    auditor = new_client("auditor1")
    assert auditor.get("/admin/changes").status_code == 200
    assert decide(auditor, 1).status_code == 403
    assert "Approve" not in auditor.get("/admin/changes").text
