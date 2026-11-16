"""Beneficiary records and the maker-checker (two-person) rule.

No admin can change family size, quota or shop alone:
  admin A PROPOSES  ->  a DIFFERENT admin B APPROVES  ->  only then it applies.
Each household row carries an HMAC that the app refreshes only inside
`decide_change`. So a household whose HMAC does not match was changed some
other way (a direct database edit) = an unauthorised change.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, clock
from .crypto import encrypt, same
from .integrity import (HOUSEHOLD_SNAPSHOT_FIELDS, as_dict, change_request_hmac,
                        household_hmac)
from .models import ChangeRequest, Household, Shop, User

# field -> (smallest allowed, largest allowed). Anything not listed here
# cannot be changed through a change request at all.
CHANGEABLE_FIELDS: dict[str, tuple[int, int]] = {
    "family_size": (1, 20),
    "quota_rice_kg": (0, 100),
    "quota_wheat_kg": (0, 100),
    "quota_sugar_kg": (0, 20),
    "shop_id": (1, 10**6),
}


class ChangeError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def enrol_household(db: Session, *, hh_code: str, head_name: str, address: str, phone: str,
                    family_size: int, shop_id: int, quota_rice_kg: int, quota_wheat_kg: int,
                    quota_sugar_kg: int) -> Household:
    household = Household(
        hh_code=hh_code, head_name_enc=encrypt(head_name), address_enc=encrypt(address),
        phone_enc=encrypt(phone), family_size=family_size, shop_id=shop_id,
        quota_rice_kg=quota_rice_kg, quota_wheat_kg=quota_wheat_kg,
        quota_sugar_kg=quota_sugar_kg, version=1, last_change_request_id=None, row_hmac="")
    db.add(household)
    db.flush()
    household.row_hmac = household_hmac(household)
    audit.append(db, actor=None, actor_name="system", action="HOUSEHOLD_ENROLLED",
                 object_type="household", object_id=hh_code, ip="local-cli",
                 after=as_dict(household, HOUSEHOLD_SNAPSHOT_FIELDS))
    return household


def propose_change(db: Session, *, admin: User, household: Household, field: str,
                   new_value: str, reason: str, ip: str) -> ChangeRequest:
    """Step 1 (the "maker"). Nothing about the household changes yet."""
    if field not in CHANGEABLE_FIELDS:
        raise ChangeError("That field cannot be changed.")
    try:
        value = int(new_value)
    except (TypeError, ValueError):
        raise ChangeError("The new value must be a whole number.")
    low, high = CHANGEABLE_FIELDS[field]
    if not low <= value <= high:
        raise ChangeError(f"Value must be between {low} and {high}.")
    if field == "shop_id" and db.get(Shop, value) is None:
        raise ChangeError("No such shop.")
    old_value = getattr(household, field)
    if value == old_value:
        raise ChangeError("The new value is the same as the current value.")
    reason = reason.strip()[:300]
    if len(reason) < 5:
        raise ChangeError("Please give a reason (at least 5 characters).")

    request = ChangeRequest(household_id=household.id, field=field, old_value=str(old_value),
                            new_value=str(value), reason=reason, proposed_by=admin.id,
                            proposed_at=clock.now_text(), status="PENDING", row_hmac="")
    db.add(request)
    db.flush()
    request.row_hmac = change_request_hmac(request)
    audit.append(db, actor=admin, action="CHANGE_PROPOSED", object_type="change_request",
                 object_id=str(request.id), ip=ip,
                 before={"household": household.hh_code, field: old_value},
                 after={"household": household.hh_code, field: value, "reason": reason})
    audit.commit(db)
    return request


def decide_change(db: Session, *, admin: User, request_id: int, approve: bool, ip: str) -> ChangeRequest:
    """Step 2 (the "checker")."""
    request = db.get(ChangeRequest, request_id)
    if request is None:
        raise ChangeError("No such change request.", 404)

    # The request row could have been edited in the database, for example to
    # swap `proposed_by` so the proposer can approve their own request.
    if not same(request.row_hmac, change_request_hmac(request)):
        audit.append(db, actor=admin, action="CHANGE_BLOCKED_TAMPERED_REQUEST",
                     object_type="change_request", object_id=str(request.id), ip=ip,
                     after={"reason": "change request failed integrity check"})
        audit.commit(db)
        raise ChangeError("This change request failed its integrity check and was blocked.", 409)

    if request.status != "PENDING":
        raise ChangeError("This request has already been decided.", 409)

    household = db.get(Household, request.household_id)

    if not approve:
        # Rejecting is always safe (the proposer may withdraw their own request).
        request.status, request.decided_by, request.decided_at = "REJECTED", admin.id, clock.now_text()
        request.row_hmac = change_request_hmac(request)
        audit.append(db, actor=admin, action="CHANGE_REJECTED", object_type="change_request",
                     object_id=str(request.id), ip=ip, after={"household": household.hh_code})
        audit.commit(db)
        return request

    # ---- THE TWO-PERSON RULE ----
    if request.proposed_by == admin.id:
        audit.append(db, actor=admin, action="SELF_APPROVAL_BLOCKED", object_type="change_request",
                     object_id=str(request.id), ip=ip,
                     after={"household": household.hh_code, "field": request.field})
        audit.commit(db)
        raise ChangeError("You cannot approve your own request. A different admin must approve it.", 403)

    if not same(household.row_hmac, household_hmac(household)):
        raise ChangeError("The household record failed its integrity check. Run verification first.", 409)
    if str(getattr(household, request.field)) != request.old_value:
        raise ChangeError("The household changed since this request was made. Propose it again.", 409)

    before = as_dict(household, HOUSEHOLD_SNAPSHOT_FIELDS)
    setattr(household, request.field, int(request.new_value))
    household.version += 1
    household.last_change_request_id = request.id
    household.row_hmac = household_hmac(household)   # only place this is refreshed
    request.status, request.decided_by, request.decided_at = "APPROVED", admin.id, clock.now_text()
    request.row_hmac = change_request_hmac(request)
    audit.append(db, actor=admin, action="CHANGE_APPROVED", object_type="household",
                 object_id=household.hh_code, ip=ip, before=before,
                 after={**as_dict(household, HOUSEHOLD_SNAPSHOT_FIELDS),
                        "changed_field": request.field, "proposed_by_user_id": request.proposed_by})
    audit.commit(db)
    return request


def quota_for(household: Household, commodity: str) -> int:
    return getattr(household, f"quota_{commodity}_kg")


def find_household(db: Session, hh_code: str) -> Household | None:
    return db.execute(select(Household).where(Household.hh_code == hh_code)).scalar_one_or_none()
