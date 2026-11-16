"""Role-based access control (RBAC), deny by default.

Two layers:
1. FUNCTION level - "may this ROLE use this route at all?"
   One dependency, `require(Perm.X)`, is put on every route. A role only has
   the permissions listed in ROLE_PERMISSIONS; anything not listed is denied.
2. OBJECT level - "may this USER touch THIS household?"
   `authorize_household` stops household A reading household B by changing
   the ID in the URL (IDOR), and stops a dealer reaching another shop.

Every denial is written to the audit log.
"""
from __future__ import annotations

from enum import Enum

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .db import get_db
from .models import Household, User
from .security import SESSION_COOKIE, user_for_token


class Perm(str, Enum):
    DASHBOARD = "dashboard:view"            # own landing page
    HISTORY_VIEW = "history:view"           # a household's distribution history (object-checked)
    HOUSEHOLD_VIEW = "household:view"       # a household's record (object-checked)
    HOUSEHOLD_LIST = "household:list"
    TX_CREATE = "transaction:create"
    TX_VIEW_SHOP = "transaction:view_shop"
    TX_VIEW_ALL = "transaction:view_all"
    CHANGE_PROPOSE = "change:propose"
    CHANGE_DECIDE = "change:decide"
    CHANGE_LIST = "change:list"
    AUDIT_VIEW = "audit:view"
    VERIFY_RUN = "verify:run"
    ALERTS_VIEW = "alerts:view"


# The whole access policy in one table. If a (role, permission) pair is not
# here, the answer is NO.
ROLE_PERMISSIONS: dict[str, frozenset[Perm]] = {
    "household": frozenset({Perm.DASHBOARD, Perm.HISTORY_VIEW, Perm.HOUSEHOLD_VIEW}),
    "dealer": frozenset({Perm.DASHBOARD, Perm.TX_CREATE, Perm.TX_VIEW_SHOP, Perm.HISTORY_VIEW}),
    "admin": frozenset({Perm.DASHBOARD, Perm.HOUSEHOLD_LIST, Perm.HOUSEHOLD_VIEW,
                        Perm.CHANGE_PROPOSE, Perm.CHANGE_DECIDE, Perm.CHANGE_LIST}),
    # The auditor can look and verify, but has no permission that changes data.
    "auditor": frozenset({Perm.DASHBOARD, Perm.HISTORY_VIEW, Perm.TX_VIEW_ALL, Perm.CHANGE_LIST,
                          Perm.AUDIT_VIEW, Perm.VERIFY_RUN, Perm.ALERTS_VIEW}),
}


class NotAuthenticated(Exception):
    """No valid session. The app answers with a redirect to /login."""


def client_ip(request: Request) -> str:
    # We use the socket address. We do NOT trust X-Forwarded-For, because the
    # client can type anything into that header to fake the logged IP.
    return request.client.host if request.client else "unknown"


def current_user(request: Request, db: Session) -> User | None:
    if not hasattr(request.state, "user"):
        request.state.user = user_for_token(db, request.cookies.get(SESSION_COOKIE))
    return request.state.user


def deny(db: Session, request: Request, user: User, reason: str) -> None:
    """Log the refused attempt, then answer 403."""
    db.rollback()
    audit.append(db, actor=user, action="ACCESS_DENIED", object_type="route",
                 object_id=request.url.path, ip=client_ip(request),
                 after={"method": request.method, "reason": reason})
    audit.commit(db)
    raise HTTPException(status_code=403, detail="You are not allowed to do that.")


def require(permission: Perm):
    """The single permission check used by every protected route."""

    def dependency(request: Request, db: Session = Depends(get_db)) -> User:
        user = current_user(request, db)
        if user is None:
            raise NotAuthenticated()
        if permission not in ROLE_PERMISSIONS.get(user.role, frozenset()):
            deny(db, request, user, f"role '{user.role}' lacks permission '{permission.value}'")
        return user

    # A test reads this attribute to prove that no route was left unprotected.
    dependency.required_permission = permission
    return dependency


def household_in_scope(user: User, household: Household) -> bool:
    """Object-level rule: which households may this user touch?"""
    if user.role == "household":
        return user.household_id == household.id
    if user.role == "dealer":
        return user.shop_id is not None and user.shop_id == household.shop_id
    return user.role in ("admin", "auditor")


def authorize_household(db: Session, request: Request, user: User, hh_code: str) -> Household:
    """Load a household only if this user is allowed to see it.

    For household and dealer users, "does not exist" and "not yours" give the
    SAME 403 answer. Otherwise someone could walk HH-000001, HH-000002, ...
    and learn which IDs are real from the different error codes.
    """
    household = db.execute(
        select(Household).where(Household.hh_code == hh_code)).scalar_one_or_none()
    if household is not None and household_in_scope(user, household):
        return household
    if household is None and user.role in ("admin", "auditor"):
        raise HTTPException(status_code=404, detail="No such household.")
    deny(db, request, user, f"object-level check failed for household {hh_code[:20]}")
    raise AssertionError("unreachable")
