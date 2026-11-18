"""Creating users, changing roles, and unlocking accounts.

Creating users and changing roles have deliberately NO web page (fewer
routes means less to attack); both are done from the CLI. Unlocking an
account IS on the web, for admins only, because waiting 15 minutes is the
weakness of a lockout: an attacker can lock a real user out on purpose.
Every one of these actions is audit-logged."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, clock
from .integrity import USER_SNAPSHOT_FIELDS, as_dict, user_hmac
from .models import ROLES, User
from .security import hash_password


def create_user(db: Session, *, username: str, password: str, role: str,
                shop_id: int | None = None, household_id: int | None = None,
                password_hash: str | None = None) -> User:
    if role not in ROLES:
        raise ValueError(f"Unknown role: {role}")
    user = User(username=username.lower(), role=role, shop_id=shop_id, household_id=household_id,
                password_hash=password_hash or hash_password(password),
                is_active=1, failed_logins=0, row_hmac="")
    db.add(user)
    db.flush()                       # gives the row its id, which is inside the HMAC
    user.row_hmac = user_hmac(user)
    # The snapshot has no password hash in it: credentials never enter the log.
    audit.append(db, actor=None, actor_name="system", action="USER_CREATED", object_type="user",
                 object_id=user.username, ip="local-cli", after=as_dict(user, USER_SNAPSHOT_FIELDS))
    return user


def set_role(db: Session, username: str, new_role: str) -> User:
    if new_role not in ROLES:
        raise ValueError(f"Unknown role: {new_role}")
    user = db.execute(select(User).where(User.username == username.lower())).scalar_one_or_none()
    if user is None:
        raise ValueError(f"No such user: {username}")
    before = as_dict(user, USER_SNAPSHOT_FIELDS)
    user.role = new_role
    user.row_hmac = user_hmac(user)
    audit.append(db, actor=None, actor_name="system", action="ROLE_CHANGED", object_type="user",
                 object_id=user.username, ip="local-cli", before=before,
                 after=as_dict(user, USER_SNAPSHOT_FIELDS))
    return user


class UnlockError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def is_locked(user: User) -> bool:
    return bool(user.locked_until) and clock.parse(user.locked_until) > clock.utcnow()


def unlock_user(db: Session, *, admin: User, username: str, ip: str) -> User:
    """An admin ends a lockout early. Rules:
    * only a currently locked account can be unlocked;
    * nobody can unlock their own account (separation of duties);
    * it is audit-logged and raises an alert for the auditor.
    The lock fields are not part of the user row's HMAC, so this does not
    trip the integrity check."""
    target = db.execute(select(User).where(User.username == username.lower()[:50])).scalar_one_or_none()
    if target is None:
        raise UnlockError("No such account.", 404)
    if target.id == admin.id:
        audit.append(db, actor=admin, action="SELF_UNLOCK_BLOCKED", object_type="user",
                     object_id=target.username, ip=ip)
        audit.commit(db)
        raise UnlockError("You cannot unlock your own account.", 403)
    if not is_locked(target):
        raise UnlockError(f"{target.username} is not locked.")
    before = {"locked_until": target.locked_until, "failed_logins": target.failed_logins}
    target.locked_until = None
    target.failed_logins = 0
    audit.append(db, actor=admin, action="ACCOUNT_UNLOCKED", object_type="user",
                 object_id=target.username, ip=ip, before=before,
                 after={"locked_until": None, "failed_logins": 0})
    audit.commit(db)
    return target
