"""Creating users and changing roles. There is deliberately NO web page for
either: fewer routes means less to attack. Both are done from the CLI and
both are audit-logged."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
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
