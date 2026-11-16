"""Authentication: password hashing, login with lockout, sessions, CSRF."""
from __future__ import annotations

import secrets
from collections import defaultdict, deque
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import audit, clock
from .config import get_settings
from .crypto import hmac_hex, same, sha256_hex
from .integrity import user_hmac
from .models import User, UserSession

SESSION_COOKIE = "rg_session"
LOGIN_CSRF_COOKIE = "rg_login_csrf"

MAX_FAILED_LOGINS = 5                    # then the account is locked ...
LOCKOUT = timedelta(minutes=15)          # ... for this long
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
SESSION_MAX_AGE = timedelta(hours=8)
MIN_PASSWORD_LENGTH = 12

# Argon2id with the library's recommended settings. It is deliberately slow
# and memory-hungry, so someone who steals the hashes can only test a few
# guesses per second instead of billions (as with plain SHA-256).
# Each hash gets its own random salt automatically.
_hasher = PasswordHasher()
# Used when the username does not exist, so "unknown user" takes about as
# long as "wrong password" and timing does not reveal which usernames exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# --------------------------------------------------------------------------
# Rate limiting (per IP address, in memory)
# --------------------------------------------------------------------------
class RateLimiter:
    """Allow at most `limit` attempts per `window`. Lockout protects one
    account from many guesses; this protects ALL accounts from one address
    trying a few guesses on each ("password spraying")."""

    def __init__(self, limit: int, window: timedelta):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = clock.utcnow()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


login_limiter = RateLimiter(limit=10, window=timedelta(minutes=1))


# --------------------------------------------------------------------------
# Login
# --------------------------------------------------------------------------
def authenticate(db: Session, username: str, password: str, ip: str) -> User | None:
    """Return the user if the login is good, otherwise None.

    Every outcome is audit-logged, but the password itself never is. The
    caller shows the SAME error for every failure so the page does not
    reveal whether the username exists or the account is locked.
    """
    username = username.strip().lower()[:50]
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()

    def fail(reason: str, action: str = "LOGIN_FAILED") -> None:
        audit.append(db, actor=user, actor_name=None if user else "anonymous", action=action,
                     object_type="user", object_id=username, ip=ip, after={"reason": reason})
        audit.commit(db)

    if user is None:
        verify_password(_DUMMY_HASH, password)  # burn the same time
        fail("unknown username")
        return None

    # The users row is itself HMAC-protected. If someone edited it directly in
    # the database (new role, swapped password hash) we refuse to trust it.
    if not same(user.row_hmac, user_hmac(user)):
        fail("user record failed integrity check", action="LOGIN_BLOCKED_TAMPERED_USER")
        return None

    now = clock.utcnow()
    if user.locked_until and clock.parse(user.locked_until) > now:
        fail("account locked")
        return None
    if not user.is_active:
        fail("account disabled")
        return None

    if not verify_password(user.password_hash, password):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = clock.to_text(now + LOCKOUT)
            user.failed_logins = 0
            audit.append(db, actor=user, action="ACCOUNT_LOCKED", object_type="user",
                         object_id=username, ip=ip,
                         after={"reason": f"{MAX_FAILED_LOGINS} failed logins", "until": user.locked_until})
        fail("wrong password")
        return None

    user.failed_logins = 0
    user.locked_until = None
    audit.append(db, actor=user, action="LOGIN_SUCCESS", object_type="user",
                 object_id=username, ip=ip)
    audit.commit(db)
    return user


# --------------------------------------------------------------------------
# Sessions (kept on the server; the cookie only carries a random token)
# --------------------------------------------------------------------------
def create_session(db: Session, user: User, ip: str) -> str:
    """Always a brand-new random token at login (prevents session fixation)."""
    token = secrets.token_urlsafe(32)
    now = clock.now_text()
    db.add(UserSession(token_hash=sha256_hex(token.encode()), user_id=user.id,
                       created_at=now, last_seen=now, ip=ip))
    db.commit()
    return token


def user_for_token(db: Session, token: str | None) -> User | None:
    if not token:
        return None
    row = db.execute(select(UserSession).where(
        UserSession.token_hash == sha256_hex(token.encode()))).scalar_one_or_none()
    if row is None:
        return None
    now = clock.utcnow()
    expired = (now - clock.parse(row.last_seen) > SESSION_IDLE_TIMEOUT
               or now - clock.parse(row.created_at) > SESSION_MAX_AGE)
    user = db.get(User, row.user_id)
    if expired or user is None or not user.is_active:
        db.delete(row)
        db.commit()
        return None
    if not same(user.row_hmac, user_hmac(user)):
        # Role or credentials were changed behind the app's back: log out.
        db.delete(row)
        audit.append(db, actor=None, actor_name=user.username, action="SESSION_KILLED_TAMPERED_USER",
                     object_type="user", object_id=user.username, ip=row.ip,
                     after={"reason": "user record failed integrity check"})
        audit.commit(db)
        return None
    row.last_seen = clock.to_text(now)
    db.commit()
    return user


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == sha256_hex(token.encode())))
        db.commit()


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------
def csrf_token(binding: str) -> str:
    """The token is an HMAC of the visitor's own cookie value.

    An attacker's website can make the victim's browser SEND a form, but it
    cannot READ our pages or cookies, so it cannot know this token. A POST
    without the right token is rejected.
    """
    return hmac_hex(get_settings().session_secret, b"csrf:" + binding.encode())


def csrf_ok(binding: str | None, submitted: str | None) -> bool:
    if not binding or not submitted:
        return False
    return same(csrf_token(binding), submitted)
