"""The web application (FastAPI).

Rule for this file: EVERY route either appears in PUBLIC_PATHS or has
`Depends(require(Perm.SOMETHING))`. tests/test_rbac.py fails if one does not.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, clock, detection, households as hh_service, security, transactions as tx_service
from .config import get_settings
from .crypto import decrypt, mask_id, mask_phone
from .db import get_db, new_session
from .models import (COMMODITIES, AuditLog, ChangeRequest, Household, Shop,
                     Transaction, User)
from .rbac import (NotAuthenticated, Perm, authorize_household, client_ip,
                   require)
from .verify import record_run, run_verification

HERE = Path(__file__).resolve().parent
PUBLIC_PATHS = {"/login"}          # the only pages reachable without a session
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# autoescape is on for .html templates: user-supplied text is shown as text,
# never run as HTML/JavaScript (prevents XSS).
templates = Jinja2Templates(directory=str(HERE / "templates"))


async def csrf_protect(request: Request) -> None:
    """Runs before EVERY state-changing request (it is a global dependency,
    so a new POST route cannot forget it)."""
    if request.method in SAFE_METHODS:
        return
    form = await request.form()
    cookie = security.LOGIN_CSRF_COOKIE if request.url.path == "/login" else security.SESSION_COOKIE
    if security.csrf_ok(request.cookies.get(cookie), form.get("csrf_token")):
        return
    with new_session() as db:
        audit.append(db, actor=None, action="ACCESS_DENIED", object_type="route",
                     object_id=request.url.path, ip=client_ip(request),
                     after={"method": request.method, "reason": "CSRF check failed"})
        audit.commit(db)
    raise HTTPException(status_code=403, detail="Form check failed (CSRF). Reload the page and try again.")


# docs_url=None etc.: the auto-generated API pages are switched off, so there
# are no extra unauthenticated routes.
app = FastAPI(title="RationGuard", docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(csrf_protect)])
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Frame-Options"] = "DENY"                 # no clickjacking
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"          # do not leak HH codes in URLs
    response.headers["Cache-Control"] = "no-store"               # private pages are not cached
    return response


@app.exception_handler(NotAuthenticated)
async def not_authenticated(request: Request, _error: NotAuthenticated):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(HTTPException)
async def http_error(request: Request, error: HTTPException):
    return templates.TemplateResponse(request, "error.html",
                                      {"status": error.status_code, "detail": error.detail, "user": None},
                                      status_code=error.status_code)


def render(request: Request, name: str, user: User | None, status_code: int = 200, **context):
    token = request.cookies.get(security.SESSION_COOKIE, "")
    context.update(user=user, csrf_token=security.csrf_token(token) if token else "")
    return templates.TemplateResponse(request, name, context, status_code=status_code)


# ==========================================================================
# Authentication
# ==========================================================================
_GENERIC_LOGIN_ERROR = "Login failed. Check your username and password, or try again later."


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    binding = request.cookies.get(security.LOGIN_CSRF_COOKIE) or secrets.token_urlsafe(24)
    response = templates.TemplateResponse(
        request, "login.html", {"user": None, "error": None, "csrf_token": security.csrf_token(binding)})
    response.set_cookie(security.LOGIN_CSRF_COOKIE, binding, httponly=True, samesite="strict",
                        secure=get_settings().cookie_secure)
    return response


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""),
          db: Session = Depends(get_db)):
    ip = client_ip(request)

    def failed(status: int, message: str):
        binding = request.cookies.get(security.LOGIN_CSRF_COOKIE, "")
        return templates.TemplateResponse(
            request, "login.html",
            {"user": None, "error": message, "csrf_token": security.csrf_token(binding)},
            status_code=status)

    if not security.login_limiter.allow(ip):
        audit.append(db, actor=None, action="LOGIN_RATE_LIMITED", object_type="user",
                     object_id=username.strip().lower()[:50], ip=ip)
        audit.commit(db)
        return failed(429, "Too many login attempts. Wait a minute and try again.")

    user = security.authenticate(db, username, password, ip)
    if user is None:
        return failed(401, _GENERIC_LOGIN_ERROR)   # same text for every reason

    token = security.create_session(db, user, ip)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        security.SESSION_COOKIE, token,
        httponly=True,          # JavaScript cannot read it (limits XSS damage)
        samesite="strict",      # not sent on requests coming from other sites (CSRF)
        secure=get_settings().cookie_secure,   # HTTPS only when enabled
        max_age=int(security.SESSION_MAX_AGE.total_seconds()))
    response.delete_cookie(security.LOGIN_CSRF_COOKIE)
    return response


@app.post("/logout")
def logout(request: Request, user: User = Depends(require(Perm.DASHBOARD)),
           db: Session = Depends(get_db)):
    security.destroy_session(db, request.cookies.get(security.SESSION_COOKIE))
    audit.append(db, actor=user, action="LOGOUT", object_type="user", object_id=user.username,
                 ip=client_ip(request))
    audit.commit(db)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(security.SESSION_COOKIE)
    return response


@app.get("/")
def home(user: User = Depends(require(Perm.DASHBOARD)), db: Session = Depends(get_db)):
    if user.role == "household":
        household = db.get(Household, user.household_id)
        return RedirectResponse(f"/households/{household.hh_code}/history", status_code=303)
    target = {"dealer": "/dealer", "admin": "/admin/households", "auditor": "/auditor"}[user.role]
    return RedirectResponse(target, status_code=303)


# ==========================================================================
# Household history (confidentiality: the IDOR-sensitive route)
# ==========================================================================
@app.get("/households/{hh_code}/history", response_class=HTMLResponse)
def household_history(hh_code: str, request: Request,
                      user: User = Depends(require(Perm.HISTORY_VIEW)),
                      db: Session = Depends(get_db)):
    # Having the permission is not enough: is THIS household in the user's scope?
    household = authorize_household(db, request, user, hh_code)
    rows = db.execute(select(Transaction).where(Transaction.household_id == household.id)
                      .order_by(Transaction.seq.desc())).scalars().all()
    month = clock.utcnow().strftime("%Y-%m")
    quotas = [{"commodity": c, "quota": hh_service.quota_for(household, c),
               "used": tx_service.month_total(db, household.id, c, month)} for c in COMMODITIES]
    # Only the household itself sees its own name here. Dealer and auditor
    # get the history without the personal details.
    owner = user.role == "household"
    view = {"hh_code": household.hh_code if owner else mask_id(household.hh_code),
            "head_name": decrypt(household.head_name_enc) if owner else None,
            "family_size": household.family_size}
    if not owner:   # someone else looked at a family's history: record it
        audit.append(db, actor=user, action="HISTORY_VIEWED", object_type="household",
                     object_id=household.hh_code, ip=client_ip(request))
        audit.commit(db)
    return render(request, "history.html", user, household=view, transactions=rows,
                  quotas=quotas, month=month)


@app.get("/households/{hh_code}", response_class=HTMLResponse)
def household_record(hh_code: str, request: Request,
                     user: User = Depends(require(Perm.HOUSEHOLD_VIEW)),
                     db: Session = Depends(get_db)):
    household = authorize_household(db, request, user, hh_code)
    shop = db.get(Shop, household.shop_id)
    view = {"hh_code": household.hh_code, "head_name": decrypt(household.head_name_enc),
            "address": decrypt(household.address_enc), "phone": decrypt(household.phone_enc),
            "family_size": household.family_size, "shop": f"{shop.code} {shop.name}",
            "shop_id": household.shop_id, "quota_rice_kg": household.quota_rice_kg,
            "quota_wheat_kg": household.quota_wheat_kg, "quota_sugar_kg": household.quota_sugar_kg,
            "version": household.version}
    if user.role == "admin":
        # Admin needs to recognise the family but not to phone them.
        view["phone"] = mask_phone(view["phone"])
        audit.append(db, actor=user, action="HOUSEHOLD_VIEWED", object_type="household",
                     object_id=household.hh_code, ip=client_ip(request))
        audit.commit(db)
    return render(request, "household.html", user, household=view,
                  fields=list(hh_service.CHANGEABLE_FIELDS),
                  shops=db.execute(select(Shop).order_by(Shop.id)).scalars().all())


# ==========================================================================
# Dealer
# ==========================================================================
def _dealer_page(request: Request, user: User, db: Session, status_code: int = 200,
                 error: str | None = None, message: str | None = None):
    rows = db.execute(select(Transaction, Household.hh_code)
                      .join(Household, Household.id == Transaction.household_id)
                      .where(Transaction.shop_id == user.shop_id)      # own shop only
                      .order_by(Transaction.seq.desc()).limit(50)).all()
    shop = db.get(Shop, user.shop_id) if user.shop_id else None
    return render(request, "dealer.html", user, status_code=status_code, error=error, message=message,
                  shop=shop, commodities=COMMODITIES,
                  idempotency_key=secrets.token_urlsafe(24),   # fresh one-time key per form
                  transactions=[{"tx": tx, "hh": mask_id(code)} for tx, code in rows])


@app.get("/dealer", response_class=HTMLResponse)
def dealer_dashboard(request: Request, user: User = Depends(require(Perm.TX_VIEW_SHOP)),
                     db: Session = Depends(get_db)):
    return _dealer_page(request, user, db)


@app.post("/transactions", response_class=HTMLResponse)
def create_transaction(request: Request, hh_code: str = Form(""), commodity: str = Form(""),
                       quantity_kg: str = Form(""), idempotency_key: str = Form(""),
                       user: User = Depends(require(Perm.TX_CREATE)), db: Session = Depends(get_db)):
    try:
        quantity = int(quantity_kg)
    except ValueError:
        return _dealer_page(request, user, db, 400, error="Quantity must be a whole number.")
    try:
        tx, created = tx_service.create_transaction(
            db, dealer=user, hh_code=hh_code.strip().upper(), commodity=commodity,
            quantity_kg=quantity, idempotency_key=idempotency_key, ip=client_ip(request))
    except tx_service.TxRejected as rejected:
        return _dealer_page(request, user, db, rejected.status, error=rejected.message)
    note = (f"Recorded transaction seq {tx.seq}." if created else
            f"This form was already submitted: transaction seq {tx.seq} exists, nothing new was recorded.")
    return _dealer_page(request, user, db, 201 if created else 200, message=note)


# ==========================================================================
# Admin: beneficiary data, maker-checker
# ==========================================================================
@app.get("/admin/households", response_class=HTMLResponse)
def admin_households(request: Request, user: User = Depends(require(Perm.HOUSEHOLD_LIST)),
                     db: Session = Depends(get_db)):
    rows = db.execute(select(Household).order_by(Household.hh_code)).scalars().all()
    # The LIST shows masked IDs and no personal data; details are one click
    # away, and that click is audit-logged.
    view = [{"masked": mask_id(h.hh_code), "hh_code": h.hh_code, "family_size": h.family_size,
             "shop_id": h.shop_id} for h in rows]
    return render(request, "admin_households.html", user, households=view)


@app.get("/admin/changes", response_class=HTMLResponse)
def list_changes(request: Request, user: User = Depends(require(Perm.CHANGE_LIST)),
                 db: Session = Depends(get_db)):
    return _changes_page(request, user, db)


def _changes_page(request: Request, user: User, db: Session, status_code: int = 200,
                  error: str | None = None, message: str | None = None):
    names = {u.id: u.username for u in db.execute(select(User)).scalars()}
    codes = {h.id: h.hh_code for h in db.execute(select(Household)).scalars()}
    rows = db.execute(select(ChangeRequest).order_by(ChangeRequest.id.desc())).scalars().all()
    view = [{"r": r, "household": mask_id(codes.get(r.household_id, "?")),
             "proposer": names.get(r.proposed_by, "?"), "decider": names.get(r.decided_by, ""),
             "mine": r.proposed_by == user.id} for r in rows]
    return render(request, "changes.html", user, status_code=status_code, changes=view,
                  error=error, message=message)


@app.post("/admin/changes", response_class=HTMLResponse)
def propose_change(request: Request, hh_code: str = Form(""), field: str = Form(""),
                   new_value: str = Form(""), reason: str = Form(""),
                   user: User = Depends(require(Perm.CHANGE_PROPOSE)), db: Session = Depends(get_db)):
    household = authorize_household(db, request, user, hh_code)
    try:
        change = hh_service.propose_change(db, admin=user, household=household, field=field,
                                           new_value=new_value, reason=reason, ip=client_ip(request))
    except hh_service.ChangeError as error:
        return _changes_page(request, user, db, error.status, error=error.message)
    return _changes_page(request, user, db, 201,
                         message=f"Change request #{change.id} created. Another admin must approve it.")


def _decide(request: Request, user: User, db: Session, request_id: int, approve: bool):
    try:
        change = hh_service.decide_change(db, admin=user, request_id=request_id, approve=approve,
                                          ip=client_ip(request))
    except hh_service.ChangeError as error:
        return _changes_page(request, user, db, error.status, error=error.message)
    return _changes_page(request, user, db, message=f"Change request #{change.id}: {change.status}.")


@app.post("/admin/changes/{request_id}/approve", response_class=HTMLResponse)
def approve_change(request_id: int, request: Request,
                   user: User = Depends(require(Perm.CHANGE_DECIDE)), db: Session = Depends(get_db)):
    return _decide(request, user, db, request_id, approve=True)


@app.post("/admin/changes/{request_id}/reject", response_class=HTMLResponse)
def reject_change(request_id: int, request: Request,
                  user: User = Depends(require(Perm.CHANGE_DECIDE)), db: Session = Depends(get_db)):
    return _decide(request, user, db, request_id, approve=False)


# ==========================================================================
# Auditor (read-only + verification)
# ==========================================================================
def _auditor_page(request: Request, user: User, db: Session, recorded: bool = False):
    report = run_verification(db)
    if recorded:
        record_run(db, report, actor=user, ip=client_ip(request))
    alerts = detection.compute_alerts(db, report)
    return render(request, "auditor.html", user, report=report, alerts=alerts, recorded=recorded,
                  anchors=len(audit.read_anchors()))


@app.get("/auditor", response_class=HTMLResponse)
def auditor_dashboard(request: Request, user: User = Depends(require(Perm.ALERTS_VIEW)),
                      db: Session = Depends(get_db)):
    return _auditor_page(request, user, db)


@app.post("/auditor/verify", response_class=HTMLResponse)
def auditor_verify(request: Request, user: User = Depends(require(Perm.VERIFY_RUN)),
                   db: Session = Depends(get_db)):
    """Same checks as `python -m rationguard verify`, and the run is logged."""
    return _auditor_page(request, user, db, recorded=True)


@app.get("/auditor/audit-log", response_class=HTMLResponse)
def auditor_audit_log(request: Request, user: User = Depends(require(Perm.AUDIT_VIEW)),
                      db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(200)).scalars().all()
    return render(request, "audit_log.html", user, entries=rows)


@app.get("/auditor/transactions", response_class=HTMLResponse)
def auditor_transactions(request: Request, user: User = Depends(require(Perm.TX_VIEW_ALL)),
                         db: Session = Depends(get_db)):
    rows = db.execute(select(Transaction, Household.hh_code)
                      .join(Household, Household.id == Transaction.household_id)
                      .order_by(Transaction.seq.desc()).limit(200)).all()
    return render(request, "transactions.html", user,
                  transactions=[{"tx": tx, "hh": mask_id(code), "hh_code": code} for tx, code in rows])
