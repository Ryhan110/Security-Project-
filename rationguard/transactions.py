"""Creating distribution transactions.

Transactions are never updated or deleted by the app. Each new one is linked
to the one before it:

    seq 1: prev_hash = 000...0        hmac = H1
    seq 2: prev_hash = H1             hmac = H2
    seq 3: prev_hash = H2             hmac = H3

`hmac` covers every field INCLUDING seq and prev_hash. Change any field,
remove a row, or swap two rows, and at least one HMAC or link stops matching.
"""
from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, clock
from .crypto import GENESIS_HASH, same
from .households import find_household, quota_for
from .integrity import TX_FIELDS, as_dict, household_hmac, tx_hmac
from .models import COMMODITIES, Transaction, User

MAX_QUANTITY_KG = 100
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


class TxRejected(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def tx_snapshot(tx: Transaction) -> dict:
    return {**as_dict(tx, TX_FIELDS), "hmac": tx.hmac}


def month_total(db: Session, household_id: int, commodity: str, month: str) -> int:
    return db.execute(select(func.coalesce(func.sum(Transaction.quantity_kg), 0)).where(
        Transaction.household_id == household_id, Transaction.commodity == commodity,
        Transaction.entitlement_month == month)).scalar_one()


def create_transaction(db: Session, *, dealer: User, hh_code: str, commodity: str,
                       quantity_kg: int, idempotency_key: str, ip: str) -> tuple[Transaction, bool]:
    """Record a distribution. Returns (transaction, created).
    `created` is False when this was a repeat of an earlier submission."""

    def reject(message: str, reason: str, status: int = 400, action: str = "TX_REJECTED"):
        db.rollback()
        audit.append(db, actor=dealer, action=action, object_type="household",
                     object_id=hh_code[:20], ip=ip,
                     after={"reason": reason, "commodity": str(commodity)[:20],
                            "quantity_kg": quantity_kg})
        audit.commit(db)
        raise TxRejected(message, status)

    # ---- 1. validate input (never trust the form) ----
    if commodity not in COMMODITIES:
        raise TxRejected("Unknown commodity.")
    if not isinstance(quantity_kg, int) or not 1 <= quantity_kg <= MAX_QUANTITY_KG:
        raise TxRejected(f"Quantity must be a whole number from 1 to {MAX_QUANTITY_KG} kg.")
    if not _IDEMPOTENCY_KEY.match(idempotency_key or ""):
        raise TxRejected("Missing or malformed idempotency key. Reload the form.")

    # ---- 2. object-level access: only households of the dealer's own shop ----
    household = find_household(db, hh_code)
    if household is None or dealer.shop_id is None or household.shop_id != dealer.shop_id:
        # Same answer for "unknown" and "other shop": no hints for ID guessing.
        reject("That household is not registered at your shop.", "household not in dealer's shop",
               status=403, action="ACCESS_DENIED")

    # ---- 3. idempotency: the form carries a one-time random key ----
    # A double click or a browser retry sends the SAME key again. We then
    # return the first transaction instead of creating a second one.
    earlier = db.execute(select(Transaction).where(
        Transaction.idempotency_key == idempotency_key)).scalar_one_or_none()
    if earlier is not None:
        same_request = (earlier.dealer_id == dealer.id and earlier.household_id == household.id
                        and earlier.commodity == commodity and earlier.quantity_kg == quantity_kg)
        if not same_request:
            reject("This form was already used for a different transaction.",
                   "idempotency key reused with different data", status=409)
        audit.append(db, actor=dealer, action="DUPLICATE_SUBMISSION_IGNORED", object_type="transaction",
                     object_id=str(earlier.seq), ip=ip, after={"household": household.hh_code})
        audit.commit(db)
        return earlier, False

    # ---- 4. fail closed if the household record was tampered with ----
    # Otherwise a quota raised by a direct database edit could be "cashed in".
    if not same(household.row_hmac, household_hmac(household)):
        reject("This household record failed its integrity check. Issue blocked; tell the auditor.",
               "household record failed integrity check", status=409)

    # ---- 5. quota rule (hard block) ----
    # The month comes from the SERVER clock, not from the form, so a dealer
    # cannot back-date an issue into a month that still has quota left.
    month = clock.utcnow().strftime("%Y-%m")
    already = month_total(db, household.id, commodity, month)
    quota = quota_for(household, commodity)
    if already + quantity_kg > quota:
        reject(f"Over quota: {already} kg already issued this month, quota is {quota} kg.",
               f"over quota (issued {already}, requested {quantity_kg}, quota {quota})")

    # ---- 6. append to the hash chain ----
    last = db.execute(select(Transaction).order_by(Transaction.seq.desc()).limit(1)).scalar_one_or_none()
    tx = Transaction(
        seq=(last.seq + 1) if last else 1,
        household_id=household.id, shop_id=household.shop_id, dealer_id=dealer.id,
        commodity=commodity, quantity_kg=quantity_kg, entitlement_month=month,
        created_at=clock.now_text(), idempotency_key=idempotency_key,
        prev_hash=last.hmac if last else GENESIS_HASH, hmac="")
    tx.hmac = tx_hmac(tx)
    db.add(tx)

    # ---- 7. log it, with a full snapshot ----
    # The snapshot is what later lets verification say "quantity_kg was 5,
    # now it is 25" or "this deleted record used to say ...".
    audit.append(db, actor=dealer, action="TRANSACTION_CREATED", object_type="transaction",
                 object_id=str(tx.seq), ip=ip, after={**tx_snapshot(tx), "household": household.hh_code})
    audit.commit(db)
    return tx, True
