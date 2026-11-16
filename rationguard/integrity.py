"""Which fields of each record are protected, and how its HMAC is computed.

Each record type has:
  * a FIXED field order (the tuple below),
  * its own type label, and
  * one of three separate keys.
The same functions are used when a record is written (app) and when it is
re-checked (verification engine), so the two can never disagree.
"""
from __future__ import annotations

from typing import Any, Mapping

from .config import get_settings
from .crypto import canonical, hmac_hex

# ---- Transactions --------------------------------------------------------
# Fixed order. `seq` and `prev_hash` are INSIDE the HMAC: that is what turns a
# pile of signed rows into a chain. Moving a row to another position, or
# removing the row before it, changes what these two fields should be.
TX_FIELDS = (
    "seq", "household_id", "shop_id", "dealer_id", "commodity", "quantity_kg",
    "entitlement_month", "created_at", "idempotency_key", "prev_hash",
)

# ---- Households ----------------------------------------------------------
HOUSEHOLD_FIELDS = (
    "id", "hh_code", "head_name_enc", "address_enc", "phone_enc", "family_size",
    "shop_id", "quota_rice_kg", "quota_wheat_kg", "quota_sugar_kg", "version",
    "last_change_request_id",
)
# Subset stored in audit snapshots (no personal data, not even encrypted).
HOUSEHOLD_SNAPSHOT_FIELDS = (
    "hh_code", "family_size", "shop_id", "quota_rice_kg", "quota_wheat_kg",
    "quota_sugar_kg", "version", "last_change_request_id",
)

# ---- Users ---------------------------------------------------------------
# password_hash is covered, so nobody can paste their own hash into another
# account. failed_logins / locked_until are NOT covered: they change often.
USER_FIELDS = (
    "id", "username", "password_hash", "role", "shop_id", "household_id", "is_active",
)
USER_SNAPSHOT_FIELDS = ("username", "role", "shop_id", "household_id", "is_active")

# ---- Change requests -----------------------------------------------------
CHANGE_REQUEST_FIELDS = (
    "id", "household_id", "field", "old_value", "new_value", "reason",
    "proposed_by", "proposed_at", "status", "decided_by", "decided_at",
)


def _get(record: Any, name: str) -> Any:
    return record[name] if isinstance(record, Mapping) else getattr(record, name)


def as_dict(record: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {name: _get(record, name) for name in fields}


def tx_hmac(record: Any) -> str:
    data = canonical("tx:v1", [(name, _get(record, name)) for name in TX_FIELDS])
    return hmac_hex(get_settings().tx_hmac_key, data)


def household_hmac(record: Any) -> str:
    data = canonical("household:v1", [(n, _get(record, n)) for n in HOUSEHOLD_FIELDS])
    return hmac_hex(get_settings().record_hmac_key, data)


def user_hmac(record: Any) -> str:
    data = canonical("user:v1", [(n, _get(record, n)) for n in USER_FIELDS])
    return hmac_hex(get_settings().record_hmac_key, data)


def change_request_hmac(record: Any) -> str:
    data = canonical("change_request:v1", [(n, _get(record, n)) for n in CHANGE_REQUEST_FIELDS])
    return hmac_hex(get_settings().record_hmac_key, data)
