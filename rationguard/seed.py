"""Fictional demo data. Every name, address and phone number is made up.
IDs use the invented format HH-000101; no real ID scheme is imitated."""
from __future__ import annotations

from sqlalchemy.orm import Session

from . import audit
from .accounts import create_user
from .config import seed_password
from .households import enrol_household
from .models import Shop

SHOPS = [("SHOP-01", "Greenfield Fair Price Shop"), ("SHOP-02", "Riverside Fair Price Shop"),
         ("SHOP-03", "Hilltop Fair Price Shop")]
FIRST = ["Asha", "Bimal", "Chitra", "Dev", "Esha", "Farid", "Gita", "Hari", "Indu", "Jai", "Kiran", "Lata"]
LAST = ["Sample", "Example", "Demo", "Testwala"]
STREETS = ["Lake Road", "Mill Lane", "Temple Street", "Station Road"]


def seed(db: Session) -> dict:
    """Create 3 shops, 12 households and one user of every kind."""
    password = seed_password()
    shops = []
    for code, name in SHOPS:
        shop = Shop(code=code, name=name)
        db.add(shop)
        shops.append(shop)
    db.flush()

    households = []
    for index, first in enumerate(FIRST):
        size = 2 + index % 5
        household = enrol_household(
            db, hh_code=f"HH-{101 + index:06d}",
            head_name=f"{first} {LAST[index % len(LAST)]}",
            address=f"{10 + index} {STREETS[index % len(STREETS)]}, Fictionpur",
            phone=f"555-01{index:02d}",
            family_size=size, shop_id=shops[index % 3].id,
            quota_rice_kg=5 * size, quota_wheat_kg=3 * size, quota_sugar_kg=size)
        households.append(household)

    for name in ("admin1", "admin2"):
        create_user(db, username=name, password=password, role="admin")
    create_user(db, username="auditor1", password=password, role="auditor")
    for index, shop in enumerate(shops, start=1):
        create_user(db, username=f"dealer{index}", password=password, role="dealer", shop_id=shop.id)
    for household in households:
        create_user(db, username=household.hh_code.replace("-", "").lower(), password=password,
                    role="household", household_id=household.id)
    db.commit()
    audit.write_anchor()   # sign the starting state straight away
    return {"shops": len(shops), "households": len(households), "users": 6 + len(households)}
