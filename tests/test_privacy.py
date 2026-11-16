"""Phase 6/9 - privacy: encryption at rest, masking, minimum data per role."""
from conftest import audit_rows, issue, new_client, sql


def test_personal_fields_are_encrypted_at_rest(db_path):
    data = db_path.read_bytes()
    for plaintext in (b"Asha", b"Sample", b"Lake Road", b"Fictionpur", b"555-01"):
        assert plaintext not in data
    name_enc = sql(db_path, "SELECT head_name_enc FROM households WHERE hh_code = 'HH-000101'")[0][0]
    from rationguard.crypto import decrypt
    assert name_enc.startswith("gAAAA") and decrypt(name_enc) == "Asha Sample"


def test_edited_ciphertext_does_not_decrypt_to_garbage():
    from rationguard.crypto import decrypt, encrypt
    token = encrypt("Asha Sample")
    broken = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert decrypt(broken).startswith("[unreadable")


def test_mask_helpers():
    from rationguard.crypto import mask_id, mask_phone
    assert mask_id("HH-000123") == "HH-***123"
    assert mask_phone("555-0100") == "******00"


def test_household_sees_its_own_details_only():
    page = new_client("hh000101").get("/households/HH-000101/history").text
    assert "Asha Sample" in page and "HH-000101" in page


def test_dealer_sees_history_without_name_and_with_masked_ids():
    dealer = new_client("dealer1")
    issue(dealer)
    history = dealer.get("/households/HH-000101/history").text
    assert "Asha" not in history and "HH-***101" in history and "HH-000101" not in history
    listing = dealer.get("/dealer").text
    assert "HH-***101" in listing and "Asha" not in listing


def test_auditor_never_sees_personal_details(db_path):
    issue(new_client("dealer1"))
    auditor = new_client("auditor1")
    pages = [auditor.get(path).text for path in
             ("/auditor", "/auditor/transactions", "/auditor/audit-log", "/households/HH-000101/history")]
    assert all("Asha" not in page and "Lake Road" not in page and "555-01" not in page for page in pages)
    assert auditor.get("/households/HH-000101").status_code == 403        # the personal record itself
    assert audit_rows(db_path, "HISTORY_VIEWED")[-1]["actor_username"] == "auditor1"


def test_admin_list_is_masked_and_detail_view_is_logged(db_path):
    admin = new_client("admin1")
    listing = admin.get("/admin/households").text
    assert ">HH-***101<" in listing and ">HH-000101<" not in listing and "Asha" not in listing
    detail = admin.get("/households/HH-000101").text
    assert "Asha Sample" in detail and "555-0100" not in detail and "******00" in detail
    assert audit_rows(db_path, "HOUSEHOLD_VIEWED")[-1]["actor_username"] == "admin1"
    assert admin.get("/households/HH-000101/history").status_code == 403  # admin does not need history


def test_audit_log_holds_no_personal_data(db_path):
    issue(new_client("dealer1"))
    new_client("admin1").get("/households/HH-000101")
    dump = " ".join(" ".join(str(v) for v in tuple(row)) for row in audit_rows(db_path))
    assert "Asha" not in dump and "Lake Road" not in dump and "555-01" not in dump
