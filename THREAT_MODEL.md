# RationGuard Threat Model (STRIDE)

All data in this project is fictional. Household IDs look like `HH-000123`.

## 1. What are we protecting?

| Asset | Why it matters | Security goal |
|---|---|---|
| Transaction records (who got how much grain) | Changing 5 kg to 25 kg hides stolen grain | **Integrity** |
| Beneficiary records (family size, quota, shop) | A bigger quota means more grain can be diverted | **Integrity + authorisation** |
| A household's distribution history | Private information about a family | **Confidentiality** |
| The audit log | It is the evidence. If it can be rewritten, nothing can be proven | **Integrity** |
| Keys (HMAC keys, Fernet key, signing key) | Whoever holds them can forge records | **Confidentiality** |

## 2. Who is the attacker?

The main attacker is an **insider**. They are not breaking in from outside; they already have a valid login.

| Attacker | What they can do |
|---|---|
| **A1. Dishonest dealer** | Logs in as a dealer. Tries to record fake or inflated distributions. |
| **A2. Dishonest admin** | Logs in as an admin. Tries to raise a quota or move a household without anyone checking. |
| **A3. Insider with database file access** (worst case) | Opens `rationguard.db` with any SQLite tool and edits rows directly. The app, its login and its permission checks are bypassed completely. Can also drop database triggers. |
| **A4. Curious household user** | Logs in as a household and tries to read another family's history. |
| **A5. Outsider** | No account. Tries to guess passwords or trick a logged-in user's browser (CSRF). |

**What we assume the attacker does NOT have:** the secret keys in `.env` and the Ed25519 private key in `keys/`. This assumption is the biggest limitation of the project and is discussed honestly in the README.

## 3. Trust boundaries

```
 Browser  ──(HTTP: cookies, forms)──►  FastAPI app  ──(SQL)──►  SQLite file
                                          │                         ▲
                                          │ keys from .env          │ A3 edits this directly
                                          ▼                         │
                                   keys/ + anchors file  (outside the database)
```

The important idea: **the database is not trusted.** Anything read from it is re-checked with a key the database does not contain.

## 4. Controls (the list every feature maps to)

| ID | Control | Where in the code |
|---|---|---|
| C1 | Argon2id password hashing | `rationguard/security.py` |
| C2 | Login rate limit (per IP) and account lockout (per user) | `rationguard/security.py`, `app.py` |
| C3 | Server-side sessions; cookie is HttpOnly + SameSite=Strict; only a hash of the token is stored | `rationguard/security.py` |
| C4 | CSRF token on every form, checked for every POST | `rationguard/security.py`, `app.py` |
| C5 | RBAC, deny by default, one `require(permission)` dependency on every route | `rationguard/rbac.py` |
| C6 | Object-level checks (anti-IDOR): household sees only itself, dealer only own shop | `rationguard/rbac.py` |
| C7 | Every denied access is written to the audit log | `rationguard/rbac.py` |
| C8 | HMAC-SHA256 on every transaction, key kept in `.env` | `rationguard/integrity.py` |
| C9 | Transaction hash chain (sequence number + previous hash) | `rationguard/transactions.py` |
| C10 | Append-only, hash-chained audit log with before/after values | `rationguard/audit.py` |
| C11 | SQLite triggers that block UPDATE/DELETE on audit log and transactions | `rationguard/db.py` |
| C12 | Ed25519-signed anchors stored in a file outside the database | `rationguard/audit.py` |
| C13 | Verification engine (CLI + auditor page) that pinpoints record and field | `rationguard/verify.py` |
| C14 | Idempotency keys | `rationguard/transactions.py` |
| C15 | Fraud rules (duplicate issue, over quota, rapid repeat, dealer velocity) | `rationguard/transactions.py`, `rationguard/detection.py` |
| C16 | Maker-checker: a different admin must approve; self-approval rejected | `rationguard/households.py` |
| C17 | HMAC on household, user and change-request rows | `rationguard/integrity.py` |
| C18 | Insider-threat alerts with severity, recomputed from the audit log | `rationguard/detection.py` |
| C19 | Fernet encryption of name, address, phone | `rationguard/crypto.py` |
| C20 | ID masking and minimum data per role | `rationguard/crypto.py`, templates |
| C21 | Secrets never logged; audit entries are scrubbed | `rationguard/audit.py` |
| C22 | Keys only in `.env` / `keys/`, both git-ignored; app refuses to start without them | `rationguard/config.py`, `.gitignore` |
| C23 | Parameterised SQL only (SQLAlchemy), auto-escaped templates, security headers | everywhere, `app.py` |

## 5. STRIDE threat table

STRIDE is a checklist of six kinds of threat:
**S**poofing (pretending to be someone), **T**ampering (changing data), **R**epudiation (denying you did it), **I**nformation disclosure (leaking data), **D**enial of service (making it unusable), **E**levation of privilege (getting more power than allowed).

"Prevents" means the attack is stopped. "Detects" means the attack may succeed but is caught afterwards. Against attacker A3 (direct database edits) we can mostly only **detect**, because nothing inside the database can stop someone who owns the file.

### Spoofing

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| S1 | Guess a user's password by trying many | A5, A1 | C2 rate limit + lockout; C18 failed-login alert | Prevents + Detects |
| S2 | Steal password hashes from the DB file and crack them | A3 | C1 Argon2id is slow and salted | Prevents (makes cracking expensive) |
| S3 | Steal a session token from the DB and reuse it | A3 | C3 only SHA-256 of the token is stored | Prevents |
| S4 | Steal the session cookie with JavaScript | A5 | C3 HttpOnly cookie; C23 CSP and escaping | Prevents |
| S5 | Trick a logged-in user's browser into submitting a form (CSRF) | A5 | C4 CSRF token; C3 SameSite=Strict | Prevents |
| S6 | Replace another user's password hash in the DB with your own, then log in as them | A3 | C17 user-row HMAC covers the password hash; login refuses a row whose HMAC fails | Prevents + Detects |
| S7 | Session fixation (plant a known session ID before login) | A5 | C3 a brand-new random token is issued at login | Prevents |

### Tampering

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| T1 | Edit a transaction row (5 kg → 25 kg) | A3 | C8 HMAC fails; C13 shows the field, old and new value; C11 trigger | Detects |
| T2 | Edit a row **and recompute its hash** | A3 | C8 the "hash" is an HMAC; without the key the attacker cannot recompute it | Detects |
| T3 | Delete a transaction from the middle | A3 | C9 gap in sequence / broken chain; C10 audit snapshot shows what was deleted | Detects |
| T4 | Delete the **last** transaction(s) (chain still looks fine) | A3 | C10 audit entry has no matching row; C12 anchor says the chain used to be longer | Detects |
| T5 | Reorder transactions | A3 | C8 sequence number is inside the HMAC; C9 | Detects |
| T6 | Insert a fake ("ghost") transaction | A3 | C8 no valid HMAC possible without key; no audit entry | Detects |
| T7 | Edit or delete an audit log row | A3 | C11 trigger blocks it; if trigger dropped, C10 chain breaks | Prevents (casual) + Detects |
| T8 | Delete the newest audit entries, or roll the whole DB back to an old copy | A3 | C12 signed anchor records a later chain head | Detects |
| T9 | Change a household's quota / family size / shop directly in the DB | A3 | C17 household HMAC fails → "unauthorised change" | Detects |
| T10 | Admin raises a quota alone through the app | A2 | C16 maker-checker, self-approval rejected | Prevents |
| T11 | Admin edits the change request row so it looks like someone else proposed it, then approves it | A2+A3 | C17 change-request HMAC is checked before approval | Prevents + Detects |
| T12 | Dealer submits the same transaction twice | A1 (or accident) | C14 idempotency key | Prevents |
| T13 | Dealer records more than the monthly quota | A1 | C15 over-quota is blocked and logged | Prevents + Detects |
| T14 | Dealer records transactions for households of another shop | A1 | C6 object-level check | Prevents + Detects (C7) |
| T15 | SQL injection through a form field | A1, A4, A5 | C23 parameterised queries | Prevents |
| T16 | Drop the protective triggers | A3 | C13 verification reports missing triggers | Detects |

### Repudiation

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| R1 | "I never created that transaction / approved that change" | A1, A2 | C10 audit log records who, what, when, IP, before/after | Detects (provides evidence) |
| R2 | Erase the evidence by editing the log | A3 | C10 chain + C11 triggers + C12 anchors | Detects |
| R3 | Quietly probe for access and deny it later | A1, A4 | C7 every denial logged; C18 denied-burst alert | Detects |

### Information disclosure

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| I1 | Household A changes the ID in the URL to read household B's history (IDOR) | A4 | C6 object-level check; C7 logged | Prevents + Detects |
| I2 | Dealer browses households of other shops | A1 | C6 | Prevents |
| I3 | Admin or auditor sees more personal data than the job needs | A2 | C20 minimum data per role, masked IDs; auditor never sees name/address | Prevents |
| I4 | Someone copies the DB file and reads names, addresses, phone numbers | A3 | C19 Fernet encryption at rest | Prevents (for those fields) |
| I5 | Secrets leak through the audit log | anyone reading logs | C21 scrubbing; passwords and tokens never logged | Prevents |
| I6 | Keys leak through the git repository | anyone with the repo | C22 `.gitignore`, `.env.example`, setup script | Prevents |
| I7 | Login page reveals which usernames exist | A5 | Same error message and similar timing for "no such user" and "wrong password" | Prevents |

### Denial of service

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| D1 | Flood the login page | A5 | C2 per-IP rate limit | Prevents (partly) |
| D2 | Lock out a victim by failing their login on purpose | A5 | Lockout is temporary (15 min); C18 alert. **Accepted trade-off**, see README | Detects |
| D3 | Destroy the database file | A3 | Out of scope (needs backups). Anchors would show a restored old copy is stale | Not prevented |

### Elevation of privilege

| # | Threat | Who | Control | Prevents / Detects |
|---|---|---|---|---|
| E1 | Call an admin or auditor route as a lower role | A1, A4 | C5 deny by default on the server for every route | Prevents + Detects (C7) |
| E2 | A new route is added and someone forgets the permission check | developer mistake | C5 a test fails if any route has no `require(...)` | Prevents |
| E3 | Change your own role to `admin` directly in the DB | A3 | C17 user-row HMAC fails → login refused, CRITICAL alert | Prevents + Detects |
| E4 | Auditor modifies data | auditor | C5 auditor has only read/verify permissions | Prevents |
| E5 | Legitimate role change misused | A2 | Roles change only through the CLI, which is audit-logged; C18 role-change alert | Detects |

## 6. Feature → threat mapping (quick check)

| Feature in the brief | Controls | Threat rows |
|---|---|---|
| 1. Authentication | C1–C4 | S1–S7, I7, D1, D2 |
| 2. RBAC + IDOR + denial logging | C5–C7 | E1, E2, E4, I1, I2, T14, R3 |
| 3. Transaction integrity | C8, C9 | T1–T6 |
| 4. Tamper-evident audit log + anchors | C10–C12, C21 | T7, T8, T4, R1, R2, I5 |
| 5. Verification engine | C13 | T1–T9, T16 (it is how they are detected) |
| 6. Duplicate and fraud detection | C14, C15 | T12, T13 |
| 7. Verification of admin changes | C16, C17 | T9, T10, T11 |
| 8. Insider-threat detection | C18 | S1, R3, E3, E5, T9 |
| 9. Privacy | C19, C20 | I3, I4 |
| Project hygiene | C22, C23 | I6, T15 |

## 7. What is deliberately NOT covered

- An attacker who steals the keys (see README, "Limitations").
- Physical destruction of the server or the DB file.
- Attacks on the operating system, the network (no TLS in the demo) or the Python runtime.
- A dealer who types an honest-looking but false transaction while the household is not present. Software cannot know what physically happened; only the fraud rules (C15) and alerts (C18) give hints.
