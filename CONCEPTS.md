# RationGuard concepts, in plain language

Study notes for the viva. Each idea follows the same order:

**What it is → Why we need it → How it works → Example from this project → Exam sentence → Common confusion**

---

## 0. First, what is a hash?

A hash function takes any data and gives back a short, fixed-length "fingerprint".

- Same input → always the same fingerprint.
- Change one character → a completely different fingerprint.
- You cannot work backwards from the fingerprint to the data.

SHA-256 is the hash function used here. Its fingerprint is 64 hex characters.

Everything below builds on this one idea.

---

## 1. HMAC (keyed fingerprint)

**What it is.** A fingerprint that can only be computed by someone who knows a secret key.

**Why we need it.** A plain hash has no secret. Suppose we stored `sha256(row)` next to each transaction. An insider changes 5 kg to 25 kg, then simply recomputes `sha256(new row)` and overwrites the stored hash. Everything matches again. The hash protected nothing.

**How it works.** `HMAC(key, data)` mixes a secret key into the hashing. Without the key, you cannot produce the right value. Our key sits in `.env`, **not** in the database.

**Analogy.** A plain hash is like a tamper sticker anyone can buy at a shop: break it, stick on a new one. An HMAC is like a wax seal pressed with a signet ring only the owner has. You can break the seal, but you cannot make a new one.

**Example from this project.**

```
transaction seq 1:  household 1, rice, 5 kg, ...   hmac = b2d3b9da...
```

Insider edits `quantity_kg` to 25. The verifier recomputes `HMAC(key, row with 25)` and gets a different value from the stored `b2d3b9da...` → **MODIFIED**.
`attacks/tamper_and_recompute_hash.py` shows the insider trying to fix the hash with SHA-256 and failing.

**Exam sentence.** *HMAC-SHA256 is a message authentication code that combines a secret key with a hash function; it provides integrity and authenticity, because only a holder of the key can produce a valid tag for a message.*

**Common confusion.**
- *HMAC vs hash:* a hash detects accidental change; an HMAC detects deliberate change by someone without the key.
- *HMAC vs encryption:* HMAC does not hide the data. The row is still readable. It only proves the row was not changed.
- *HMAC vs digital signature:* both prove integrity. HMAC uses **one shared secret key** (whoever can verify can also forge). A signature uses a **private key to sign and a public key to verify**.

### Canonical serialisation (a small but important detail)

Before hashing, a record must be turned into bytes in **one exact way**: fixed field order, fixed separators. Otherwise the same record could give two different fingerprints. We use JSON with a fixed field list. A plain `a|b|c` join is unsafe: `("ab","c")` and `("a","bc")` would both become `abc`. This is also why quantities are whole kilograms: `2.5` and `2.50` are the same number but different bytes.

---

## 2. Hash chain

**What it is.** Each record stores the fingerprint of the record before it, so the records form a chain.

**Why we need it.** An HMAC on each row catches a row being **changed**. It does not catch a row being **deleted**: the remaining rows are all still individually valid. It also does not catch rows being **swapped around**.

**How it works.** Each transaction has a sequence number and a `prev_hash` field holding the HMAC of the transaction before it. Both are *inside* that transaction's own HMAC.

**Analogy.** Numbered pages in a bound notebook, where each page also starts by repeating the last line of the previous page. Tear a page out and both the numbering and the repeated line give it away.

**Example from this project.**

```
seq 1: prev = 000...0   hmac = H1
seq 2: prev = H1        hmac = H2
seq 3: prev = H2        hmac = H3
```

Delete seq 2: the sequence jumps 1 → 3, and seq 3 points at `H2`, which no longer exists → **DELETED**.
Swap seq 2 and 3: each row's HMAC was computed with its old sequence number → **REORDERED**.

**Exam sentence.** *A hash chain links records by including the hash of the previous record in each new record, so any modification, deletion or reordering of earlier records breaks every later link.*

**Common confusion.** A hash chain is the core idea of a blockchain, but it is **not** a blockchain. There is no network, no mining, no consensus; it is one chain kept by one system.

**The weak spot.** A chain cannot notice that its **end** was cut off. Delete the newest three records and what remains is a perfect, shorter chain. That is what anchoring (section 5) fixes.

---

## 3. RBAC (role-based access control)

**What it is.** Permissions are given to **roles**, and each user has a role.

**Why we need it.** Giving permissions person by person does not scale and mistakes creep in. With roles, the whole policy fits in one small table that can be read and checked.

**How it works.**
1. Each route asks for one permission: `Depends(require(Perm.TX_CREATE))`.
2. `ROLE_PERMISSIONS` lists what each role may do.
3. **Deny by default:** if a pair (role, permission) is not in the table, the answer is no.
4. The check runs on the **server**. Hiding a button in the page is not security.

**Example from this project.**

| Role | Allowed |
|---|---|
| household | view own history and record |
| dealer | create transactions, view own shop |
| admin | list households, propose and decide changes |
| auditor | view logs, transactions, alerts; run verification. Nothing that changes data |

A dealer opening `/auditor` gets 403, and an `ACCESS_DENIED` entry is written to the audit log. A test (`test_every_route_is_protected_or_explicitly_public`) fails if a new route forgets its check.

**Exam sentence.** *RBAC assigns permissions to roles rather than to individual users; users obtain permissions through their role, which supports least privilege and separation of duties.*

**Common confusion.**
- *Authentication vs authorisation:* authentication = "who are you?" (login). Authorisation = "what may you do?" (RBAC).
- RBAC alone answers "may a household user view histories?" It does **not** answer "*which* household's history?". That is the next concept.

---

## 4. IDOR (insecure direct object reference)

**What it is.** A bug where the app checks that you are logged in and have the right role, but forgets to check that the **specific record** you asked for is yours.

**Why it matters here.** The history page is `/households/HH-000101/history`. If the server only checked "is this a household user?", then HH-000101 could type `HH-000102` into the URL and read a neighbour's history.

**How we stop it.** An **object-level check** after the role check:

- household user → only where `user.household_id == household.id`
- dealer → only where `household.shop_id == user.shop_id`

**Analogy.** A hotel key card. RBAC says "guests may open guest rooms". The object-level check says "…but only *your* room".

**Example from this project.** `attacks/idor_attempt.py`: own history → 200; neighbour's history → 403; a household ID that does not exist → also 403 with the identical page. That last point stops an attacker learning which IDs are real by comparing error codes.

**Exam sentence.** *IDOR is an access-control flaw in which an application uses a user-supplied identifier to fetch an object without verifying that the requesting user is authorised for that particular object.*

**Common confusion.** Making IDs random and hard to guess is **not** a fix; it only hides the problem. The fix is the ownership check on the server.

---

## 5. Anchoring (signed checkpoints)

**What it is.** Every so often we write down "the chain currently ends at entry N with fingerprint X", **sign** that note, and store it **outside the database**.

**Why we need it.** Two attacks leave every chain perfectly valid:

1. **Truncation:** delete the newest entries. The rest is a valid shorter chain.
2. **Roll-back:** replace the database file with last week's copy.

Chains prove that what exists is consistent. They cannot prove nothing is missing from the end.

**How it works.**
1. Take the latest audit entry number and hash, and the latest transaction number and HMAC.
2. Sign them with an **Ed25519 private key**.
3. Append the signed note to `anchors/anchors.jsonl`.
4. Verification checks each signature with the **public key**, then checks the database still contains that entry with that hash.

**Analogy.** Photographing the last page of a ledger each evening and posting the photo to someone else. If pages vanish later, the photo proves the ledger was longer.

**Example from this project.** `attacks/truncate_log_tail.py` removes transaction 3 and its log entries. Both chains still verify. The anchor says the log reached entry #36; it now ends at #35 → **LOG_TRUNCATED**.

**Why a signature and not an HMAC here?** Checking a signature needs only the public key, which is not secret. An outside auditor can verify anchors without being trusted with any key, and the private key could be kept on a different machine.

**Exam sentence.** *Anchoring periodically commits the current head of a hash chain, under a digital signature, to storage outside the system being protected, so that truncation or wholesale replacement of the chain can be detected.*

**Common confusion.** The anchor does not store the data, only the fingerprint of the chain head. And it only protects entries written **before** it; newer entries are covered by the next anchor.

---

## 6. Maker-checker (two-person rule)

**What it is.** One person proposes a sensitive change (the *maker*); a **different** person must approve it (the *checker*).

**Why we need it.** RBAC says admins may change quotas. But a single dishonest admin could raise a household's quota and share the extra grain with a dealer. Requiring two people means fraud needs **collusion**, which is harder and riskier.

**How it works.**
1. admin1 proposes: `HH-000101 quota_rice_kg 10 → 20`. Nothing changes yet.
2. admin2 approves. Only now is the household updated, its HMAC refreshed, and the before/after written to the audit log.
3. If the approver is the proposer, the server refuses (403) and logs `SELF_APPROVAL_BLOCKED`.

**The clever part.** The household's HMAC is refreshed **only** inside the approval step. So a household whose HMAC does not match was changed some other way, meaning a direct database edit → **UNAUTHORISED_CHANGE**. The change request row has its own HMAC too, so editing `proposed_by` to fake a different proposer is caught (`attacks/self_approve_change.py`).

**Exam sentence.** *Maker-checker enforces separation of duties by requiring that a transaction initiated by one authorised person be independently approved by a second authorised person before it takes effect.*

**Common confusion.** This is not "two admins exist". It is "the *same* admin can never do both steps of *one* change".

---

## 7. Shorter notes on the supporting ideas

### Argon2 (password hashing)
**Why not SHA-256 for passwords?** SHA-256 is designed to be fast; an attacker with stolen hashes can test billions of guesses per second. Argon2id is deliberately slow and memory-hungry, and adds a random **salt** per user, so identical passwords get different hashes and each guess is expensive.
*Confusion:* this is the opposite goal to HMAC. For records we want fast; for passwords we want slow.

### Lockout and rate limiting
Lockout: 5 wrong passwords locks **that account** for 15 minutes. Rate limit: at most 10 login attempts per minute from **one address**. Lockout stops many guesses at one account; the rate limit stops a few guesses at many accounts.

### Session cookie flags
After login the browser holds a random token in a cookie. `HttpOnly` = JavaScript cannot read it. `SameSite=Strict` = the browser does not send it on requests that start from another website. The database stores only the SHA-256 of the token, so stealing the table does not let you log in.

### CSRF (cross-site request forgery)
**Attack:** you are logged in; a malicious page silently submits a form to our site and your browser attaches your cookie. **Defence:** every form carries a secret token derived from your session. The malicious page cannot read our pages, so it cannot know the token, and the server rejects the request.

### Idempotency key
"Idempotent" means doing it twice has the same effect as doing it once. Each issue form carries a one-time random key. A double-click sends the same key twice; the server records one transaction and returns it for the second request.

### Append-only log and triggers
The app only ever inserts into the audit log. SQLite triggers make the database refuse `UPDATE` and `DELETE` on it. An insider who owns the file can drop the trigger, which is why this is called **defence in depth**: a cheap extra layer on top of the real protection (the chain).

### Fernet (encryption at rest)
Name, address and phone are stored encrypted. Someone who copies the database file sees only ciphertext. Fernet is *authenticated* encryption: if the ciphertext is altered, decryption fails instead of returning garbage.
*Confusion:* encryption gives **confidentiality**; HMAC gives **integrity**. We use both, for different fields and different threats.

### Least privilege and data minimisation
Give each role only what its job needs. The auditor sees transactions but never names. The admin sees the household record but not its history. Lists show `HH-***101`.

### Detect vs prevent
Against someone using the app, we **prevent** (403, blocked). Against someone editing the file, we can only **detect**. A good answer in the viva names which one applies.

### STRIDE
A checklist for finding threats: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege. See `THREAT_MODEL.md`.

---

## 8. How verification decides what happened

| What the engine sees | What it reports |
|---|---|
| Row's HMAC is wrong; a field differs from the audit snapshot | **MODIFIED**, with field, original value, current value |
| Row's HMAC is wrong; only `seq`/`prev_hash` differ from the snapshot | **REORDERED** |
| A sequence number is missing | **DELETED** (original contents shown from the snapshot) |
| Row's HMAC is wrong and no snapshot exists | **INSERTED** (forged row) |
| Audit entry's content does not match its hash, or a link is broken | **LOG_TAMPERED** |
| Anchor says the log was longer than it is now | **LOG_TRUNCATED** |
| Household / user / change request HMAC is wrong | **UNAUTHORISED_CHANGE** |
| A protective trigger is gone | **TRIGGER_MISSING** |

The "original value" comes from the snapshot saved in the audit log when the record was created, and is used only if that log entry itself passed its hash check.

---

## 9. Likely viva questions

**Q. If the attacker can edit the database, why can't they edit the HMAC too?**
They can edit the column, but they cannot compute the *correct* value without the key, and the key is not in the database.

**Q. What if the attacker gets the key?**
Then they can forge transactions. This is the main limitation. Anchors still help, because they need a different (private) key. A real system keeps keys in an HSM.

**Q. Why both an HMAC and a chain?**
HMAC catches a changed row. The chain catches deleted and reordered rows. Neither does the other's job.

**Q. Why both a chain and anchors?**
The chain cannot see that its end was removed. The anchor remembers how long it was.

**Q. Why Ed25519 for anchors but HMAC for records?**
Records are verified by the system itself, so a shared key is fine and fast. Anchors are meant to be checkable by an outsider who should not hold a secret.

**Q. Why is the auditor read-only?**
Separation of duties. The person checking the records must not be able to alter them.

**Q. Why are alerts not stored in a table?**
A stored alert is a row an insider could delete. Ours are recomputed from the tamper-evident log every time.

**Q. Where is SQL injection prevented?**
All queries go through SQLAlchemy with bound parameters. User input is never joined into SQL text.

**Q. Is this a blockchain?**
No. It borrows the hash-chain idea, but there is one writer and no consensus. For one organisation's records that is simpler, and the anchor provides the outside witness.

**Q. What is the difference between the trigger and the hash chain?**
The trigger *prevents* casual edits but can be dropped. The chain cannot prevent anything, but it *detects* edits even after the trigger is dropped.
