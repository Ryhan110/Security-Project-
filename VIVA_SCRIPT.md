# Viva demo script (about 8 minutes)

What to type, what the examiner sees, and what to say. Run everything from the project folder with the virtual environment turned on.

## 0. Opening (30 seconds)

> "The main attacker here is an insider: a dealer or admin with a real login who, in the worst case, can open the database file and edit it directly. So my system does not trust its own database. Every record has a keyed fingerprint whose key is not in the database, and a verification engine re-checks everything."

Show `THREAT_MODEL.md` briefly: the attacker table and the STRIDE table.

## 1. The main story: a tampered transaction (2 minutes)

```bash
./demo.sh
```

| On screen | Say |
|---|---|
| Step 3, all green | "The dealer recorded three distributions through the real app. Verification passes." |
| Step 4, the attack | "Now the insider opens the SQLite file with plain `sqlite3`, no keys, and changes 5 kg to 25 kg. He even drops the trigger and puts it back." |
| Step 5, red | "Verification names the exact record, the kind of failure, and the field: `quantity_kg` was 5, now 25. The original value comes from the snapshot in the audit log." |
| Step 6, alerts | "It is raised as CRITICAL because no audit entry explains the change, which means someone went around the app." |

## 2. "Why not just a hash?" (1.5 minutes)

```bash
./demo.sh tamper_and_recompute_hash
```

> "This attacker is smarter. He has read my source code, so he knows exactly how a record is turned into bytes. He changes the row and recomputes SHA-256. With a plain hash that would work perfectly. It fails here because the real value is an HMAC, and the key is in `.env`, not in the database."

## 3. "Why anchors?" (1.5 minutes)

```bash
./demo.sh truncate_log_tail
```

> "Here nothing is left broken. He deletes the newest transaction and the newest log entries. Both chains that remain are perfectly valid, just shorter. A hash chain cannot see that its end is missing. The signed anchor, stored outside the database, remembers the log was longer."

## 4. Access control (1.5 minutes)

```bash
./demo.sh idor_attempt
```

> "A household user changes the ID in the URL. Role checks alone would allow it, because he *is* a household user. The object-level check asks: is this *your* household? He gets 403, it is logged, and a household ID that does not exist gives the identical answer, so IDs cannot be guessed."

```bash
./demo.sh self_approve_change
```

> "One admin proposes a quota increase and tries to approve it himself: blocked. Then he edits the request row so it looks like the other admin proposed it: blocked again, because the request row has its own HMAC."

## 5. The tests (30 seconds)

```bash
python -m pytest -q
```

> "214 tests. Every attack has a test proving it is detected. Every role is tested against every route, and one test fails if a new route is added without a permission check."

## 6. Close with the limitations (1 minute)

Say these before you are asked. It shows you understand the design.

1. "The keys are on the same machine. A real system would keep them in an HSM."
2. "The anchor file is on the same disk. A real system would send anchors to external write-once storage."
3. "Against direct database edits I can only detect, not prevent."
4. "Software cannot know whether grain was physically handed over."

## If something goes wrong during the demo

| Problem | Fix |
|---|---|
| `Configuration error: ... is not set` | Run `python scripts/setup_keys.py` |
| `database is locked` | Stop any running `serve` in another terminal and run again |
| `./demo.sh: Permission denied` | Run `bash demo.sh` |
| Verification is red right after `setup_keys.py --force` | Old data was signed with the old keys. `./demo.sh` rebuilds the database |
