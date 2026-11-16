"""Generate fresh secrets on THIS machine.

Creates:
  .env                              HMAC keys, Fernet key, session secret, demo password
  keys/anchor_ed25519_private.pem   signs anchors
  keys/anchor_ed25519_public.pem    verifies anchors (safe to share)

Nothing here is ever committed: .env and keys/ are in .gitignore.
Run:  python scripts/setup_keys.py          (refuses to overwrite)
      python scripts/setup_keys.py --force  (new keys; old data can no longer be verified)
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def write_private(path: Path, data: bytes) -> None:
    """Create the file readable by the owner only (mode 600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def main() -> int:
    force = "--force" in sys.argv
    env_path = ROOT / ".env"
    private_path = ROOT / "keys" / "anchor_ed25519_private.pem"
    public_path = ROOT / "keys" / "anchor_ed25519_public.pem"

    if (env_path.exists() or private_path.exists()) and not force:
        print("Keys already exist (.env or keys/). Nothing changed.")
        print("Use --force to replace them (existing data will then fail verification).")
        return 0

    template = (ROOT / ".env.example").read_text()
    seed_password = secrets.token_urlsafe(12)
    values = {
        "RG_TX_HMAC_KEY": secrets.token_hex(32),
        "RG_AUDIT_HMAC_KEY": secrets.token_hex(32),
        "RG_RECORD_HMAC_KEY": secrets.token_hex(32),
        "RG_FERNET_KEY": Fernet.generate_key().decode(),
        "RG_SESSION_SECRET": secrets.token_hex(32),
        "RG_SEED_PASSWORD": seed_password,
    }
    lines = []
    for line in template.splitlines():
        name = line.split("=", 1)[0]
        lines.append(f"{name}={values[name]}" if name in values else line)
    write_private(env_path, ("\n".join(lines) + "\n").encode())

    private_key = Ed25519PrivateKey.generate()
    write_private(
        private_path,
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print("Created .env and keys/ with fresh random secrets (both are git-ignored).")
    print(f"Demo password for every seeded user: {seed_password}")
    print("(It is also stored in .env as RG_SEED_PASSWORD.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
