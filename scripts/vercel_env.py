"""Generate a fresh, separate set of secrets for the hosted demo.

Writes `.env.vercel` (git-ignored). Import that file in Vercel:
  Project -> Settings -> Environment Variables -> "Import .env"
These are NOT your local keys: the hosted copy and your laptop never share
secrets, so leaking one does not affect the other.
"""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def build() -> dict[str, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "RG_TX_HMAC_KEY": secrets.token_hex(32),
        "RG_AUDIT_HMAC_KEY": secrets.token_hex(32),
        "RG_RECORD_HMAC_KEY": secrets.token_hex(32),
        "RG_SESSION_SECRET": secrets.token_hex(32),
        "RG_FERNET_KEY": Fernet.generate_key().decode(),
        "RG_SEED_PASSWORD": secrets.token_urlsafe(12),
        "RG_SIGNING_PRIVATE_KEY_B64": base64.b64encode(private).decode(),
        "RG_SIGNING_PUBLIC_KEY_B64": base64.b64encode(public).decode(),
        "RG_ANCHOR_EVERY": "1",
    }


def main() -> None:
    values = build()
    path = ROOT / ".env.vercel"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write("".join(f"{name}={value}\n" for name, value in values.items()))
    print(f"Wrote {path.name} (git-ignored). Import it into Vercel's Environment Variables.")
    print(f"Login password for the hosted demo users: {values['RG_SEED_PASSWORD']}")


if __name__ == "__main__":
    main()
