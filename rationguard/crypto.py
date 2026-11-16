"""Small cryptographic building blocks. Nothing here is home-made crypto: we
only call well-known primitives (HMAC-SHA256, Fernet, Ed25519) from the
standard library and the `cryptography` package.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .config import get_settings

GENESIS_HASH = "0" * 64  # "previous hash" of the very first record in a chain


# --------------------------------------------------------------------------
# Canonical serialisation
# --------------------------------------------------------------------------
def canonical(record_type: str, fields: Sequence[tuple[str, Any]]) -> bytes:
    """Turn a record into ONE exact sequence of bytes.

    A hash only helps if the same record always produces the same bytes.
    So we fix everything: the field order (the caller passes a fixed list),
    the separators, and the character encoding.

    Why JSON and not just "a|b|c"? With a plain join, the two different
    records ("ab", "c") and ("a", "bc") could both become "abc". JSON quotes
    every value, so field boundaries can never be confused.

    `record_type` (for example "tx:v1") is included so that a valid HMAC for
    one kind of record can never be replayed as another kind.
    """
    body = [record_type, [[name, value] for name, value in fields]]
    return json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# --------------------------------------------------------------------------
# HMAC
# --------------------------------------------------------------------------
def hmac_hex(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 as hex text.

    WHY NOT A PLAIN SHA-256 HASH?
    A plain hash needs no secret. An insider who changes quantity 5 -> 25 in
    the database can simply run sha256 over the new row and overwrite the
    stored hash too; everything would look consistent again.
    HMAC mixes a SECRET KEY into the hash. The key lives in .env, not in the
    database, so the insider can change the row but cannot produce the
    matching HMAC. (attacks/tamper_and_recompute_hash.py demonstrates this.)
    """
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def same(a: str, b: str) -> bool:
    """Constant-time comparison, so response timing does not leak how many
    leading characters of a secret value were correct."""
    return hmac.compare_digest(a.encode(), b.encode())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Encryption at rest (Fernet = AES-128-CBC + HMAC, with a random IV)
# --------------------------------------------------------------------------
def encrypt(plaintext: str) -> str:
    return Fernet(get_settings().fernet_key).encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    try:
        return Fernet(get_settings().fernet_key).decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        # Fernet is "authenticated": if the ciphertext was edited, it refuses
        # to decrypt instead of returning garbage.
        return "[unreadable: ciphertext was modified]"


# --------------------------------------------------------------------------
# Ed25519 signatures (used for anchors)
# --------------------------------------------------------------------------
def sign(message: bytes) -> str:
    pem = get_settings().signing_private_key.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key.sign(message).hex()


def signature_ok(message: bytes, signature_hex: str) -> bool:
    """Needs only the PUBLIC key. An auditor can check anchors without ever
    holding a secret, which is why anchors use signatures and not HMAC."""
    pem = get_settings().signing_public_key.read_bytes()
    key = serialization.load_pem_public_key(pem)
    assert isinstance(key, Ed25519PublicKey)
    try:
        key.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------
def mask_id(hh_code: str) -> str:
    """HH-000123 -> HH-***123. Lists show only the last three digits."""
    if len(hh_code) < 6:
        return "***"
    return hh_code[:3] + "*" * (len(hh_code) - 6) + hh_code[-3:]


def mask_phone(phone: str) -> str:
    return "*" * max(0, len(phone) - 2) + phone[-2:]
