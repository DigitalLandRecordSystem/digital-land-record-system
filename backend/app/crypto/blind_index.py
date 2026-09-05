"""Blind indexes for looking up encrypted fields.

Encrypted values cannot be searched directly, and must not be, since the
encrypting key may rotate. Instead each searchable field is stored
alongside HMAC(value, BLIND_INDEX_KEY): deterministic, so it can be
indexed and matched, but not reversible to the original value. The key
lives in .env, never in the database.
"""
from app.config import BLIND_INDEX_KEY
from app.crypto.hmac_service import hmac_hex


def blind_index(value: str) -> str:
    """Deterministic, irreversible lookup token for a field value."""
    return hmac_hex(BLIND_INDEX_KEY, value.strip().lower().encode("utf-8"))