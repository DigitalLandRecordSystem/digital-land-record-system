"""HMAC tags over stored records, to detect unauthorised modification.

Encryption hides a record's contents but does not prevent someone with
database access from altering or replacing ciphertext. An HMAC over the
stored fields, keyed with a secret held outside the database, makes any
such change detectable: the tag will not verify.
"""
from app.config import INTEGRITY_KEY
from app.crypto.hmac_service import hmac_hex, verify_hmac

SEPARATOR = "|"


def _payload(*fields) -> bytes:
    return SEPARATOR.join("" if f is None else str(f) for f in fields).encode("utf-8")


def compute_tag(*fields) -> str:
    """HMAC tag over the given field values, in order."""
    return hmac_hex(INTEGRITY_KEY, _payload(*fields))


def verify_tag(tag: str, *fields) -> bool:
    """Constant-time check that the fields still match their tag."""
    return verify_hmac(INTEGRITY_KEY, _payload(*fields), tag)