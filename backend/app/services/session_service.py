"""Secure session management.

The raw session token is generated randomly and returned to the client
once; only its SHA-256 hash is stored. A stolen database therefore cannot
be used to impersonate a live session. Sessions carry an expiry and an
explicit MFA flag, so a session created after a password check but before
the second factor cannot be used for anything.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.config import SESSION_LIFETIME_MINUTES
from app.crypto.hashing import sha256_hex
from app.crypto.random_gen import random_hex


def _now():
    return datetime.now(timezone.utc)


def create_session(conn, user_id: str, mfa_verified: bool = False,
                   ip_address: str = None, user_agent: str = None) -> str:
    """Create a session and return the raw token (shown to the client once)."""
    token = random_hex(32)
    issued = _now()
    expires = issued + timedelta(minutes=SESSION_LIFETIME_MINUTES)

    conn.execute(
        """INSERT INTO sessions
           (session_id, user_id, token_hash, mfa_verified,
            issued_at, expires_at, ip_address, user_agent, revoked)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
        (str(uuid.uuid4()), user_id, sha256_hex(token), 1 if mfa_verified else 0,
         issued.isoformat(), expires.isoformat(), ip_address, user_agent),
    )
    conn.commit()
    return token


def _lookup(conn, token: str):
    return conn.execute(
        "SELECT * FROM sessions WHERE token_hash = ?", (sha256_hex(token),)
    ).fetchone()


def validate_session(conn, token: str, require_mfa: bool = True):
    """Return the session row if usable, else None."""
    if not token:
        return None
    row = _lookup(conn, token)
    if row is None or row["revoked"]:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= _now():
        return None
    if require_mfa and not row["mfa_verified"]:
        return None
    return row


def mark_mfa_verified(conn, token: str) -> bool:
    row = _lookup(conn, token)
    if row is None:
        return False
    conn.execute("UPDATE sessions SET mfa_verified = 1 WHERE session_id = ?",
                 (row["session_id"],))
    conn.commit()
    return True


def revoke_session(conn, token: str) -> bool:
    """Log out: revoke rather than delete, so the record survives for audit."""
    row = _lookup(conn, token)
    if row is None:
        return False
    conn.execute("UPDATE sessions SET revoked = 1 WHERE session_id = ?",
                 (row["session_id"],))
    conn.commit()
    return True


def revoke_all_for_user(conn, user_id: str) -> None:
    """Used on password change or key rotation."""
    conn.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))
    conn.commit()