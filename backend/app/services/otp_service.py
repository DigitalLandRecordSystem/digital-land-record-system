"""Email one-time passwords: the second authentication factor.

A fresh six-digit code is generated for each pending login and bound to
that session, so a code issued for one sign-in attempt can never complete
another. Only HMAC(code) is stored, under a key held outside the database,
exactly as the raw session token is never stored.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.config import OTP_KEY, OTP_MAX_ATTEMPTS, OTP_TTL_SECONDS
from app.crypto.hmac_service import hmac_hex, verify_hmac
from app.crypto.random_gen import random_below

DIGITS = 6


def _now():
    return datetime.now(timezone.utc)


def _consume(conn, otp_id: str) -> None:
    conn.execute("UPDATE login_otps SET consumed = 1 WHERE otp_id = ?", (otp_id,))
    conn.commit()


def generate_code() -> str:
    """A uniform six-digit code.

    random_below uses rejection sampling, so every code is equally likely.
    Taking random bytes modulo 10**6 would bias the low codes.
    """
    return str(random_below(10 ** DIGITS)).zfill(DIGITS)


def issue(conn, user_id: str, session_id: str) -> str:
    """Create a code for a pending session and return it for delivery.

    Any earlier code for the same session is consumed first, so only the
    most recently issued code can be used.
    """
    conn.execute("UPDATE login_otps SET consumed = 1 WHERE session_id = ?",
                 (session_id,))

    code = generate_code()
    issued = _now()
    conn.execute(
        """INSERT INTO login_otps
           (otp_id, user_id, session_id, code_hmac, attempts, consumed,
            issued_at, expires_at)
           VALUES (?, ?, ?, ?, 0, 0, ?, ?)""",
        (str(uuid.uuid4()), user_id, session_id,
         hmac_hex(OTP_KEY, code.encode("utf-8")),
         issued.isoformat(),
         (issued + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()),
    )
    conn.commit()
    return code


def verify(conn, session_id: str, code: str) -> bool:
    """Check a code against its pending session. Single use, attempt-capped."""
    row = conn.execute(
        """SELECT * FROM login_otps
           WHERE session_id = ? AND consumed = 0
           ORDER BY issued_at DESC LIMIT 1""", (session_id,)).fetchone()
    if row is None:
        return False

    if datetime.fromisoformat(row["expires_at"]) <= _now():
        _consume(conn, row["otp_id"])
        return False

    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        _consume(conn, row["otp_id"])
        return False

    matched = bool(code) and verify_hmac(
        OTP_KEY, code.encode("utf-8"), row["code_hmac"])

    conn.execute(
        "UPDATE login_otps SET attempts = attempts + 1, consumed = ? "
        "WHERE otp_id = ?",
        (1 if matched else 0, row["otp_id"]),
    )
    conn.commit()
    return matched