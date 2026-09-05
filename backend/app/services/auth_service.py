"""Two-step authentication: password, then time-based second factor."""
import base64

from app.crypto import key_manager as km
from app.crypto import rsa_service, totp
from app.crypto.kdf import verify_password
from app.services import session_service, user_service


class AuthError(Exception):
    pass


def get_totp_secret(conn, user_id: str) -> str:
    """Decrypt a user's stored TOTP secret."""
    row = conn.execute(
        "SELECT totp_secret_enc FROM users WHERE user_id = ?", (user_id,)
    ).fetchone()
    if row is None or row["totp_secret_enc"] is None:
        raise LookupError("no TOTP secret for this user")

    _, private, _ = km.get_active_key(conn, user_id, km.RSA)
    ciphertext = base64.b64decode(row["totp_secret_enc"])
    return rsa_service.decrypt(ciphertext, private).decode()


def start_login(conn, username: str, password: str,
                ip_address: str = None, user_agent: str = None) -> str:
    """Step one: verify the password. Returns a session token awaiting MFA.

    The returned session has mfa_verified = 0 and cannot be used for any
    protected operation until complete_login succeeds.
    """
    row = user_service.find_by_username(conn, username)
    if row is None:
        raise AuthError("invalid credentials")

    if not verify_password(password, row["password_hash"],
                           row["password_salt"], row["kdf_iterations"]):
        raise AuthError("invalid credentials")

    return session_service.create_session(
        conn, row["user_id"], mfa_verified=False,
        ip_address=ip_address, user_agent=user_agent)


def complete_login(conn, token: str, code: str) -> bool:
    """Step two: verify the one-time code and upgrade the session."""
    row = session_service.validate_session(conn, token, require_mfa=False)
    if row is None:
        raise AuthError("session is invalid or expired")

    secret = get_totp_secret(conn, row["user_id"])
    if not totp.verify_code(secret, code):
        raise AuthError("invalid verification code")

    session_service.mark_mfa_verified(conn, token)
    return True


def current_user(conn, token: str):
    """The authenticated user row for a fully verified session, or None."""
    row = session_service.validate_session(conn, token, require_mfa=True)
    if row is None:
        return None
    return conn.execute("SELECT * FROM users WHERE user_id = ?",
                        (row["user_id"],)).fetchone()


def logout(conn, token: str) -> bool:
    return session_service.revoke_session(conn, token)