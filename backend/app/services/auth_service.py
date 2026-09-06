"""Two-step authentication: password, then time-based second factor."""
import base64

from app.crypto import key_manager as km
from app.crypto import rsa_service, totp
from app.crypto.kdf import verify_password
from app.services import session_service, user_service
from app.config import KDF_ITERATIONS

# Fixed decoy values, used only to spend the same time on a username that
# does not exist as on one that does. They are not a hash of any password.
_DUMMY_SALT = "00" * 16
_DUMMY_HASH = "00" * 32

class AuthError(Exception):
    pass


def get_totp_secret(conn, user_id: str) -> str:
    """Decrypt a user's stored TOTP secret, under the key version that wrote it."""
    row = conn.execute(
        "SELECT totp_secret_enc, key_version FROM users WHERE user_id = ?",
        (user_id,)).fetchone()
    if row is None or row["totp_secret_enc"] is None:
        raise LookupError("no TOTP secret for this user")

    _, private = km.get_key_version(conn, user_id, km.RSA, row["key_version"])
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
        # Returning early here would leak which usernames exist: a miss would
        # answer in microseconds and a hit only after a full KDF run. Derive
        # against a dummy salt instead, so both paths cost the same, then fail.
        verify_password(password, _DUMMY_HASH, _DUMMY_SALT, KDF_ITERATIONS)
        raise AuthError("invalid credentials")

    if not verify_password(password, row["password_hash"],
                           row["password_salt"], row["kdf_iterations"]):
        raise AuthError("invalid credentials")

    return session_service.create_session(
        conn, row["user_id"], mfa_verified=False,
        ip_address=ip_address, user_agent=user_agent,
        lifetime_minutes=session_service.PENDING_LIFETIME_MINUTES)


def complete_login(conn, token: str, code: str) -> str:
    """Step two: verify the one-time code and issue a fresh, verified session.

    The pending token is revoked and replaced rather than upgraded, so a token
    observed before the second factor can never become an authenticated session.
    """
    row = session_service.validate_session(conn, token, require_mfa=False)
    if row is None:
        raise AuthError("session is invalid or expired")
    if row["mfa_verified"]:
        raise AuthError("session already verified")

    secret = get_totp_secret(conn, row["user_id"])
    if not totp.verify_code(secret, code):
        raise AuthError("invalid verification code")

    session_service.revoke_session(conn, token)
    return session_service.create_session(
        conn, row["user_id"], mfa_verified=True,
        ip_address=row["ip_address"], user_agent=row["user_agent"])


def current_user(conn, token: str):
    """The authenticated user row for a fully verified session, or None."""
    row = session_service.validate_session(conn, token, require_mfa=True)
    if row is None:
        return None
    return conn.execute("SELECT * FROM users WHERE user_id = ?",
                        (row["user_id"],)).fetchone()


def logout(conn, token: str) -> bool:
    return session_service.revoke_session(conn, token)