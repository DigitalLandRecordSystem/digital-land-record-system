"""Two-step authentication: password, then an emailed one-time code."""
from app.services import mailer, otp_service, session_service, user_service


class AuthError(Exception):
    pass


def _address(conn, user_id: str) -> str:
    """The user's email, decrypted under the key version that wrote it.

    Routed through user_service.get_user_details so this path inherits the
    recorded-key-version lookup rather than repeating it. Reading the active
    key here would silently lock out every rotated account.
    """
    return user_service.get_user_details(conn, user_id)["email"]


def masked_address(conn, user_id: str) -> str:
    """Where the code was sent, safe to display on the verification page."""
    return mailer.mask(_address(conn, user_id))


def _dispatch(conn, session_row) -> None:
    code = otp_service.issue(conn, session_row["user_id"],
                             session_row["session_id"])
    mailer.send_otp(_address(conn, session_row["user_id"]), code)


def start_login(conn, username: str, password: str,
                ip_address: str = None, user_agent: str = None) -> str:
    """Step one: verify the password, then email a code.

    The returned session has mfa_verified = 0 and cannot be used for any
    protected operation until complete_login succeeds.
    """
    from app.crypto.kdf import verify_password

    row = user_service.find_by_username(conn, username)
    if row is None:
        raise AuthError("invalid credentials")

    if not verify_password(password, row["password_hash"],
                           row["password_salt"], row["kdf_iterations"]):
        raise AuthError("invalid credentials")

    token = session_service.create_session(
        conn, row["user_id"], mfa_verified=False,
        ip_address=ip_address, user_agent=user_agent)

    _dispatch(conn, session_service.validate_session(conn, token,
                                                     require_mfa=False))
    return token


def resend(conn, token: str) -> None:
    """Issue and send a replacement code, invalidating the previous one."""
    row = session_service.validate_session(conn, token, require_mfa=False)
    if row is None or row["mfa_verified"]:
        raise AuthError("session is invalid or expired")
    _dispatch(conn, row)


def complete_login(conn, token: str, code: str) -> str:
    """Step two: verify the code and issue a fresh, verified session.

    The pending token is revoked and replaced rather than upgraded, so a
    token observed before the second factor can never become an
    authenticated session.
    """
    row = session_service.validate_session(conn, token, require_mfa=False)
    if row is None:
        raise AuthError("session is invalid or expired")
    if row["mfa_verified"]:
        raise AuthError("session already verified")

    if not otp_service.verify(conn, row["session_id"], code):
        raise AuthError("invalid or expired verification code")

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