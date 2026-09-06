import pytest

from app.services import auth_service as auth
from app.services import session_service as ss
from app.services import user_service as us
from app.services import otp_service as otp


@pytest.fixture
def account(conn):
    uid = us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2")
    return uid


# ---- email OTP ----

def test_code_is_six_digits(conn, account, outbox):
    auth.start_login(conn, "maimuna", "hunter2")
    address, code = outbox[-1]
    assert address == "maimuna@example.com"
    assert len(code) == 6 and code.isdigit()


def test_plaintext_code_never_stored(conn, account, outbox):
    auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    row = conn.execute("SELECT * FROM login_otps").fetchone()
    assert code not in " ".join(str(v) for v in tuple(row))


def test_code_is_single_use(conn, account, outbox):
    """A code that has been accepted once is consumed and cannot be reused."""
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    session_id = ss.validate_session(conn, pending,
                                     require_mfa=False)["session_id"]
    assert otp.verify(conn, session_id, code)
    assert not otp.verify(conn, session_id, code)


def test_code_is_bound_to_its_session(conn, account, outbox):
    """A code issued for one sign-in cannot complete a different one."""
    auth.start_login(conn, "maimuna", "hunter2")
    first_code = outbox[-1][1]
    second = auth.start_login(conn, "maimuna", "hunter2")
    with pytest.raises(auth.AuthError):
        auth.complete_login(conn, second, first_code)


def test_expired_code_rejected(conn, account, outbox):
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    conn.execute("UPDATE login_otps SET expires_at = '2000-01-01T00:00:00+00:00'")
    conn.commit()
    with pytest.raises(auth.AuthError):
        auth.complete_login(conn, pending, code)


def test_attempts_are_capped(conn, account, outbox):
    from app.config import OTP_MAX_ATTEMPTS
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    for _ in range(OTP_MAX_ATTEMPTS):
        with pytest.raises(auth.AuthError):
            auth.complete_login(conn, pending, "000000")
    with pytest.raises(auth.AuthError):        # the real code no longer works
        auth.complete_login(conn, pending, code)


def test_resend_invalidates_the_previous_code(conn, account, outbox):
    pending = auth.start_login(conn, "maimuna", "hunter2")
    old = outbox[-1][1]
    auth.resend(conn, pending)
    new = outbox[-1][1]
    with pytest.raises(auth.AuthError):
        auth.complete_login(conn, pending, old)
    assert auth.complete_login(conn, pending, new)


# ---- login flow ----

def test_full_login(conn, account, outbox):
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    token = auth.complete_login(conn, pending, code)
    assert token != pending
    assert auth.current_user(conn, token)["user_id"] == account


def test_session_unusable_before_second_factor(conn, account):
    """The core two-step requirement: password alone grants nothing."""
    token = auth.start_login(conn, "maimuna", "hunter2")
    assert auth.current_user(conn, token) is None


def test_pending_token_dies_after_verification(conn, account, outbox):
    """Token rotation at the MFA boundary: the pre-MFA token is never upgraded."""
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    token = auth.complete_login(conn, pending, code)
    assert auth.current_user(conn, pending) is None
    assert auth.current_user(conn, token) is not None


def test_wrong_password_rejected(conn, account):
    with pytest.raises(auth.AuthError):
        auth.start_login(conn, "maimuna", "wrong")


def test_unknown_user_rejected(conn):
    with pytest.raises(auth.AuthError):
        auth.start_login(conn, "nobody", "hunter2")


def test_wrong_code_rejected(conn, account):
    token = auth.start_login(conn, "maimuna", "hunter2")
    with pytest.raises(auth.AuthError):
        auth.complete_login(conn, token, "000000")
    assert auth.current_user(conn, token) is None


def test_logout_revokes(conn, account, outbox):
    pending = auth.start_login(conn, "maimuna", "hunter2")
    code = outbox[-1][1]
    token = auth.complete_login(conn, pending, code)
    assert auth.logout(conn, token)
    assert auth.current_user(conn, token) is None


# ---- sessions ----

def test_raw_token_not_stored(conn, account):
    token = ss.create_session(conn, account, mfa_verified=True)
    row = conn.execute("SELECT token_hash FROM sessions").fetchone()
    assert token not in row["token_hash"]
    assert len(row["token_hash"]) == 64


def test_expired_session_rejected(conn, account):
    token = ss.create_session(conn, account, mfa_verified=True)
    conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
    conn.commit()
    assert ss.validate_session(conn, token) is None


def test_unknown_token_rejected(conn):
    assert ss.validate_session(conn, "deadbeef" * 8) is None