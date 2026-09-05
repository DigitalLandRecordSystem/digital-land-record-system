import time
import pytest

from app.crypto import totp
from app.services import auth_service as auth
from app.services import session_service as ss
from app.services import user_service as us

ALIGNED = 1_700_000_040          # exact multiple of 30, so windows are clean


@pytest.fixture
def account(conn):
    uid = us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2")
    return uid


# ---- TOTP ----

def test_code_is_six_digits():
    secret = totp.generate_secret()
    code = totp.generate_code(secret, ALIGNED)
    assert len(code) == 6 and code.isdigit()


def test_code_is_stable_within_a_window():
    secret = totp.generate_secret()
    assert totp.generate_code(secret, ALIGNED) == totp.generate_code(secret, ALIGNED + 29)


def test_code_changes_between_windows():
    secret = totp.generate_secret()
    assert totp.generate_code(secret, ALIGNED) != totp.generate_code(secret, ALIGNED + 30)


def test_verify_accepts_current_and_adjacent():
    secret = totp.generate_secret()
    for offset in (-30, 0, 30):
        code = totp.generate_code(secret, ALIGNED + offset)
        assert totp.verify_code(secret, code, ALIGNED)


def test_verify_rejects_distant_and_malformed():
    secret = totp.generate_secret()
    assert not totp.verify_code(secret, totp.generate_code(secret, ALIGNED + 300), ALIGNED)
    assert not totp.verify_code(secret, "12345", ALIGNED)
    assert not totp.verify_code(secret, "abcdef", ALIGNED)
    assert not totp.verify_code(secret, "", ALIGNED)


# ---- login flow ----

def test_full_login(conn, account):
    token = auth.start_login(conn, "maimuna", "hunter2")
    code = totp.generate_code(auth.get_totp_secret(conn, account))
    assert auth.complete_login(conn, token, code)
    assert auth.current_user(conn, token)["user_id"] == account


def test_session_unusable_before_second_factor(conn, account):
    """The core two-step requirement: password alone grants nothing."""
    token = auth.start_login(conn, "maimuna", "hunter2")
    assert auth.current_user(conn, token) is None


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


def test_logout_revokes(conn, account):
    token = auth.start_login(conn, "maimuna", "hunter2")
    auth.complete_login(conn, token, totp.generate_code(auth.get_totp_secret(conn, account)))
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