"""Tests for user registration, encrypted storage, and row integrity."""
import pytest

from app.services import user_service as us
from app.crypto import key_manager as km


def test_register_and_retrieve(conn):
    uid = us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2",
                           contact="01700000000")
    details = us.get_user_details(conn, uid)

    assert details["username"] == "maimuna"
    assert details["email"] == "maimuna@example.com"
    assert details["contact"] == "01700000000"
    assert details["role"] == us.ROLE_OWNER


def test_registration_without_contact(conn):
    uid = us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2")
    assert us.get_user_details(conn, uid)["contact"] is None


def test_personal_data_is_not_plaintext_in_db(conn):
    """Requirement: critical data must not be readable if the DB is stolen."""
    us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2",
                     contact="01700000000")
    row = conn.execute("SELECT * FROM users").fetchone()

    for column in ("username_enc", "email_enc", "contact_enc"):
        assert "maimuna" not in row[column]
        assert "01700000000" not in row[column]

    # the password is hashed, never stored or encrypted
    assert "hunter2" not in row["password_hash"]
    assert "hunter2" not in row["password_salt"]


def test_private_keys_not_plaintext_in_db(conn):
    """Private key material must be wrapped before storage."""
    uid = us.register_user(conn, "maimuna", "maimuna@example.com", "hunter2")
    _, rsa_private, _ = km.get_active_key(conn, uid, km.RSA)

    row = conn.execute(
        "SELECT private_key_enc FROM user_keys WHERE user_id = ? AND algorithm = ?",
        (uid, km.RSA),
    ).fetchone()
    assert str(rsa_private["d"]) not in row["private_key_enc"]


def test_duplicate_username_rejected(conn):
    us.register_user(conn, "maimuna", "a@example.com", "pw1")
    with pytest.raises(us.RegistrationError):
        us.register_user(conn, "maimuna", "b@example.com", "pw2")


def test_duplicate_email_rejected(conn):
    us.register_user(conn, "maimuna", "shared@example.com", "pw1")
    with pytest.raises(us.RegistrationError):
        us.register_user(conn, "rahim", "shared@example.com", "pw2")


def test_lookup_is_case_insensitive(conn):
    uid = us.register_user(conn, "Maimuna", "Maimuna@Example.com", "pw1")
    assert us.find_by_username(conn, "maimuna")["user_id"] == uid
    assert us.find_by_username(conn, "MAIMUNA")["user_id"] == uid


def test_lookup_missing_user_returns_none(conn):
    assert us.find_by_username(conn, "nobody") is None


def test_blind_index_is_not_the_username(conn):
    """The lookup token must not reveal the value it indexes."""
    us.register_user(conn, "maimuna", "a@example.com", "pw1")
    row = conn.execute("SELECT username_idx FROM users").fetchone()
    assert "maimuna" not in row["username_idx"]
    assert len(row["username_idx"]) == 64        # SHA-256 hex


def test_keys_issued_on_registration(conn):
    uid = us.register_user(conn, "maimuna", "a@example.com", "pw1")
    for algorithm in (km.RSA, km.ECC):
        _, _, version = km.get_active_key(conn, uid, algorithm)
        assert version == 1


def test_admin_role_can_be_assigned(conn):
    uid = us.register_user(conn, "admin", "admin@example.com", "pw1",
                           role=us.ROLE_ADMIN)
    assert us.get_user_details(conn, uid)["role"] == us.ROLE_ADMIN


def test_integrity_passes_for_untouched_row(conn):
    uid = us.register_user(conn, "maimuna", "a@example.com", "pw1")
    assert us.verify_user_integrity(conn, uid)


def test_integrity_detects_role_tampering(conn):
    """Privilege escalation attempted directly against the database."""
    uid = us.register_user(conn, "maimuna", "a@example.com", "pw1",
                           role=us.ROLE_OWNER)
    assert us.verify_user_integrity(conn, uid)

    conn.execute("UPDATE users SET role = 'ADMIN' WHERE user_id = ?", (uid,))
    conn.commit()

    assert not us.verify_user_integrity(conn, uid)


def test_integrity_detects_ciphertext_tampering(conn):
    """Replacing an encrypted field is detected even without decrypting it."""
    uid = us.register_user(conn, "maimuna", "a@example.com", "pw1")
    other = us.register_user(conn, "rahim", "b@example.com", "pw2")
    stolen = conn.execute(
        "SELECT email_enc FROM users WHERE user_id = ?", (other,)
    ).fetchone()["email_enc"]

    conn.execute("UPDATE users SET email_enc = ? WHERE user_id = ?", (stolen, uid))
    conn.commit()

    assert not us.verify_user_integrity(conn, uid)