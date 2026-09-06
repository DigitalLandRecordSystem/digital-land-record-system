"""End-to-end encrypted transfer messages."""
import pytest

from app.crypto import messaging_key as mk
from app.services import deed_service as ds
from app.services import message_service as ms
from app.services import transfer_service as ts
from app.services import user_service as us


def _user(conn, name, role=us.ROLE_OWNER):
    uid = us.register_user(conn, name, f"{name}@example.com", f"pw-{name}",
                           role=role)
    return conn.execute("SELECT * FROM users WHERE user_id = ?",
                        (uid,)).fetchone()


@pytest.fixture
def parties(conn):
    alice = _user(conn, "alice")
    bob = _user(conn, "bob")
    admin = _user(conn, "root", role=us.ROLE_ADMIN)
    deed = ds.create_deed(conn, alice["user_id"], "PLOT-1", "Dhaka", "2.5",
                          "some land")
    return alice, bob, admin, deed


# ---- key derivation ----

def test_derivation_is_deterministic():
    salt = mk.new_salt()
    assert mk.derive_private("hunter2", salt, 100) == \
           mk.derive_private("hunter2", salt, 100)


def test_different_password_gives_different_key():
    salt = mk.new_salt()
    assert mk.derive_private("hunter2", salt, 100) != \
           mk.derive_private("hunter3", salt, 100)


def test_registration_creates_a_messaging_key(conn):
    uid = us.register_user(conn, "maimuna", "m@example.com", "hunter2")
    row = conn.execute("SELECT * FROM messaging_keys WHERE user_id = ?",
                       (uid,)).fetchone()
    assert row is not None and row["public_key"]


def test_private_scalar_appears_nowhere_in_the_database(conn):
    """The claim that makes this end-to-end: the scalar is not stored at all."""
    uid = us.register_user(conn, "maimuna", "m@example.com", "hunter2")
    row = conn.execute("SELECT salt, iterations FROM messaging_keys "
                       "WHERE user_id = ?", (uid,)).fetchone()
    scalar = mk.derive_private("hunter2", row["salt"], row["iterations"])["d"]

    dump = ""
    for (table,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"):
        for record in conn.execute(f"SELECT * FROM {table}"):
            dump += " ".join("" if v is None else str(v) for v in tuple(record))

    assert str(scalar) not in dump
    assert format(scalar, "x") not in dump


# ---- messages ----

def test_recipient_can_read(conn, parties):
    alice, bob, _, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob",
                              message="the boundary wall is mine")
    assert ts.read_message(conn, req, bob, "pw-bob") == \
           "the boundary wall is mine"


def test_sender_can_read_their_own_copy(conn, parties):
    alice, _, _, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob", message="keep the well")
    assert ts.read_message(conn, req, alice, "pw-alice") == "keep the well"


def test_wrong_password_is_rejected(conn, parties):
    alice, bob, _, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob", message="private")
    with pytest.raises(ms.MessageError):
        ts.read_message(conn, req, bob, "not-bobs-password")


def test_administrator_cannot_read(conn, parties):
    """RBAC with teeth: the admin has no key for either copy."""
    alice, _, admin, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob", message="private")
    with pytest.raises(ts.AccessDenied):
        ts.read_message(conn, req, admin, "pw-root")


def test_message_not_stored_in_plaintext(conn, parties):
    alice, _, _, deed = parties
    ts.request_transfer(conn, deed, alice, "bob", message="the well is shared")
    row = conn.execute("SELECT * FROM transfer_requests").fetchone()
    assert "the well is shared" not in str(row["message_to_enc"])
    assert "the well is shared" not in str(row["message_from_enc"])


def test_tampered_message_is_detected(conn, parties):
    alice, bob, _, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob", message="original")
    conn.execute("UPDATE transfer_requests SET message_to_enc = ? "
                 "WHERE request_id = ?", ("AAAA", req))
    conn.commit()
    with pytest.raises(ts.TransferError):
        ts.read_message(conn, req, bob, "pw-bob")


def test_message_is_optional(conn, parties):
    alice, bob, _, deed = parties
    req = ts.request_transfer(conn, deed, alice, "bob")
    with pytest.raises(ts.TransferError):
        ts.read_message(conn, req, bob, "pw-bob")


def test_overlong_message_rejected(conn, parties):
    alice, _, _, deed = parties
    with pytest.raises(ts.TransferError):
        ts.request_transfer(conn, deed, alice, "bob",
                            message="x" * (ms.MAX_LENGTH + 1))