"""Deeds, profiles, transfers, and behaviour across key rotation."""
import pytest

from app.crypto import key_manager as km
from app.crypto import totp
from app.services import auth_service as auth
from app.services import deed_service as ds
from app.services import profile_service as ps
from app.services import transfer_service as ts
from app.services import user_service as us


def _make_user(conn, name, role=us.ROLE_OWNER):
    uid = us.register_user(conn, name, f"{name}@example.com", "hunter2",
                           role=role)
    return conn.execute("SELECT * FROM users WHERE user_id = ?",
                        (uid,)).fetchone()


@pytest.fixture
def owner(conn):
    return _make_user(conn, "alice")


@pytest.fixture
def other(conn):
    return _make_user(conn, "bob")


@pytest.fixture
def admin(conn):
    return _make_user(conn, "root", role=us.ROLE_ADMIN)


@pytest.fixture
def deed(conn, owner):
    return ds.create_deed(conn, owner["user_id"], "PLOT-1", "Dhaka", "5.25",
                          "Boundary: north road, south canal.")


# ---- deeds ----

def test_deed_round_trip(conn, owner, deed):
    got = ds.get_deed(conn, deed, owner)
    assert got["plot_no"] == "PLOT-1"
    assert got["content"] == "Boundary: north road, south canal."


def test_deed_stored_encrypted(conn, deed):
    row = conn.execute("SELECT * FROM deeds WHERE deed_id = ?", (deed,)).fetchone()
    for column in ("plot_no_enc", "district_enc", "area_enc", "content_enc"):
        assert "Dhaka" not in row[column]
        assert "PLOT-1" not in row[column]


def test_duplicate_plot_rejected(conn, owner, deed):
    with pytest.raises(ds.DeedError):
        ds.create_deed(conn, owner["user_id"], "PLOT-1", "Khulna", "1.0", "x")


def test_stranger_cannot_view(conn, other, deed):
    with pytest.raises(ds.AccessDenied):
        ds.get_deed(conn, deed, other)


def test_admin_can_view(conn, admin, deed):
    assert ds.get_deed(conn, deed, admin)["plot_no"] == "PLOT-1"


def test_admin_cannot_edit(conn, admin, deed):
    """Administrators approve transfers; they do not edit owners' records."""
    with pytest.raises(ds.AccessDenied):
        ds.update_deed(conn, deed, admin, "Khulna", "9.0", "rewritten")


def test_edit_changes_content(conn, owner, deed):
    ds.update_deed(conn, deed, owner, "Khulna", "9.0", "revised text")
    got = ds.get_deed(conn, deed, owner)
    assert (got["district"], got["area"], got["content"]) == \
           ("Khulna", "9.0", "revised text")


def test_tampered_deed_is_detected(conn, owner, deed):
    row = conn.execute("SELECT district_enc FROM deeds WHERE deed_id = ?",
                       (deed,)).fetchone()
    conn.execute("UPDATE deeds SET district_enc = ? WHERE deed_id = ?",
                 ("X" + row["district_enc"][1:], deed))
    conn.commit()
    assert ds.verify_deed_integrity(conn, deed) is False
    with pytest.raises(ds.IntegrityFailure):
        ds.get_deed(conn, deed, owner)


# ---- profiles ----

def test_profile_absent_initially(conn, owner):
    assert ps.get_profile(conn, owner["user_id"])["exists"] is False


def test_profile_round_trip(conn, owner):
    ps.update_profile(conn, owner["user_id"], full_name="Alice Rahman",
                      address="12 Green Road", phone="01700000000",
                      nid="1234567890")
    got = ps.get_profile(conn, owner["user_id"])
    assert got["full_name"] == "Alice Rahman"
    assert got["nid"] == "1234567890"
    assert got["exists"] is True


def test_profile_stored_encrypted(conn, owner):
    ps.update_profile(conn, owner["user_id"], full_name="Alice Rahman")
    row = conn.execute("SELECT full_name_enc FROM profiles WHERE user_id = ?",
                       (owner["user_id"],)).fetchone()
    assert "Alice" not in row["full_name_enc"]


def test_tampered_profile_is_detected(conn, owner):
    ps.update_profile(conn, owner["user_id"], full_name="Alice Rahman")
    row = conn.execute("SELECT full_name_enc FROM profiles WHERE user_id = ?",
                       (owner["user_id"],)).fetchone()
    conn.execute("UPDATE profiles SET full_name_enc = ? WHERE user_id = ?",
                 ("X" + row["full_name_enc"][1:], owner["user_id"]))
    conn.commit()
    with pytest.raises(ps.IntegrityFailure):
        ps.get_profile(conn, owner["user_id"])


def test_unknown_profile_field_rejected(conn, owner):
    with pytest.raises(ps.ProfileError):
        ps.update_profile(conn, owner["user_id"], salary="secret")


# ---- transfers ----

def test_transfer_moves_ownership_and_reencrypts(conn, owner, other, admin, deed):
    req = ts.request_transfer(conn, deed, owner, "bob")
    ts.approve(conn, req, admin)

    assert ds.get_deed(conn, deed, other)["plot_no"] == "PLOT-1"
    with pytest.raises(ds.AccessDenied):
        ds.get_deed(conn, deed, owner)


def test_only_owner_may_request(conn, other, deed):
    with pytest.raises(ts.AccessDenied):
        ts.request_transfer(conn, deed, other, "bob")


def test_only_admin_may_decide(conn, owner, other, deed):
    req = ts.request_transfer(conn, deed, owner, "bob")
    with pytest.raises(ts.AccessDenied):
        ts.approve(conn, req, other)


def test_unknown_recipient_rejected(conn, owner, deed):
    with pytest.raises(ts.TransferError):
        ts.request_transfer(conn, deed, owner, "nobody")


def test_duplicate_pending_request_rejected(conn, owner, other, deed):
    ts.request_transfer(conn, deed, owner, "bob")
    with pytest.raises(ts.TransferError):
        ts.request_transfer(conn, deed, owner, "bob")


def test_rejection_reason_readable_only_by_requester(conn, owner, other,
                                                     admin, deed):
    req = ts.request_transfer(conn, deed, owner, "bob")
    ts.reject(conn, req, admin, "boundary dispute unresolved")

    mine = ts.list_for_user(conn, owner["user_id"])[0]
    assert mine["reason"] == "boundary dispute unresolved"

    theirs = ts.list_for_user(conn, other["user_id"])[0]
    assert theirs["reason"] is None


def test_decided_request_cannot_be_decided_again(conn, owner, other, admin, deed):
    req = ts.request_transfer(conn, deed, owner, "bob")
    ts.approve(conn, req, admin)
    with pytest.raises(ts.TransferError):
        ts.reject(conn, req, admin, "changed my mind")


def test_forged_approval_is_detected(conn, owner, other, admin, deed):
    """Flipping a decision directly in the database breaks its HMAC."""
    req = ts.request_transfer(conn, deed, owner, "bob")
    ts.reject(conn, req, admin, "not allowed")
    assert ts.verify_decision(conn, req) is True

    conn.execute("UPDATE transfer_requests SET status = 'APPROVED' "
                 "WHERE request_id = ?", (req,))
    conn.commit()
    assert ts.verify_decision(conn, req) is False


# ---- key rotation ----

def test_deed_readable_after_ecc_rotation(conn, owner, deed):
    """A retired key must still decrypt records written under it."""
    km.rotate_key(conn, owner["user_id"], km.ECC)
    got = ds.get_deed(conn, deed, owner)
    assert got["plot_no"] == "PLOT-1"
    assert got["key_version"] == 1


def test_account_readable_after_rsa_rotation(conn, owner):
    """Regression: account fields were decrypted with the active key, not
    the version that wrote them, which broke every rotated account."""
    km.rotate_key(conn, owner["user_id"], km.RSA)
    assert us.get_user_details(conn, owner["user_id"])["username"] == "alice"


def test_login_survives_rsa_rotation(conn, owner):
    """Regression: the TOTP secret became unreadable after rotation, which
    locked the user out of their own account."""
    km.rotate_key(conn, owner["user_id"], km.RSA)
    pending = auth.start_login(conn, "alice", "hunter2")
    code = totp.generate_code(auth.get_totp_secret(conn, owner["user_id"]))
    token = auth.complete_login(conn, pending, code)
    assert auth.current_user(conn, token)["user_id"] == owner["user_id"]


def test_migration_moves_records_forward(conn, owner, deed):
    km.rotate_key(conn, owner["user_id"], km.RSA)
    km.rotate_key(conn, owner["user_id"], km.ECC)
    us.reencrypt_account(conn, owner["user_id"])
    ds.reencrypt_owned(conn, owner["user_id"])

    assert ds.get_deed(conn, deed, owner)["key_version"] == 2
    assert us.get_user_details(conn, owner["user_id"])["username"] == "alice"


def test_profile_readable_after_rotation_and_migration(conn, owner):
    ps.update_profile(conn, owner["user_id"], full_name="Alice Rahman")
    km.rotate_key(conn, owner["user_id"], km.RSA)
    assert ps.get_profile(conn, owner["user_id"])["full_name"] == "Alice Rahman"

    ps.reencrypt(conn, owner["user_id"])
    got = ps.get_profile(conn, owner["user_id"])
    assert got["full_name"] == "Alice Rahman"
    assert got["key_version"] == 2


# ---- key integrity and distribution ----

def test_substituted_public_key_is_detected(conn, owner):
    """A public key swapped directly in the database breaks its HMAC."""
    key = km.list_keys(conn, owner["user_id"])[0]
    assert key["intact"] is True

    conn.execute("UPDATE user_keys SET public_key = ? WHERE key_id = ?",
                 ('{"n": 1, "e": 65537}', key["key_id"]))
    conn.commit()

    assert km.verify_key_integrity(conn, key["key_id"]) is False
    with pytest.raises(km.KeyIntegrityError):
        km.get_active_key(conn, owner["user_id"], key["algorithm"])


def test_distribution_returns_public_key_only(conn, owner):
    public, version = km.get_public_key(conn, owner["user_id"], km.RSA)
    assert version == 1
    assert "d" not in public and "p" not in public and "q" not in public


def test_directory_lists_active_keys(conn, owner, other):
    entries = km.public_directory(conn)
    users = {e["user_id"] for e in entries}
    assert owner["user_id"] in users and other["user_id"] in users
    assert all(len(e["fingerprint"]) == 16 for e in entries)