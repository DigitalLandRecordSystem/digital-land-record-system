"""Deed records: create, view, edit, transfer ownership.

Deed fields are encrypted under the owner's ECC public key using
EC-ElGamal. Each row carries an HMAC tag over its ciphertexts and owner,
so any modification made directly in the database is detected on read.
The plot number is additionally stored as a blind index so that duplicate
registrations can be rejected without holding the value in plaintext.
"""
import base64
import uuid
from datetime import datetime, timezone

from app.crypto import ecc_service
from app.crypto import key_manager as km
from app.crypto.blind_index import blind_index
from app.crypto.integrity import compute_tag, verify_tag

ROLE_ADMIN = "ADMIN"


class DeedError(Exception):
    pass


class AccessDenied(DeedError):
    pass


class IntegrityFailure(DeedError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt(value: str, public_key) -> str:
    """Encrypt a field with ECC and base64-encode it for text storage."""
    return base64.b64encode(ecc_service.encrypt(str(value), public_key)).decode()


def _decrypt(stored: str, private_key) -> str:
    return ecc_service.decrypt(base64.b64decode(stored), private_key).decode("utf-8")


def _tag_of(row) -> str:
    """The HMAC tag covering a deed's ciphertexts and its owner."""
    return compute_tag(row["plot_no_enc"], row["district_enc"],
                       row["area_enc"], row["content_enc"], row["owner_id"])


def _fetch(conn, deed_id: str):
    row = conn.execute("SELECT * FROM deeds WHERE deed_id = ?", (deed_id,)).fetchone()
    if row is None:
        raise LookupError("no such deed")
    return row


def _check_integrity(row) -> None:
    if not verify_tag(row["hmac_tag"], row["plot_no_enc"], row["district_enc"],
                      row["area_enc"], row["content_enc"], row["owner_id"]):
        raise IntegrityFailure(
            "integrity check failed: this record has been modified in storage")


def can_view(row, user) -> bool:
    """Owners see their own deeds; administrators see all."""
    return user["role"] == ROLE_ADMIN or row["owner_id"] == user["user_id"]


# ---------- create ----------

def create_deed(conn, owner_id: str, plot_no: str, district: str,
                area: str, content: str) -> str:
    """Create a deed owned by owner_id. Returns the new deed_id."""
    if not (plot_no and district and area and content):
        raise DeedError("all deed fields are required")

    plot_idx = blind_index(plot_no)
    if conn.execute("SELECT 1 FROM deeds WHERE plot_no_idx = ?",
                    (plot_idx,)).fetchone():
        raise DeedError("a deed for that plot number already exists")

    public, _, version = km.get_active_key(conn, owner_id, km.ECC)

    plot_enc     = _encrypt(plot_no, public)
    district_enc = _encrypt(district, public)
    area_enc     = _encrypt(area, public)
    content_enc  = _encrypt(content, public)

    deed_id = str(uuid.uuid4())
    tag = compute_tag(plot_enc, district_enc, area_enc, content_enc, owner_id)
    now = _now()

    conn.execute(
        """INSERT INTO deeds
           (deed_id, plot_no_idx, plot_no_enc, district_enc, area_enc,
            content_enc, owner_id, key_version, hmac_tag, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (deed_id, plot_idx, plot_enc, district_enc, area_enc, content_enc,
         owner_id, version, tag, now, now),
    )
    conn.commit()
    return deed_id


# ---------- read ----------

def get_deed(conn, deed_id: str, user) -> dict:
    """Decrypt and return a deed. Raises if the caller may not see it."""
    row = _fetch(conn, deed_id)
    if not can_view(row, user):
        raise AccessDenied("you do not have access to this deed")
    _check_integrity(row)

    # Decrypt under the key version this row was written with, which may be
    # older than the owner's current key.
    _, private = km.get_key_version(conn, row["owner_id"], km.ECC, row["key_version"])

    return {
        "deed_id": row["deed_id"],
        "plot_no": _decrypt(row["plot_no_enc"], private),
        "district": _decrypt(row["district_enc"], private),
        "area": _decrypt(row["area_enc"], private),
        "content": _decrypt(row["content_enc"], private),
        "owner_id": row["owner_id"],
        "key_version": row["key_version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_deeds(conn, user) -> list:
    """Summaries of the deeds this user may see, newest first.

    Integrity is reported rather than raised, so a tampered row still
    appears in the list and is visibly flagged.
    """
    if user["role"] == ROLE_ADMIN:
        rows = conn.execute(
            "SELECT * FROM deeds ORDER BY updated_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM deeds WHERE owner_id = ? ORDER BY updated_at DESC",
            (user["user_id"],)).fetchall()

    summaries = []
    for row in rows:
        intact = verify_tag(row["hmac_tag"], row["plot_no_enc"],
                            row["district_enc"], row["area_enc"],
                            row["content_enc"], row["owner_id"])
        entry = {
            "deed_id": row["deed_id"],
            "owner_id": row["owner_id"],
            "key_version": row["key_version"],
            "updated_at": row["updated_at"],
            "intact": intact,
            "plot_no": None,
            "district": None,
        }
        if intact:
            _, private = km.get_key_version(conn, row["owner_id"],
                                            km.ECC, row["key_version"])
            entry["plot_no"] = _decrypt(row["plot_no_enc"], private)
            entry["district"] = _decrypt(row["district_enc"], private)
        summaries.append(entry)
    return summaries


def verify_deed_integrity(conn, deed_id: str) -> bool:
    """Public integrity check, used by the tamper demonstration."""
    row = _fetch(conn, deed_id)
    return verify_tag(row["hmac_tag"], row["plot_no_enc"], row["district_enc"],
                      row["area_enc"], row["content_enc"], row["owner_id"])


# ---------- update ----------

def update_deed(conn, deed_id: str, user, district: str,
                area: str, content: str) -> None:
    """Edit a deed. Only the owner may edit; the plot number is immutable.

    Re-encrypts under the owner's currently active key, so an edit after a
    key rotation migrates the record forward.
    """
    row = _fetch(conn, deed_id)
    if row["owner_id"] != user["user_id"]:
        raise AccessDenied("only the owner may edit a deed")
    _check_integrity(row)

    if not (district and area and content):
        raise DeedError("all deed fields are required")

    public, _, version = km.get_active_key(conn, row["owner_id"], km.ECC)

    # The plot number is re-encrypted too, so the whole row shares one key
    # version. Its value is unchanged; only the ciphertext is fresh.
    _, old_private = km.get_key_version(conn, row["owner_id"],
                                        km.ECC, row["key_version"])
    plot_no = _decrypt(row["plot_no_enc"], old_private)

    plot_enc     = _encrypt(plot_no, public)
    district_enc = _encrypt(district, public)
    area_enc     = _encrypt(area, public)
    content_enc  = _encrypt(content, public)
    tag = compute_tag(plot_enc, district_enc, area_enc, content_enc,
                      row["owner_id"])

    conn.execute(
        """UPDATE deeds SET plot_no_enc = ?, district_enc = ?, area_enc = ?,
               content_enc = ?, key_version = ?, hmac_tag = ?, updated_at = ?
           WHERE deed_id = ?""",
        (plot_enc, district_enc, area_enc, content_enc, version, tag,
         _now(), deed_id),
    )
    conn.commit()


# ---------- ownership ----------

def change_owner(conn, deed_id: str, new_owner_id: str) -> None:
    """Re-encrypt a deed under the new owner's key and reassign it.

    Called by the transfer workflow after an administrator approves. The
    deed is decrypted with the old owner's key and re-encrypted with the
    new owner's, so the previous owner's key can no longer read it.
    """
    row = _fetch(conn, deed_id)
    _check_integrity(row)

    _, old_private = km.get_key_version(conn, row["owner_id"],
                                        km.ECC, row["key_version"])
    fields = [_decrypt(row[col], old_private) for col in
              ("plot_no_enc", "district_enc", "area_enc", "content_enc")]

    public, _, version = km.get_active_key(conn, new_owner_id, km.ECC)
    plot_enc, district_enc, area_enc, content_enc = [
        _encrypt(value, public) for value in fields]
    tag = compute_tag(plot_enc, district_enc, area_enc, content_enc,
                      new_owner_id)

    conn.execute(
        """UPDATE deeds SET plot_no_enc = ?, district_enc = ?, area_enc = ?,
               content_enc = ?, owner_id = ?, key_version = ?, hmac_tag = ?,
               updated_at = ?
           WHERE deed_id = ?""",
        (plot_enc, district_enc, area_enc, content_enc, new_owner_id,
         version, tag, _now(), deed_id),
    )
    conn.commit()


def plot_number(conn, deed_id: str) -> str:
    """The decrypted plot number for a deed, for display in related records."""
    row = _fetch(conn, deed_id)
    _, private = km.get_key_version(conn, row["owner_id"], km.ECC, row["key_version"])
    return _decrypt(row["plot_no_enc"], private)