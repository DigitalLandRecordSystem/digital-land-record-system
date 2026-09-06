"""Ownership transfer: owners request, administrators decide.

An approved transfer re-encrypts the deed under the new owner's ECC key,
so the previous owner's key can no longer read it. Every decision carries
an HMAC over its own fields, so an approval cannot be forged or altered in
the database.
"""
import base64
import uuid
from datetime import datetime, timezone

from app.crypto import key_manager as km
from app.crypto import rsa_service
from app.crypto.integrity import compute_tag, verify_tag
from app.services import deed_service as ds
from app.services import user_service as us
from app.services import message_service as ms

PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"


class TransferError(Exception):
    pass


class AccessDenied(TransferError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decision_tag(row) -> str:
    """HMAC covering a decision, so approvals cannot be forged in storage."""
    return compute_tag(row["request_id"], row["deed_id"], row["from_user_id"],
                       row["to_user_id"], row["status"],
                       row["decided_on"], row["decided_by"])


# ---------- requesting ----------

def request_transfer(conn, deed_id: str, requester, to_username: str,
                     message: str = None) -> str:
    """An owner asks to transfer a deed to another registered user.

    An optional message is encrypted under the recipient's messaging key,
    with a second copy under the sender's own. The server can read neither.
    """
    deed = conn.execute("SELECT * FROM deeds WHERE deed_id = ?",
                        (deed_id,)).fetchone()
    if deed is None:
        raise LookupError("no such deed")
    if deed["owner_id"] != requester["user_id"]:
        raise AccessDenied("only the owner may request a transfer")

    recipient = us.find_by_username(conn, to_username)
    if recipient is None:
        raise TransferError("no registered user with that username")
    if recipient["user_id"] == requester["user_id"]:
        raise TransferError("a deed cannot be transferred to its current owner")

    if conn.execute(
        "SELECT 1 FROM transfer_requests WHERE deed_id = ? AND status = ?",
        (deed_id, PENDING)).fetchone():
        raise TransferError("a transfer for this deed is already pending")

    _, version = km.get_public_key(conn, requester["user_id"], km.RSA)
    request_id = str(uuid.uuid4())

    to_enc = from_enc = tag = None
    if message:
        if len(message) > ms.MAX_LENGTH:
            raise TransferError(
                f"a message may be at most {ms.MAX_LENGTH} characters")
        to_enc = ms.encrypt_for(conn, recipient["user_id"], message)
        from_enc = ms.encrypt_for(conn, requester["user_id"], message)
        tag = compute_tag(request_id, to_enc, from_enc)

    conn.execute(
        """INSERT INTO transfer_requests
           (request_id, deed_id, from_user_id, to_user_id, status,
            requested_on, key_version, message_to_enc, message_from_enc,
            message_hmac)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (request_id, deed_id, requester["user_id"], recipient["user_id"],
         PENDING, _now(), version, to_enc, from_enc, tag),
    )
    conn.commit()
    return request_id


# ---------- deciding ----------

def _fetch(conn, request_id: str):
    row = conn.execute("SELECT * FROM transfer_requests WHERE request_id = ?",
                       (request_id,)).fetchone()
    if row is None:
        raise LookupError("no such transfer request")
    return row


def approve(conn, request_id: str, admin) -> None:
    """Approve a transfer and re-encrypt the deed under the new owner's key."""
    if admin["role"] != us.ROLE_ADMIN:
        raise AccessDenied("only an administrator may decide a transfer")

    row = _fetch(conn, request_id)
    if row["status"] != PENDING:
        raise TransferError(f"this request was already {row['status'].lower()}")

    ds.change_owner(conn, row["deed_id"], row["to_user_id"])
    _record(conn, row, APPROVED, admin, reason=None)


def reject(conn, request_id: str, admin, reason: str) -> None:
    """Reject a transfer, storing the reason encrypted for the requester."""
    if admin["role"] != us.ROLE_ADMIN:
        raise AccessDenied("only an administrator may decide a transfer")
    if not reason:
        raise TransferError("a reason is required when rejecting a transfer")

    row = _fetch(conn, request_id)
    if row["status"] != PENDING:
        raise TransferError(f"this request was already {row['status'].lower()}")

    _record(conn, row, REJECTED, admin, reason)


def _record(conn, row, status: str, admin, reason) -> None:
    """Write the decision, its encrypted reason, and its HMAC."""
    decided_on = _now()
    reason_enc = None
    key_version = row["key_version"]
    if reason:
        # Encrypted under the requester's key, so only they can read it.
        public, key_version = km.get_public_key(conn, row["from_user_id"], km.RSA)
        reason_enc = base64.b64encode(
            rsa_service.encrypt(reason, public)).decode()

    decision = {"request_id": row["request_id"], "deed_id": row["deed_id"],
                "from_user_id": row["from_user_id"],
                "to_user_id": row["to_user_id"], "status": status,
                "decided_on": decided_on, "decided_by": admin["user_id"]}

    conn.execute(
        """UPDATE transfer_requests
           SET status = ?, reason_enc = ?, decided_on = ?, decided_by = ?,
               approval_hmac = ?, key_version = ?
           WHERE request_id = ?""",
        (status, reason_enc, decided_on, admin["user_id"],
         _decision_tag(decision), key_version, row["request_id"]),
    )
    conn.commit()


def verify_decision(conn, request_id: str) -> bool:
    """Check that a recorded decision has not been altered in the database."""
    row = _fetch(conn, request_id)
    if row["status"] == PENDING:
        return True
    return verify_tag(row["approval_hmac"], row["request_id"], row["deed_id"],
                      row["from_user_id"], row["to_user_id"], row["status"],
                      row["decided_on"], row["decided_by"])


def read_message(conn, request_id: str, viewer, password: str) -> str:
    """Decrypt a transfer message for one of its two parties.

    RBAC lives here rather than in the template: an administrator is not
    merely prevented from seeing the plaintext, they have no path to it.
    Their account holds no scalar that decrypts either copy.
    """
    row = _fetch(conn, request_id)

    if viewer["user_id"] == row["to_user_id"]:
        ciphertext = row["message_to_enc"]
    elif viewer["user_id"] == row["from_user_id"]:
        ciphertext = row["message_from_enc"]
    else:
        raise AccessDenied(
            "only the parties to this transfer may read its message")

    if ciphertext is None:
        raise TransferError("this request carries no message")

    if not verify_tag(row["message_hmac"], row["request_id"],
                      row["message_to_enc"], row["message_from_enc"]):
        raise TransferError("this message failed its integrity check")

    return ms.decrypt_with_password(conn, viewer["user_id"], ciphertext,
                                    password)


# ---------- listing ----------

def _decorate(conn, rows, viewer_id=None) -> list:
    out = []
    for row in rows:
        entry = dict(row)
        entry["intact"] = verify_decision(conn, row["request_id"])
        entry["from_username"] = us.get_user_details(
            conn, row["from_user_id"])["username"]
        entry["to_username"] = us.get_user_details(
            conn, row["to_user_id"])["username"]
        entry["plot_no"] = ds.plot_number(conn, row["deed_id"])
        entry["reason"] = None
        if row["reason_enc"] and viewer_id == row["from_user_id"]:
            _, private = km.get_key_version(conn, row["from_user_id"],
                                            km.RSA, row["key_version"])
            entry["reason"] = rsa_service.decrypt(
                base64.b64decode(row["reason_enc"]), private).decode("utf-8")

        entry["has_message"] = row["message_to_enc"] is not None
        entry["message_intact"] = row["message_hmac"] is None or verify_tag(
            row["message_hmac"], row["request_id"],
            row["message_to_enc"], row["message_from_enc"])
        out.append(entry)
    return out


def list_for_user(conn, user_id: str) -> list:
    """Transfers this user sent or received."""
    rows = conn.execute(
        """SELECT * FROM transfer_requests
           WHERE from_user_id = ? OR to_user_id = ?
           ORDER BY requested_on DESC""", (user_id, user_id)).fetchall()
    return _decorate(conn, rows, viewer_id=user_id)


def list_pending(conn) -> list:
    """The administrator's decision queue."""
    rows = conn.execute(
        "SELECT * FROM transfer_requests WHERE status = ? ORDER BY requested_on",
        (PENDING,)).fetchall()
    return _decorate(conn, rows)