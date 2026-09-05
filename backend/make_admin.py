"""Promote an existing user to administrator.

Usage:  python make_admin.py <username>

Role is not encrypted (it is not secret, and access control must read it on
every request), but it is covered by the user row's HMAC tag, so the tag is
recomputed here. Changing the role directly with SQL would break integrity
verification for that user.
"""
import sys

from app.crypto.integrity import compute_tag
from app.database.db import get_connection
from app.services import user_service as us


def promote(username: str) -> None:
    conn = get_connection()
    row = us.find_by_username(conn, username)
    if row is None:
        raise SystemExit(f"no such user: {username}")
    if row["role"] == us.ROLE_ADMIN:
        print(f"{username} is already an administrator.")
        return

    tag = compute_tag(row["username_enc"], row["email_enc"],
                      row["contact_enc"], us.ROLE_ADMIN)
    conn.execute("UPDATE users SET role = ?, hmac_tag = ? WHERE user_id = ?",
                 (us.ROLE_ADMIN, tag, row["user_id"]))
    conn.commit()
    print(f"{username} is now an administrator.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python make_admin.py <username>")
    promote(sys.argv[1])