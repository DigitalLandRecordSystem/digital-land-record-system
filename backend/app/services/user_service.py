"""User registration and retrieval, with field-level encryption."""
import base64
import uuid
from datetime import datetime, timezone

from app.config import KDF_ITERATIONS
from app.crypto import key_manager as km
from app.crypto import rsa_service
from app.crypto.blind_index import blind_index
from app.crypto.integrity import compute_tag, verify_tag
from app.crypto.kdf import hash_password, verify_password
from app.services import message_service

ROLE_ADMIN = "ADMIN"
ROLE_OWNER = "OWNER"


class RegistrationError(Exception):
    pass


def _encrypt_field(value: str, public_key) -> str:
    """Encrypt a field and base64-encode it for text storage."""
    if not value:
        return None
    return base64.b64encode(rsa_service.encrypt(value, public_key)).decode()


def _decrypt_field(stored: str, private_key) -> str:
    if stored is None:
        return None
    return rsa_service.decrypt(base64.b64decode(stored), private_key).decode("utf-8")


def register_user(conn, username: str, email: str, password: str,
                  contact: str = None, role: str = ROLE_OWNER) -> str:
    """Register a user. Returns the new user_id.

    All personal fields are encrypted under the user's own RSA public key
    before storage; the password is salted and hashed; and both keypairs
    are issued and stored wrapped.
    """
    username_idx = blind_index(username)
    email_idx = blind_index(email)

    existing = conn.execute(
        "SELECT 1 FROM users WHERE username_idx = ? OR email_idx = ?",
        (username_idx, email_idx),
    ).fetchone()
    if existing:
        raise RegistrationError("username or email is already registered")

    user_id = str(uuid.uuid4())

    # Generate both keypairs before inserting, so the user's own public
    # key can encrypt the row that the keys will then reference.
    rsa_public, rsa_private = km.new_keypair(km.RSA)
    ecc_public, ecc_private = km.new_keypair(km.ECC)

    username_enc = _encrypt_field(username, rsa_public)
    email_enc    = _encrypt_field(email, rsa_public)
    contact_enc  = _encrypt_field(contact, rsa_public) if contact else None

    password_hash, password_salt, iterations = hash_password(password, KDF_ITERATIONS)

    tag = compute_tag(username_enc, email_enc, contact_enc, role)

    conn.execute(
        """INSERT INTO users
           (user_id, username_idx, username_enc, email_idx, email_enc,
            contact_enc, password_hash, password_salt, kdf_iterations,
            role, key_version, hmac_tag, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
        (user_id, username_idx, username_enc, email_idx, email_enc,
         contact_enc, password_hash, password_salt, iterations,
         role, tag, datetime.now(timezone.utc).isoformat()),
    )

    km.store_key(conn, user_id, km.RSA, rsa_public, rsa_private)
    km.store_key(conn, user_id, km.ECC, ecc_public, ecc_private)
    message_service.create_for_user(conn, user_id, password, iterations)
    conn.commit()

    return user_id


def find_by_username(conn, username: str):
    """Look up a user row by blind index. Returns None if absent."""
    return conn.execute(
        "SELECT * FROM users WHERE username_idx = ?", (blind_index(username),)
    ).fetchone()


def get_user_details(conn, user_id: str) -> dict:
    """Decrypt and return a user's personal fields."""
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise LookupError("no such user")

    _, private = km.get_key_version(conn, user_id, km.RSA, row["key_version"])
    return {
        "user_id": row["user_id"],
        "username": _decrypt_field(row["username_enc"], private),
        "email": _decrypt_field(row["email_enc"], private),
        "contact": _decrypt_field(row["contact_enc"], private),
        "role": row["role"],
        "created_at": row["created_at"],
    }

def verify_user_integrity(conn, user_id: str) -> bool:
    """Check that a user row has not been modified in the database."""
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise LookupError("no such user")
    return verify_tag(row["hmac_tag"], row["username_enc"],
                      row["email_enc"], row["contact_enc"], row["role"])


def reencrypt_account(conn, user_id: str) -> None:
    """Re-encrypt account fields under the user's active RSA key.

    Blind indexes are unaffected: they are HMACs under a separate key, not
    RSA ciphertexts, so lookup keeps working across a rotation.
    """
    row = conn.execute("SELECT * FROM users WHERE user_id = ?",
                       (user_id,)).fetchone()
    if row is None:
        raise LookupError("no such user")

    _, old_private = km.get_key_version(conn, user_id, km.RSA, row["key_version"])
    username = _decrypt_field(row["username_enc"], old_private)
    email = _decrypt_field(row["email_enc"], old_private)
    contact = _decrypt_field(row["contact_enc"], old_private)

    public, version = km.get_public_key(conn, user_id, km.RSA)
    username_enc = _encrypt_field(username, public)
    email_enc = _encrypt_field(email, public)
    contact_enc = _encrypt_field(contact, public)
    tag = compute_tag(username_enc, email_enc, contact_enc, row["role"])

    conn.execute(
        """UPDATE users SET username_enc = ?, email_enc = ?, contact_enc = ?,
                key_version = ?, hmac_tag = ?
           WHERE user_id = ?""",
        (username_enc, email_enc, contact_enc, version, tag, user_id),
    )
    conn.commit()