"""End-to-end encrypted messages attached to transfer requests.

A message is encrypted with EC-ElGamal under the recipient's messaging
public key, and a second copy under the sender's own, so both parties can
read it and nobody else can -- not another user, not an administrator, and
not the server, which holds neither private scalar.

A four-byte canary is prepended before encryption. EC-ElGamal with the
wrong scalar returns plausible bytes rather than raising, so without the
canary a wrong password would render as noise instead of being rejected.
The HMAC cannot do this job: it covers the ciphertext, and verifies
correctly no matter who attempts to decrypt.
"""
import base64
from datetime import datetime, timezone

from app.crypto import ecc_service, messaging_key
from app.crypto import key_manager as km

CANARY = b"LRS1"
MAX_LENGTH = 400


class MessageError(Exception):
    pass


def create_for_user(conn, user_id: str, password: str, iterations: int) -> None:
    """Record a user's messaging public key and salt at registration.

    The scalar is derived, used to compute the public point, and dropped.
    """
    salt = messaging_key.new_salt()
    public = messaging_key.derive_public(password, salt, iterations)

    conn.execute(
        """INSERT INTO messaging_keys
           (user_id, public_key, salt, iterations, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, km.serialise_key(public), salt, iterations,
         datetime.now(timezone.utc).isoformat()),
    )


def _key_row(conn, user_id: str):
    row = conn.execute(
        "SELECT * FROM messaging_keys WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        raise MessageError("this user has no messaging key")
    return row


def encrypt_for(conn, user_id: str, text: str) -> str:
    """Encrypt a message under a user's messaging public key."""
    public = km.deserialise_key(_key_row(conn, user_id)["public_key"])
    payload = CANARY + text.encode("utf-8")
    return base64.b64encode(ecc_service.encrypt(payload, public)).decode()


def decrypt_with_password(conn, user_id: str, ciphertext: str,
                          password: str) -> str:
    """Re-derive the scalar from the password, decrypt, and discard it."""
    row = _key_row(conn, user_id)
    private = messaging_key.derive_private(password, row["salt"],
                                           row["iterations"])
    
    # A wrong scalar yields a garbage point. Depending on the bytes, that
    # surfaces as an OverflowError from the decoder, or as plaintext that
    # fails the canary, or as invalid UTF-8. All three mean the same thing.
    try:
        plaintext = ecc_service.decrypt(base64.b64decode(ciphertext), private)
    except (OverflowError, ValueError):
        raise MessageError("incorrect password") from None

    if not plaintext.startswith(CANARY):
        raise MessageError("incorrect password")

    try:
        return plaintext[len(CANARY):].decode("utf-8")
    except UnicodeDecodeError:
        raise MessageError("incorrect password") from None