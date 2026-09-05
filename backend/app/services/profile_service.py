"""User profiles: view and update, with RSA-encrypted fields.

Profile fields are encrypted under the user's own RSA public key and
covered by an HMAC tag, so modification in storage is detected on read.
Deed content uses ECC; profile and account data use RSA.
"""
import base64
import uuid
from datetime import datetime, timezone

from app.crypto import key_manager as km
from app.crypto import rsa_service
from app.crypto.integrity import compute_tag, verify_tag

FIELDS = ("full_name", "address", "phone", "nid")


class ProfileError(Exception):
    pass


class IntegrityFailure(ProfileError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt(value, public_key):
    if not value:
        return None
    return base64.b64encode(rsa_service.encrypt(str(value), public_key)).decode()


def _decrypt(stored, private_key):
    if stored is None:
        return None
    return rsa_service.decrypt(base64.b64decode(stored), private_key).decode("utf-8")


def _tag(row_or_values, user_id: str) -> str:
    """HMAC over the four ciphertexts and the owning user."""
    return compute_tag(*(row_or_values[f"{f}_enc"] for f in FIELDS), user_id)


def _fetch(conn, user_id: str):
    return conn.execute(
        "SELECT * FROM profiles WHERE user_id = ?", (user_id,)).fetchone()


def get_profile(conn, user_id: str) -> dict:
    """Decrypt and return a profile. Returns empty fields if none exists yet."""
    row = _fetch(conn, user_id)
    if row is None:
        return {f: None for f in FIELDS} | {"exists": False, "key_version": None,
                                            "updated_at": None}

    if not verify_tag(row["hmac_tag"], *(row[f"{f}_enc"] for f in FIELDS), user_id):
        raise IntegrityFailure(
            "integrity check failed: this profile has been modified in storage")

    _, private = km.get_key_version(conn, user_id, km.RSA, row["key_version"])
    profile = {f: _decrypt(row[f"{f}_enc"], private) for f in FIELDS}
    profile.update(exists=True, key_version=row["key_version"],
                   updated_at=row["updated_at"])
    return profile


def update_profile(conn, user_id: str, **values) -> None:
    """Create or replace a profile, encrypting every field under RSA.

    Always writes under the user's currently active key, so saving after a
    key rotation migrates the record forward.
    """
    unknown = set(values) - set(FIELDS)
    if unknown:
        raise ProfileError(f"unknown profile field(s): {', '.join(sorted(unknown))}")

    public, _, version = km.get_active_key(conn, user_id, km.RSA)
    enc = {f"{f}_enc": _encrypt(values.get(f), public) for f in FIELDS}
    tag = compute_tag(*(enc[f"{f}_enc"] for f in FIELDS), user_id)
    now = _now()

    if _fetch(conn, user_id) is None:
        conn.execute(
            """INSERT INTO profiles
               (profile_id, user_id, full_name_enc, address_enc, phone_enc,
                nid_enc, key_version, hmac_tag, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), user_id, enc["full_name_enc"], enc["address_enc"],
             enc["phone_enc"], enc["nid_enc"], version, tag, now),
        )
    else:
        conn.execute(
            """UPDATE profiles SET full_name_enc = ?, address_enc = ?,
                   phone_enc = ?, nid_enc = ?, key_version = ?, hmac_tag = ?,
                   updated_at = ?
               WHERE user_id = ?""",
            (enc["full_name_enc"], enc["address_enc"], enc["phone_enc"],
             enc["nid_enc"], version, tag, now, user_id),
        )
    conn.commit()


def verify_profile_integrity(conn, user_id: str) -> bool:
    """Public integrity check, used by the tamper demonstration."""
    row = _fetch(conn, user_id)
    if row is None:
        raise LookupError("no profile for this user")
    return verify_tag(row["hmac_tag"], *(row[f"{f}_enc"] for f in FIELDS), user_id)