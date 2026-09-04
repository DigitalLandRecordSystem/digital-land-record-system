"""Key management: generation, storage, retrieval, and rotation.

Each user holds two keypairs -- RSA (user data, profiles) and ECC (deed
content). Public keys are stored in plaintext, as public keys are not
secret. Private keys are encrypted under the server master public key
before storage, so the database alone never yields a usable private key;
the master private key is held in a file outside the database.

Keys are versioned. Rotation issues a new version and retires the old one,
which is kept so that records encrypted under it remain readable.
"""
import base64
import json
import uuid
from datetime import datetime, timezone

from app.config import MASTER_KEY_PATH, RSA_KEY_BITS
from app.crypto import rsa_service, ecc_service

RSA = "RSA"
ECC = "ECC"


# ---------- master key ----------

_master_cache = None


def load_master_key():
    """Load the server master keypair from disk (cached)."""
    global _master_cache
    if _master_cache is None:
        with open(MASTER_KEY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        _master_cache = (data["public"], data["private"])
    return _master_cache


# ---------- serialisation ----------

def serialise_key(key: dict) -> str:
    """Key dict -> JSON text."""
    return json.dumps(key, sort_keys=True)


def deserialise_key(text: str) -> dict:
    """JSON text -> key dict. Restores ECC points as tuples."""
    key = json.loads(text)
    if "Q" in key:                      # JSON turns the point tuple into a list
        key["Q"] = tuple(key["Q"])
    return key


def wrap_private_key(private_key: dict) -> str:
    """Encrypt a private key under the master public key. Returns base64."""
    master_public, _ = load_master_key()
    plaintext = serialise_key(private_key).encode("utf-8")
    return base64.b64encode(rsa_service.encrypt(plaintext, master_public)).decode()


def unwrap_private_key(wrapped: str) -> dict:
    """Decrypt a stored private key using the master private key."""
    _, master_private = load_master_key()
    ciphertext = base64.b64decode(wrapped)
    return deserialise_key(rsa_service.decrypt(ciphertext, master_private).decode())


# ---------- key generation ----------

def _new_keypair(algorithm: str):
    if algorithm == RSA:
        public, private = rsa_service.generate_keypair(RSA_KEY_BITS)
    elif algorithm == ECC:
        private, public = ecc_service.generate_keypair()   # note the order
    else:
        raise ValueError(f"unknown algorithm: {algorithm}")
    return public, private


def create_key(conn, user_id: str, algorithm: str, version: int = 1) -> dict:
    """Generate, wrap, and store a keypair. Returns the public key."""
    public, private = _new_keypair(algorithm)

    conn.execute(
        """INSERT INTO user_keys
           (key_id, user_id, algorithm, version, public_key,
            private_key_enc, is_active, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
        (str(uuid.uuid4()), user_id, algorithm, version,
         serialise_key(public), wrap_private_key(private),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return public


def create_user_keys(conn, user_id: str) -> None:
    """Issue the initial RSA and ECC keypairs for a new user."""
    create_key(conn, user_id, RSA)
    create_key(conn, user_id, ECC)


# ---------- retrieval ----------

def get_active_key(conn, user_id: str, algorithm: str):
    """Return (public, private, version) for the user's active key."""
    row = conn.execute(
        """SELECT public_key, private_key_enc, version FROM user_keys
           WHERE user_id = ? AND algorithm = ? AND is_active = 1
           ORDER BY version DESC LIMIT 1""",
        (user_id, algorithm),
    ).fetchone()
    if row is None:
        raise LookupError(f"no active {algorithm} key for user {user_id}")
    return (deserialise_key(row["public_key"]),
            unwrap_private_key(row["private_key_enc"]),
            row["version"])


def get_key_version(conn, user_id: str, algorithm: str, version: int):
    """Return (public, private) for a specific version, active or retired.

    Needed to read records encrypted under a key that has since rotated.
    """
    row = conn.execute(
        """SELECT public_key, private_key_enc FROM user_keys
           WHERE user_id = ? AND algorithm = ? AND version = ?""",
        (user_id, algorithm, version),
    ).fetchone()
    if row is None:
        raise LookupError(f"no {algorithm} key version {version} for user {user_id}")
    return (deserialise_key(row["public_key"]),
            unwrap_private_key(row["private_key_enc"]))


def list_keys(conn, user_id: str):
    return conn.execute(
        """SELECT key_id, algorithm, version, is_active, created_at, retired_at
           FROM user_keys WHERE user_id = ? ORDER BY algorithm, version""",
        (user_id,),
    ).fetchall()


# ---------- rotation ----------

def rotate_key(conn, user_id: str, algorithm: str) -> dict:
    """Retire the current key and issue the next version.

    The old key is retained, not deleted, so records still encrypted under
    it can be read. Callers re-encrypt affected records under the new key.
    """
    row = conn.execute(
        """SELECT MAX(version) AS v FROM user_keys
           WHERE user_id = ? AND algorithm = ?""",
        (user_id, algorithm),
    ).fetchone()
    current = row["v"] or 0

    conn.execute(
        """UPDATE user_keys SET is_active = 0, retired_at = ?
           WHERE user_id = ? AND algorithm = ? AND is_active = 1""",
        (datetime.now(timezone.utc).isoformat(), user_id, algorithm),
    )
    public = create_key(conn, user_id, algorithm, version=current + 1)
    conn.commit()
    return public