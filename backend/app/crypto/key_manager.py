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
from app.crypto.hashing import sha256_hex
from app.crypto.integrity import compute_tag, verify_tag

RSA = "RSA"
ECC = "ECC"

class KeyIntegrityError(Exception):
    """A stored key record does not match its HMAC tag."""


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


# ---------- integrity ----------

def _key_tag(key_id, user_id, algorithm, version, public_text, private_enc) -> str:
    """HMAC over a whole key record.

    Public keys are not encrypted, because they are not secret. They are
    tagged, because substituting one would silently redirect every future
    encryption for that user to an attacker's keypair.
    """
    return compute_tag(key_id, user_id, algorithm, str(version),
                       public_text, private_enc)


def _check_key_row(row) -> None:
    if not verify_tag(row["hmac_tag"], row["key_id"], row["user_id"],
                      row["algorithm"], str(row["version"]),
                      row["public_key"], row["private_key_enc"]):
        raise KeyIntegrityError(
            f"key {row['key_id']} failed its integrity check; it may have "
            f"been substituted in storage")


def verify_key_integrity(conn, key_id: str) -> bool:
    """Public integrity check for a single key record."""
    row = conn.execute("SELECT * FROM user_keys WHERE key_id = ?",
                       (key_id,)).fetchone()
    if row is None:
        raise LookupError("no such key")
    try:
        _check_key_row(row)
    except KeyIntegrityError:
        return False
    return True


def key_fingerprint(public: dict) -> str:
    """Short, stable identifier for a public key, for display and comparison."""
    return sha256_hex(serialise_key(public))[:16]


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


def store_key(conn, user_id: str, algorithm: str,
              public: dict, private: dict, version: int = 1) -> None:
    """Store a keypair: public in the clear, private wrapped, both tagged."""
    key_id = str(uuid.uuid4())
    public_text = serialise_key(public)
    private_enc = wrap_private_key(private)
    tag = _key_tag(key_id, user_id, algorithm, version, public_text, private_enc)

    conn.execute(
        """INSERT INTO user_keys
           (key_id, user_id, algorithm, version, public_key,
            private_key_enc, hmac_tag, is_active, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)""",
        (key_id, user_id, algorithm, version, public_text, private_enc, tag,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def create_key(conn, user_id: str, algorithm: str, version: int = 1) -> dict:
    """Generate, wrap, and store a keypair. Returns the public key."""
    public, private = _new_keypair(algorithm)
    store_key(conn, user_id, algorithm, public, private, version)
    return public


def new_keypair(algorithm: str):
    """Public wrapper: generate a keypair without storing it."""
    return _new_keypair(algorithm)


def create_user_keys(conn, user_id: str) -> None:
    """Issue the initial RSA and ECC keypairs for a new user."""
    create_key(conn, user_id, RSA)
    create_key(conn, user_id, ECC)


# ---------- retrieval ----------

def _active_row(conn, user_id: str, algorithm: str):
    return conn.execute(
        """SELECT * FROM user_keys
           WHERE user_id = ? AND algorithm = ? AND is_active = 1
           ORDER BY version DESC LIMIT 1""",
        (user_id, algorithm),
    ).fetchone()


def get_active_key(conn, user_id: str, algorithm: str):
    """Return (public, private, version) for the user's active key."""
    row = _active_row(conn, user_id, algorithm)
    if row is None:
        raise LookupError(f"no active {algorithm} key for user {user_id}")
    _check_key_row(row)
    return (deserialise_key(row["public_key"]),
            unwrap_private_key(row["private_key_enc"]),
            row["version"])


def get_key_version(conn, user_id: str, algorithm: str, version: int):
    """Return (public, private) for a specific version, active or retired.

    Needed to read records encrypted under a key that has since rotated.
    """
    row = conn.execute(
        """SELECT * FROM user_keys
           WHERE user_id = ? AND algorithm = ? AND version = ?""",
        (user_id, algorithm, version),
    ).fetchone()
    if row is None:
        raise LookupError(f"no {algorithm} key version {version} for user {user_id}")
    _check_key_row(row)
    return (deserialise_key(row["public_key"]),
            unwrap_private_key(row["private_key_enc"]))


def get_public_key(conn, user_id: str, algorithm: str, version: int = None):
    """Distribution: hand out a user's public key so others can encrypt for them.

    Returns (public_key, version). No private key material is unwrapped, so
    encrypting a record for another user never requires access to that
    user's secrets, and the server master key is not touched.
    """
    if version is None:
        row = _active_row(conn, user_id, algorithm)
    else:
        row = conn.execute(
            """SELECT * FROM user_keys
               WHERE user_id = ? AND algorithm = ? AND version = ?""",
            (user_id, algorithm, version),
        ).fetchone()
    if row is None:
        raise LookupError(f"no {algorithm} public key for user {user_id}")
    _check_key_row(row)
    return deserialise_key(row["public_key"]), row["version"]


def list_keys(conn, user_id: str) -> list:
    """Every key held for a user, with fingerprint and integrity status."""
    rows = conn.execute(
        "SELECT * FROM user_keys WHERE user_id = ? ORDER BY algorithm, version",
        (user_id,),
    ).fetchall()

    out = []
    for row in rows:
        entry = dict(row)
        entry["intact"] = verify_tag(
            row["hmac_tag"], row["key_id"], row["user_id"], row["algorithm"],
            str(row["version"]), row["public_key"], row["private_key_enc"])
        entry["fingerprint"] = sha256_hex(row["public_key"])[:16]
        out.append(entry)
    return out


def public_directory(conn) -> list:
    """The published directory of active public keys for every user.

    This is what distribution looks like in practice: any party may fetch
    any user's public key, and nothing secret is exposed by doing so.
    """
    rows = conn.execute(
        """SELECT k.user_id, k.algorithm, k.version, k.public_key, u.role
           FROM user_keys k JOIN users u ON u.user_id = k.user_id
           WHERE k.is_active = 1
           ORDER BY k.user_id, k.algorithm""").fetchall()
    return [{"user_id": r["user_id"], "role": r["role"],
             "algorithm": r["algorithm"], "version": r["version"],
             "fingerprint": sha256_hex(r["public_key"])[:16]} for r in rows]


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