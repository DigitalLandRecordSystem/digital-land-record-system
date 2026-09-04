"""PBKDF2-HMAC-SHA256 password hashing, implemented from scratch (RFC 2898).

Iteration count is deliberately low (see .env KDF_ITERATIONS) because our
SHA-256 is pure Python at ~840us per HMAC. OWASP's recommended 600,000
would take over eight minutes per login here.
"""
from app.crypto.hmac_service import hmac_sha256
from app.crypto.random_gen import random_bytes

SALT_BYTES = 16
DEFAULT_ITERATIONS = 1000
DK_LEN = 32          # one SHA-256 block, so no outer PBKDF2 loop needed


def pbkdf2(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte key from a password and salt."""
    if isinstance(password, str):
        password = password.encode("utf-8")

    # U1 = HMAC(password, salt || INT32BE(1))
    u = hmac_sha256(password, salt + (1).to_bytes(4, "big"))
    result = bytearray(u)

    # U2..Uc, XOR-ing each into the accumulator
    for _ in range(iterations - 1):
        u = hmac_sha256(password, u)
        for i in range(DK_LEN):
            result[i] ^= u[i]

    return bytes(result)


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS):
    """Hash a new password. Returns (hash_hex, salt_hex, iterations)."""
    salt = random_bytes(SALT_BYTES)
    return pbkdf2(password, salt, iterations).hex(), salt.hex(), iterations


def verify_password(password: str, stored_hash: str,
                    stored_salt: str, iterations: int) -> bool:
    """Check a password against stored values. Constant-time comparison."""
    salt = bytes.fromhex(stored_salt)
    computed = pbkdf2(password, salt, iterations)
    expected = bytes.fromhex(stored_hash)

    if len(computed) != len(expected):
        return False
    diff = 0
    for x, y in zip(computed, expected):
        diff |= x ^ y
    return diff == 0