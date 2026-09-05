"""Time-based one-time passwords (RFC 6238) for two-step authentication.

Uses HMAC-SHA256 rather than the HMAC-SHA1 of standard authenticator apps,
since this project implements its hashing from scratch and SHA-1 is not
provided. The construction is otherwise the standard one: a counter derived
from the current time is authenticated under the user's secret, and the
result is truncated to six digits.
"""
import base64
import time

from app.crypto.hmac_service import hmac_sha256
from app.crypto.random_gen import random_bytes

TIME_STEP = 30          # seconds per code
DIGITS = 6
WINDOW = 1              # accept the previous and next step, for clock drift


def generate_secret() -> str:
    """A new base32-encoded TOTP secret."""
    return base64.b32encode(random_bytes(20)).decode()


def generate_code(secret: str, at: float = None) -> str:
    """The six-digit code valid for the given time (default: now)."""
    key = base64.b32decode(secret, casefold=True)
    counter = int((time.time() if at is None else at) // TIME_STEP)

    mac = hmac_sha256(key, counter.to_bytes(8, "big"))

    offset = mac[-1] & 0x0F                                   # dynamic truncation
    truncated = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def verify_code(secret: str, code: str, at: float = None) -> bool:
    """Check a code, allowing one step either side for clock drift."""
    if not code or len(code) != DIGITS or not code.isdigit():
        return False

    now = time.time() if at is None else at
    result = 0
    for offset in range(-WINDOW, WINDOW + 1):
        expected = generate_code(secret, now + offset * TIME_STEP)
        difference = 0
        for x, y in zip(expected, code):
            difference |= ord(x) ^ ord(y)
        result |= 1 if difference == 0 else 0
    return result == 1