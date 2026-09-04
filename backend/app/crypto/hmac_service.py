"""HMAC-SHA256 implemented from scratch (RFC 2104). No hmac module."""
from app.crypto.hashing import sha256

BLOCK_SIZE = 64          # SHA-256 operates on 64-byte blocks
IPAD = 0x36
OPAD = 0x5c


def _normalise_key(key: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = sha256(key)                       # long keys are hashed down
    return key + b"\x00" * (BLOCK_SIZE - len(key))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")

    k = _normalise_key(key)
    inner_pad = bytes(b ^ IPAD for b in k)
    outer_pad = bytes(b ^ OPAD for b in k)

    return sha256(outer_pad + sha256(inner_pad + message))


def hmac_hex(key, message) -> str:
    return hmac_sha256(key, message).hex()


def verify_hmac(key, message, tag) -> bool:
    """Constant-time tag comparison."""
    if isinstance(tag, str):
        tag = bytes.fromhex(tag)
    expected = hmac_sha256(key, message)
    if len(expected) != len(tag):
        return False
    result = 0
    for x, y in zip(expected, tag):
        result |= x ^ y                         # accumulate, never early-exit
    return result == 0