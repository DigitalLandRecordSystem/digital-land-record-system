"""RSA implemented from scratch, with OAEP padding.

  - sympy.randprime for large prime generation
  - pow(m, e, n) for encryption, pow(c, d, n) for decryption
  - pow(e, -1, phi) for the modular inverse

sympy and pow provide general-purpose arithmetic only; no RSA
implementation is used. The algorithm itself -- key construction,
encryption, decryption, and the OAEP padding scheme -- is implemented here.

Padding (EME-OAEP, RFC 8017) matters cryptographically, not cosmetically.
Unpadded "textbook" RSA is deterministic, so an attacker holding the
database can encrypt guesses under the stored public key and compare
ciphertexts, recovering low-entropy fields such as an email address or a
phone number without ever touching a private key. OAEP injects a fresh
random seed into every block, so the same plaintext encrypts to a
different ciphertext each time and that attack disappears.

MGF1 and the hash are built on our own SHA-256; no library primitive is
used here either.

extra:
block chunking, so data longer than the modulus can be encrypted.
"""
import sympy

from app.crypto.hashing import sha256
from app.crypto.random_gen import random_bytes

PUBLIC_EXPONENT = 65537
HASH_LEN = 32                 # SHA-256 output, in bytes
LABEL = b""                   # OAEP label; empty, as is standard


# ---------- modular arithmetic ----------

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """base^exponent mod modulus. pow(m, e, n)."""
    return pow(base, exponent, modulus)


def mod_inverse(a: int, m: int) -> int:
    """a^-1 mod m. pow(e, -1, phi). Raises ValueError if none exists."""
    return pow(a, -1, m)


# ---------- key generation ----------

def generate_keypair(bits: int = 2048):
    """Generate an RSA keypair.

    steps: pick primes p and q, n = pq, phi = (p-1)(q-1),
    then d such that d*e = 1 mod phi.

    Returns (public, private) where public = {n, e} and private = {n, d}.
    """
    half = bits // 2
    while True:
        p = sympy.randprime(2 ** (half - 1), 2 ** half)
        q = sympy.randprime(2 ** (half - 1), 2 ** half)
        if p == q:
            continue

        n = p * q
        if n.bit_length() != bits:          # ensure the modulus is full size
            continue

        phi = (p - 1) * (q - 1)
        try:
            d = mod_inverse(PUBLIC_EXPONENT, phi)
        except ValueError:
            continue                        # gcd(e, phi) != 1, pick new primes

        return {"n": n, "e": PUBLIC_EXPONENT}, {"n": n, "d": d}


# ---------- OAEP padding ----------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, length: int) -> bytes:
    """Mask generation function MGF1, over our own SHA-256.

    Stretches a short seed into a mask of arbitrary length by hashing the
    seed against an incrementing 4-byte counter.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:length])


def _oaep_encode(message: bytes, k: int) -> bytes:
    """Pad one plaintext chunk into a k-byte encoded message.

    EM = 0x00 || maskedSeed || maskedDB, where
    DB = hash(label) || zero padding || 0x01 || message.
    """
    max_len = k - 2 * HASH_LEN - 2
    if len(message) > max_len:
        raise ValueError(f"chunk too long for OAEP: {len(message)} > {max_len}")

    db = (sha256(LABEL)
          + b"\x00" * (max_len - len(message))
          + b"\x01"
          + message)                              # length: k - HASH_LEN - 1

    seed = random_bytes(HASH_LEN)                 # fresh randomness per block
    masked_db = _xor(db, mgf1(seed, k - HASH_LEN - 1))
    masked_seed = _xor(seed, mgf1(masked_db, HASH_LEN))

    return b"\x00" + masked_seed + masked_db


def _oaep_decode(encoded: bytes, k: int) -> bytes:
    """Recover the plaintext chunk from a k-byte encoded message."""
    if len(encoded) != k or encoded[0] != 0x00:
        raise ValueError("OAEP decoding error")

    masked_seed = encoded[1:1 + HASH_LEN]
    masked_db = encoded[1 + HASH_LEN:]

    seed = _xor(masked_seed, mgf1(masked_db, HASH_LEN))
    db = _xor(masked_db, mgf1(seed, k - HASH_LEN - 1))

    if db[:HASH_LEN] != sha256(LABEL):
        raise ValueError("OAEP decoding error")

    # Skip the zero padding; the message begins after the 0x01 separator.
    index = HASH_LEN
    while index < len(db) and db[index] == 0x00:
        index += 1
    if index == len(db) or db[index] != 0x01:
        raise ValueError("OAEP decoding error")

    return db[index + 1:]


# ---------- encryption ----------

def _key_bytes(key) -> int:
    return (key["n"].bit_length() + 7) // 8


def chunk_size(key) -> int:
    """Plaintext bytes per block, after OAEP overhead.

    OAEP costs two hashes plus two delimiter bytes, so a 1024-bit key
    carries 62 bytes per block and a 2048-bit key carries 190.
    """
    return _key_bytes(key) - 2 * HASH_LEN - 2


def encrypt(message, public_key) -> bytes:
    """c = OAEP(m)^e mod n, applied blockwise.

    Output is a whole number of fixed-size ciphertext blocks. No length
    prefix is needed: OAEP encodes each chunk's own length, so the exact
    plaintext length is no longer leaked by the stored ciphertext.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    k = _key_bytes(public_key)
    size = chunk_size(public_key)
    if size < 1:
        raise ValueError("modulus too small for OAEP; use at least 1024 bits")
    out = bytearray()

    # range(0, 0, size) is empty, so an empty message must still emit one
    # block; otherwise b"" would encrypt to b"" and reveal itself.
    for i in range(0, max(len(message), 1), size):
        block = _oaep_encode(message[i:i + size], k)
        m = int.from_bytes(block, "big")
        c = mod_exp(m, public_key["e"], public_key["n"])
        out += c.to_bytes(k, "big")

    return bytes(out)


def decrypt(ciphertext: bytes, private_key) -> bytes:
    """m = OAEP-decode(c^d mod n), applied blockwise."""
    k = _key_bytes(private_key)

    if not ciphertext or len(ciphertext) % k != 0:
        raise ValueError("malformed ciphertext")

    parts = []
    for i in range(0, len(ciphertext), k):
        c = int.from_bytes(ciphertext[i:i + k], "big")
        m = mod_exp(c, private_key["d"], private_key["n"])
        parts.append(_oaep_decode(m.to_bytes(k, "big"), k))

    return b"".join(parts)
