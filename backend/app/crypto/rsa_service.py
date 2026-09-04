"""RSA implemented from scratch.

  - sympy.randprime for large prime generation
  - pow(m, e, n) for encryption, pow(c, d, n) for decryption
  - pow(e, -1, phi) for the modular inverse

sympy and pow provide general-purpose arithmetic only; no RSA
implementation is used. The algorithm itself -- key construction,
encryption, and decryption -- is implemented here.

extra:
block chunking with a length prefix, so data longer
than the modulus can be encrypted.
"""
import sympy

PUBLIC_EXPONENT = 65537       


# ---------- modular arithmetic ----------

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """base^exponent mod modulus. pow(m, e, n)."""
    return pow(base, exponent, modulus)


def mod_inverse(a: int, m: int) -> int:
    """a^-1 mod m. pow(e, -1, phi). Raises ValueError if none exists."""
    return pow(a, -1, m)


# ---------- key generation ----------

def generate_keypair(bits: int = 1024):
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


# ---------- encryption ----------

def _key_bytes(key) -> int:
    return (key["n"].bit_length() + 7) // 8


def chunk_size(key) -> int:
    """Plaintext bytes per block: one less than the modulus, so m < n."""
    return _key_bytes(key) - 1


def encrypt(message, public_key) -> bytes:
    """c = m^e mod n, applied blockwise. Output is a 4-byte length
    prefix followed by fixed-size ciphertext blocks."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    k = _key_bytes(public_key)
    size = k - 1
    out = bytearray(len(message).to_bytes(4, "big"))

    for i in range(0, len(message), size):
        m = int.from_bytes(message[i:i + size], "big")
        c = mod_exp(m, public_key["e"], public_key["n"])
        out += c.to_bytes(k, "big")

    return bytes(out)


def decrypt(ciphertext: bytes, private_key) -> bytes:
    """m = c^d mod n, applied blockwise."""
    total_len = int.from_bytes(ciphertext[:4], "big")
    body = ciphertext[4:]
    k = _key_bytes(private_key)
    size = k - 1

    if len(body) % k != 0:
        raise ValueError("malformed ciphertext")

    parts = []
    remaining = total_len
    for i in range(0, len(body), k):
        c = int.from_bytes(body[i:i + k], "big")
        m = mod_exp(c, private_key["d"], private_key["n"])
        take = min(size, remaining)
        parts.append(m.to_bytes(take, "big"))
        remaining -= take

    return b"".join(parts)