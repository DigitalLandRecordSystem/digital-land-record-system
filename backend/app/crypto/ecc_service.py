"""ECC over secp256k1 with EC-ElGamal encryption, implemented from scratch.

Extends the point arithmetic (point_add, scalar_mult) to a
real curve and a full asymmetric encryption scheme. No symmetric
primitives are used anywhere: ECIES was rejected precisely because its
payload layer requires a symmetric cipher.
"""
from app.crypto.random_gen import random_range

# --- secp256k1 domain parameters (standard, publicly published) ---
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (GX, GY)

K_SLACK = 256      # encoding search space: 256 candidate x values per chunk
CHUNK_SIZE = 30    # bytes of plaintext per curve point


# ---------- point arithmetic ----------

def mod_inverse(k, p):
    """Modular inverse, as used in Lab 7."""
    return pow(k, -1, p)

def point_add(point_p, point_q, a=A, p=P):
    """Add two curve points. None represents the point at infinity."""
    if point_p is None:
        return point_q
    if point_q is None:
        return point_p

    x1, y1 = point_p
    x2, y2 = point_q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None                        # vertical line -> infinity

    if point_p == point_q:                 # doubling
        m = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        m = (y2 - y1) * mod_inverse(x2 - x1, p) % p

    xr = (m * m - x1 - x2) % p
    yr = (m * (x1 - xr) - y1) % p
    return (xr, yr)


def scalar_mult(k, point, a=A, p=P):
    """Double-and-add scalar multiplication."""
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result


def negate(point, p=P):
    if point is None:
        return None
    x, y = point
    return (x, (-y) % p)


def is_on_curve(point, a=A, b=B, p=P) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + a * x + b)) % p == 0


# ---------- message <-> point encoding (Koblitz) ----------

def encode_point(chunk: bytes):
    """Map up to CHUNK_SIZE bytes onto a curve point."""
    if len(chunk) > CHUNK_SIZE:
        raise ValueError(f"chunk too long: {len(chunk)} > {CHUNK_SIZE}")
    m = int.from_bytes(chunk, "big")
    for offset in range(K_SLACK):
        x = (m * K_SLACK + offset) % P
        rhs = (x * x * x + A * x + B) % P
        y = y = pow(rhs, (P + 1) // 4, P)   # sqrt shortcut: valid as P % 4 == 3(rhs, (P + 1) // 4, P)   # sqrt shortcut: valid as P % 4 == 3
        if (y * y - rhs) % P == 0:
            return (x, y)
    raise ValueError("failed to encode chunk onto the curve")


def decode_point(point) -> int:
    x, _ = point
    return x // K_SLACK                     # discard the search offset


# ---------- keys ----------

def generate_keypair():
    """Returns (private, public). Private: d. Public: Q = d*G."""
    d = random_range(1, N - 1)
    return {"d": d}, {"Q": scalar_mult(d, G)}


# ---------- EC-ElGamal ----------

def encrypt(message, public_key) -> bytes:
    """Encrypt arbitrary-length data. Returns a serialisable byte string."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    out = bytearray()
    out += len(message).to_bytes(4, "big")          # length prefix

    for i in range(0, len(message), CHUNK_SIZE):
        chunk = message[i:i + CHUNK_SIZE]
        point_m = encode_point(chunk)
        k = random_range(1, N - 1)                  # fresh nonce EVERY chunk
        c1 = scalar_mult(k, G)
        c2 = point_add(point_m, scalar_mult(k, public_key["Q"]))
        for x, y in (c1, c2):                       # 4 x 32 bytes per chunk
            out += x.to_bytes(32, "big")
            out += y.to_bytes(32, "big")
    return bytes(out)


def decrypt(ciphertext: bytes, private_key) -> bytes:
    total_len = int.from_bytes(ciphertext[:4], "big")
    body = ciphertext[4:]
    if len(body) % 128 != 0:
        raise ValueError("malformed ciphertext")

    parts = []
    remaining = total_len
    for i in range(0, len(body), 128):
        block = body[i:i + 128]
        c1 = (int.from_bytes(block[0:32], "big"),  int.from_bytes(block[32:64], "big"))
        c2 = (int.from_bytes(block[64:96], "big"), int.from_bytes(block[96:128], "big"))

        point_m = point_add(c2, negate(scalar_mult(private_key["d"], c1)))
        take = min(CHUNK_SIZE, remaining)
        parts.append(decode_point(point_m).to_bytes(take, "big"))
        remaining -= take

    return b"".join(parts)