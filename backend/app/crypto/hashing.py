"""SHA-256 implemented from scratch (FIPS 180-4). No hashlib."""

MASK = 0xFFFFFFFF

# Round constants: first 32 bits of the fractional parts of the
# cube roots of the first 64 primes.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Initial state: first 32 bits of the fractional parts of the
# square roots of the first 8 primes.
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def _rotr(x, n):
    """Rotate a 32-bit word right by n bits."""
    return ((x >> n) | (x << (32 - n))) & MASK


def _pad(message: bytes) -> bytes:
    bit_len = len(message) * 8
    padded = message + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    return padded + bit_len.to_bytes(8, "big")


def sha256(message: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of message."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    h = list(H_INIT)
    data = _pad(message)

    for offset in range(0, len(data), 64):
        block = data[offset:offset + 64]

        # --- message schedule ---
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)

        # --- compression ---
        a, b, c, d, e, f, g, hh = h

        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + S1 + ch + K[i] + w[i]) & MASK
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASK

            hh = g
            g = f
            f = e
            e = (d + temp1) & MASK
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK

        for i, v in enumerate([a, b, c, d, e, f, g, hh]):
            h[i] = (h[i] + v) & MASK

    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(message) -> str:
    return sha256(message).hex()