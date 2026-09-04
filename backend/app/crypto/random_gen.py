"""Cryptographically secure randomness.

Note: os.urandom is the operating system's CSPRNG, not an encryption
algorithm, so using it does not conflict with the 'implement from scratch'
requirement. Writing our own PRNG would be strictly less secure.
"""
import os

def random_bytes(n: int) -> bytes:
    """Generate cryptographically secure random bytes of specified length."""
    if n < 0:
        raise ValueError("Length must be non-negative")
    return os.urandom(n)

def random_hex(nbytes: int = 32) -> str:
    """hex string for session tokens."""
    return random_bytes(nbytes).hex()

def random_below(n: int) -> int:
    """Uniform random integer in the range [0, n) using rejection sampling."""
    if n <= 0:
        raise ValueError("n must be positive")
    nbytes = (n.bit_length() + 7) // 8
    while True:
        candidate = int.from_bytes(random_bytes(nbytes), "big")
        candidate >>= (nbytes * 8 - n.bit_length())  # Shift to fit in range
        if candidate < n:
            return candidate                         # else: try again

def random_range(low: int, high: int) -> int:
    """Uniform random integer in the range [low, high)."""
    if low > high:
        raise ValueError("low must be <= high")
    return low + random_below(high - low)

