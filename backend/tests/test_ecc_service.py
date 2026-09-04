import pytest
from app.crypto.ecc_service import (
    generate_keypair, encrypt, decrypt, point_add, scalar_mult,
    is_on_curve, encode_point, decode_point, G, N, CHUNK_SIZE,
)

@pytest.fixture(scope="module")
def keys():
    return generate_keypair()

def test_point_arithmetic_known_values():
    # Small-curve check: y^2 = x^3 - 2x + 2 (mod 23), base point (4, 9).
    # Verifies point_add and scalar_mult against hand-computable values
    # before trusting them on a 256-bit curve.
    p, a, base = 23, -2, (4, 9)
    assert scalar_mult(2, base, a, p) == (15, 14)
    assert scalar_mult(3, base, a, p) == (12, 2)

def test_generator_on_curve():
    assert is_on_curve(G)
    assert is_on_curve(scalar_mult(12345, G))

def test_order_of_generator():
    assert scalar_mult(N, G) is None       # N*G is the point at infinity

def test_encode_decode(keys):
    for data in (b"a", b"x" * 30, bytes(range(30))):
        point = encode_point(data)
        assert is_on_curve(point)
        assert decode_point(point).to_bytes(len(data), "big") == data

def test_roundtrip_boundaries(keys):
    priv, pub = keys
    c = CHUNK_SIZE
    for length in (1, c - 1, c, c + 1, c * 3, c * 3 + 7):
        data = bytes([i % 256 for i in range(length)])
        assert decrypt(encrypt(data, pub), priv) == data

def test_text_roundtrip(keys):
    priv, pub = keys
    deed = "Plot 42, Gulshan, Dhaka. Area: 5.5 katha. Owner: Sarah Chowdhury."
    assert decrypt(encrypt(deed, pub), priv).decode() == deed

def test_encryption_is_randomised(keys):
    _, pub = keys
    assert encrypt(b"APPROVED", pub) != encrypt(b"APPROVED", pub)

def test_wrong_key_does_not_recover_plaintext(keys):
    priv, pub = keys
    other_priv, _ = generate_keypair()
    ciphertext = encrypt(b"secret deed content", pub)
    try:
        recovered = decrypt(ciphertext, other_priv)
    except (OverflowError, ValueError):
        return          # decryption failed outright -- expected outcome
    assert recovered != b"secret deed content"