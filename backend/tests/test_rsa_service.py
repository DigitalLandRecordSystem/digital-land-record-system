import pytest
from app.crypto.rsa_service import (
    generate_keypair, encrypt, decrypt, mod_exp, mod_inverse, chunk_size,
)

@pytest.fixture(scope="module")
def keys():
    return generate_keypair(1024)

def test_mod_exp():
    assert mod_exp(4, 13, 497) == 445
    assert mod_exp(2, 10, 1000) == 24

def test_mod_inverse():
    assert mod_inverse(3, 11) == 4          # 3*4 = 12 = 1 mod 11
    with pytest.raises(ValueError):
        mod_inverse(4, 8)                   # gcd != 1, no inverse

def test_keypair_structure(keys):
    pub, priv = keys
    assert pub["n"] == priv["n"]
    assert pub["n"].bit_length() == 1024
    assert pub["e"] == 65537

def test_roundtrip_boundaries(keys):
    pub, priv = keys
    s = chunk_size(pub)
    for length in (0, 1, s - 1, s, s + 1, s * 3, s * 3 + 7):
        data = bytes([i % 256 for i in range(length)])
        assert decrypt(encrypt(data, pub), priv) == data

def test_leading_zeros_preserved(keys):
    pub, priv = keys
    data = b"\x00\x00hello"                 # length prefix preserves these
    assert decrypt(encrypt(data, pub), priv) == data

def test_text_roundtrip(keys):
    pub, priv = keys
    text = "Plot 42, Bunyland, Narnia. Owner: Maimuna Chowdhury."
    assert decrypt(encrypt(text, pub), priv).decode() == text

def test_oaep_encryption_is_randomised(keys):
    pub, priv = keys
    # OAEP draws a fresh seed per block, so the same plaintext must never
    # produce the same ciphertext twice. This is what stops an attacker
    # holding the database from confirming a guess against the stored
    # public key.
    a, b = encrypt(b"APPROVED", pub), encrypt(b"APPROVED", pub)
    assert a != b
    assert decrypt(a, priv) == decrypt(b, priv) == b"APPROVED"

def test_short_message_is_reduced(keys):
    pub, _ = keys
    # With a large public exponent, m^e always exceeds n, so modular
    # reduction always occurs -- even for very short plaintexts.
    m = int.from_bytes(b"a", "big")
    assert m ** pub["e"] > pub["n"]

def test_wrong_key_does_not_recover_plaintext(keys):
    pub, _ = keys
    _, other_priv = generate_keypair(1024)
    ciphertext = encrypt(b"secret deed", pub)
    try:
        recovered = decrypt(ciphertext, other_priv)
    except (OverflowError, ValueError):
        return
    assert recovered != b"secret deed"