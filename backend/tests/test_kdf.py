import hashlib
from app.crypto.kdf import pbkdf2, hash_password, verify_password

def test_matches_reference_pbkdf2():
    # Verify our PBKDF2 against the standard library implementation.
    # (Reference used in the test only, never in the implementation.)
    pwd, salt = b"correct horse battery staple", b"sixteen byte slt"
    for iters in (1, 2, 10, 100):
        assert pbkdf2(pwd, salt, iters) == \
            hashlib.pbkdf2_hmac("sha256", pwd, salt, iters, dklen=32)

def test_roundtrip():
    h, s, it = hash_password("hunter2", iterations=100)
    assert verify_password("hunter2", h, s, it)
    assert not verify_password("hunter3", h, s, it)

def test_salt_makes_hashes_unique():
    h1, s1, _ = hash_password("samepassword", iterations=100)
    h2, s2, _ = hash_password("samepassword", iterations=100)
    assert s1 != s2 and h1 != h2      # identical passwords, different stored hashes

def test_iterations_matter():
    salt = b"sixteen byte slt"
    assert pbkdf2(b"pw", salt, 10) != pbkdf2(b"pw", salt, 11)