from app.crypto.hmac_service import hmac_hex, verify_hmac

def test_rfc4231_case1():
    assert hmac_hex(bytes([0x0b])*20, b"Hi There") == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

def test_rfc4231_case2():
    assert hmac_hex(b"Jefe", b"what do ya want for nothing?") == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

def test_rfc4231_case3():
    assert hmac_hex(bytes([0xaa])*20, bytes([0xdd])*50) == \
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

def test_long_key_is_hashed():
    # key longer than the 64-byte block must be hashed down first
    assert hmac_hex(bytes([0xaa])*131,
                    b"Test Using Larger Than Block-Size Key - Hash Key First") == \
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"

def test_verify_roundtrip():
    tag = hmac_hex(b"secret", b"deed content")
    assert verify_hmac(b"secret", b"deed content", tag)
    assert not verify_hmac(b"secret", b"deed contenu", tag)   # tampered message
    assert not verify_hmac(b"wrong",  b"deed content", tag)   # wrong key