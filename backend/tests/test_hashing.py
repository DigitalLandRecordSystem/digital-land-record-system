from app.crypto.hashing import sha256_hex
import hashlib

def test_empty():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_abc():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_long_multiblock():
    message = b"digital land record system " * 20
    assert sha256_hex(message) == hashlib.sha256(message).hexdigest()

def test_padding_boundaries():
    for n in (55, 56, 63, 64, 65, 119, 128):
        message = b"a" * n
        assert sha256_hex(message) == hashlib.sha256(message).hexdigest(), f"failed at length n={n}"

# ---------------------------------------------------------------------------
# Why these lengths?
#
# SHA-256 processes 64-byte blocks. Padding always costs at least 9 bytes:
# one 0x80 marker byte + 8 bytes holding the message length in bits.
# So a message of n bytes occupies n + 9 bytes, rounded up to a multiple of 64.
# Every interesting test case falls out of that one fact:
#
#   n    | n+9 | blocks | why it matters
#   -----+-----+--------+--------------------------------------------------
#   55   | 64  |   1    | largest message fitting in ONE block; padding lands
#        |     |        | exactly on the boundary, zero filler bytes added
#   56   | 65  |   2    | first message that spills over; one byte more than
#        |     |        | 55 and the work doubles
#   63   | 72  |   2    | one byte short of a full block
#   64   | 73  |   2    | message is exactly one block; padding forms an
#        |     |        | entire second block on its own
#   65   | 74  |   2    | just past a block boundary
#   119  | 128 |   2    | the n=55 case shifted up one block; exact fit again
#   128  | 137 |   3    | exactly two blocks of message, padding forms a third
#
# The critical pair is 55 vs 56, which pins down the padding loop
#     while len(padded) % 64 != 56:
# At n=55 the loop body never runs (56 % 64 == 56 already).
# At n=56 it must run 63 times to reach 120.
# Those are opposite extremes of the same line, so a wrong comparison
# (!= 0, or < instead of !=) either corrupts the digest or hangs forever.
#
# Principle: test the boundaries, not the middle. 1000 random bytes prove
# far less than 55 vs 56 does.
# ---------------------------------------------------------------------------