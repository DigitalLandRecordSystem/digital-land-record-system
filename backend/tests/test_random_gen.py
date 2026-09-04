from app.crypto.random_gen import random_below, random_range, random_bytes

def test_in_range():
    for _ in range(2000):
        assert 0 <= random_below(100) < 100
        assert 10 <= random_range(10, 20) <= 20

def test_length():
    assert len(random_bytes(32)) == 32

def test_not_constant():
    # 200 draws from a large range should not repeat
    vals = {random_below(2**64) for _ in range(200)}
    assert len(vals) == 200

def test_covers_range():
    # every value 0..9 should appear across 5000 draws
    seen = {random_below(10) for _ in range(5000)}
    assert seen == set(range(10))