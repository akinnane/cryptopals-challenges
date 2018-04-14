from cryptopals.random import (
    random_bytes,
    random_int
)


def test_random_bytes():
    assert(random_bytes(8) != random_bytes(8))


def test_random_bytes_size():
    for s in range(1, 3):
        assert(len(random_bytes(s)) == s)


def test_random_int():
    assert(type(random_int(1, 2)) == int)
