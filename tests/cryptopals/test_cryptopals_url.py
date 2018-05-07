from cryptopals.url import (
    encode_query,
    decode_query
)


def test_decode_query():
    i = 'foo=bar&baz=qux&zap=zazzle'
    e = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }

    assert(e == decode_query(i))


def test_encode_query():
    i = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }
    e = 'foo=bar&baz=qux&zap=zazzle'

    assert(e == encode_query(i))


def test_encode_query_removes_equals():
    i = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zaz=zle'
    }
    e = 'foo=bar&baz=qux&zap=zazzle'

    assert(e == encode_query(i))


def test_encode_query_removes_ambersand():
    i = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zaz&zle'
    }
    e = 'foo=bar&baz=qux&zap=zazzle'

    assert(e == encode_query(i))


def test_encode_query_removes_given_characters():
    i = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zaz-_zle'
    }
    e = 'foo=bar&baz=qux&zap=zazzle'

    assert(e == encode_query(i, remove='_-'))


def test_encode_query_works_for_ints():
    i = {
        'foo': 'bar',
        'uid': 2,
        'zap': 'zaz&zle'
    }
    e = 'foo=bar&uid=2&zap=zazzle'

    assert(e == encode_query(i))
