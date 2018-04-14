import os


def random_bytes(size):
    return ''.join(
        chr(c)
        for c in bytearray(os.urandom(size))
    )


def random_int(start, end):
    return ord(random_bytes(1)) % (end - start + 1) + start
