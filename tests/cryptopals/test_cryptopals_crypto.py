from cryptopals.crypto import (
    aes_ecb_encrypt,
    pkcs7_pad
)


def test_pkcs7_pad():
    i = 'AAAAAAAA'
    e = i + chr(8) * 8

    assert(e == pkcs7_pad(i))


def test_aes_ecb_encrypt():
    e = '91befd7fe8e6d8a664a98309686d19b3'

    key = 'aaaaaaaaaaaaaaaa'
    pt = 'texttexttext'
    r = aes_ecb_encrypt(key, pt)

    assert(e == r.encode('hex'))
