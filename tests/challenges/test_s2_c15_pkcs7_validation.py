'''PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid
PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby,
make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
'''
from cryptopals.crypto import pkcs7_unpad



def test_pkcs7_unpad_works_for_valid_strigs():
    valid_padding = ['ICE ICE BABY' + chr(4) * 4]
    for s in valid_padding:
        assert('ICE ICE BABY' == pkcs7_unpad(s))

def test_pkcs7_unpad_raises_ValueError_for_invalid_strigs():
    invalid_padding = [
        'ICE ICE BABY' + chr(5) * 4,
        'ICE ICE BABY' + chr(1) + chr(2) + chr(3) + chr(4)
    ]
    for s in invalid_padding:
        try:
            pkcs7_unpad(s)
            assert(False)
        except ValueError:
            pass
