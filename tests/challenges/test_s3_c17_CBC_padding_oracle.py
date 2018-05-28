"""The CBC padding oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future
encryptions), pad the string out to the 16-byte AES block size and
CBC-encrypt it under that key, providing the caller the ciphertext and
IV.

The second function should consume the ciphertext produced by the
first function, decrypt it, check its padding, and return true or
false depending on whether the padding is valid.  What you're doing
here.

This pair of functions approximates AES-CBC encryption as its deployed
serverside in web applications; the second function models the
server's consumption of an encrypted session token, as if it was a
cookie.

It turns out that it's possible to decrypt the ciphertexts provided by
the first function.

The decryption here depends on a side-channel leak by the decryption
function. The leak is the error message that the padding is valid or
not.

You can find 100 web pages on how this attack works, so I won't
re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is
valid padding, and occur in 1/256 trials of "randomized" plaintexts
produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid
padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are
"padded". Padding oracles have nothing to do with the actual padding
on a CBC plaintext. It's an attack that targets a specific bit of code
that handles decryption. You can mount a padding oracle on any CBC
block, whether it's padded or not.
"""
from cryptopals.challenges.s3_c17_cbc_padding_oracle import (
    s3_c17_cbc_padding_oracle
)
from pytest import fixture


@fixture
def padding_oracle():
    """Pytest fixture for padding oracle

    :returns: A fixture to use for the tests
    :rtype: c3_c17_cbc_padding_oracle

    """
    return s3_c17_cbc_padding_oracle()


def test_can_create_s3_c17_cbc_padding_oracle(padding_oracle):
    assert(padding_oracle)


def test_random_string(padding_oracle):
    """
    The first function should select at random one of the following 10 strings:
    """
    strings = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        (
            'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5k'
            'IHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic='
        ),
        (
            'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG'
            '9pbnQsIG5vIGZha2luZw=='
        ),
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]
    random_string = padding_oracle.random_string()
    assert(random_string in strings)


def test_random_string_is_saved(padding_oracle):
    """
    Assert the random string is saved.
    """
    assert(padding_oracle._random_string)


def test_padding_oracle_generates_an_encryption_key(padding_oracle):
    """
    generate a random AES key (which it should save for all future
    encryptions),
    """
    assert(len(padding_oracle.key) == 16)


def test_padding_oracle_generates_an_encryption_iv(padding_oracle):
    """
    generate and save random CBC IV
    """
    assert(len(padding_oracle.iv) == 16)


def test_padding_oracle_can_cbc_encrypt_with_padding(padding_oracle):
    """
    pad the string out to the 16-byte AES block size and
    CBC-encrypt it under that key, providing the caller the ciphertext and
    IV.
    """
    padding_oracle.key = 'YELLOW SUBMARINE'
    padding_oracle.iv = 'ORANGE SUBMARINE'
    padding_oracle._random_string = 'Cooking MCs like a poung of bacon'
    expected = {
        'iv': padding_oracle.iv,
        'ct': (
            "\x9d\x00\x9a'\x0cui\xa7\x9d\x99\x82m0b\xc4\xf0b[\xbc\xa0\xda"
            "\x9c87^\x9c\x1a\xcb\xcbT\x9ec\xec|\xd1v\xb1b\xec\xec\x07,]\x82"
            "\x92\x9a9\xec"
        )
    }
    result = padding_oracle.encrypt()
    assert(result == expected)


def test_padding_oracle_pkcs7_validator_true(padding_oracle):
    """
    Check that the padding validator works for correct padding
    """
    for i in range(1, 16):
        assert(padding_oracle.pkcs7_validator(chr(i) * i))


def test_padding_oracle_pkcs7_validator_false(padding_oracle):
    """
    Check that the padding validator works for incorrect padding
    """
    string = 'hello' + chr(10) * 5
    assert(not padding_oracle.pkcs7_validator(string))


def test_padding_oracle_decrypts_and_validate_correct_padding(padding_oracle):
    """
    The second function should consume the ciphertext produced by the
    first function, decrypt it, check its padding, and return true or
    false depending on whether the padding is valid.
    """
    padding_oracle.key = 'YELLOW SUBMARINE'
    padding_oracle.iv = 'ORANGE SUBMARINE'
    padding_oracle._random_string = 'Cooking MCs like a poung of bacon'
    iv_ct = {
        'iv': padding_oracle.iv,
        'ct': (
            "\x9d\x00\x9a'\x0cui\xa7\x9d\x99\x82m0b\xc4\xf0b[\xbc\xa0\xda"
            "\x9c87^\x9c\x1a\xcb\xcbT\x9ec\xec|\xd1v\xb1b\xec\xec\x07,]\x82"
            "\x92\x9a9\xec"
        )
    }
    result = padding_oracle.decrypt_and_validate_padding(
        iv_ct['iv'],
        iv_ct['ct']
    )
    assert(result)


def test_padding_oracle_decrypts_and_validates_bad_padding(padding_oracle):
    """
    The second function should consume the ciphertext produced by the
    first function, decrypt it, check its padding, and return true or
    false depending on whether the padding is valid.
    """
    padding_oracle.key = 'YELLOW SUBMARINE'
    padding_oracle.iv = 'ORANGE SUBMARINE'
    padding_oracle._random_string = 'Cooking MCs like a poung of bacon'
    iv_ct = {
        'iv': padding_oracle.iv,
        'ct': (
            "\x9d\x00\x9a'\x0cui\xa7\x9d\x99\x82m0b\xc4\xf0b[\xbc\xa0\xda"
            "\x9c87^\x9c\x1a\xcb\xcbT\x9ec\xec|\xd1v\xb1b\xec\xec\x07,]\x82"
            "\x92\x9a9\xed"
        )
    }
    result = padding_oracle.decrypt_and_validate_padding(
        iv_ct['iv'],
        iv_ct['ct']
    )
    assert(not result)
