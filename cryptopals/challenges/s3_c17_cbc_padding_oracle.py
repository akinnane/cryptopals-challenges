from cryptopals.random import (
    random_int,
    random_bytes
)
from cryptopals.crypto import (
    aes_cbc_encrypt,
    aes_cbc_decrypt
)


class s3_c17_cbc_padding_oracle(object):
    def __init__(self):
        self.key = random_bytes(16)
        self.iv = random_bytes(16)
        self._random_string = self.random_string()

    def random_string(self):
        """Pick a random string from the challenge.

        :returns: A random string from the choices
        :rtype: str

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
        return strings[random_int(0, 9)]

    def encrypt(self):
        """
        Encrypt the chosen string with our random key and iv.

        :returns: Return a dict containing the CipherText and the IV
        :rtype: dict

        """
        return {
            'ct': aes_cbc_encrypt(
                self.key,
                self._random_string,
                self.iv
            ),
            'iv': self.iv
        }

    def decrypt_and_validate_padding(self, iv, ct):
        """
        Decrypt the given ciphertext and check for valid padding.

        :param iv: The IV to use
        :param ct: The ciphertext to decrypt
        :returns: A boolean describing the validity of the padding
        :rtype: bool

        """
        return aes_cbc_decrypt(
            self.key,
            ct,
            iv,
            unpadder=self.pkcs7_validator
        )

    def pkcs7_validator(self, string):
        """
        Check if the pkcs7 padding is valid

        :param string: The input string to unpad.
        :returns: A string without padding
        :rtype: str

        """
        return len(set(string[-ord(string[-1]):])) == 1
