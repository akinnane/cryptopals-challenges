from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pkcs7_pad(string, blocksize=16):
    """Pad a string using pkcs7 to the target block size.

    https://tools.ietf.org/html/rfc5652#section-6.3

    :param string: The input string to be padded
    :param blocksize: The target blocksize
    :returns: A padded string
    :rtype: str

    """
    padding = blocksize - (len(string) % blocksize)
    return string + (chr(padding) * padding)


def pkcs7_unpad(string):
    """Remove the pkcs7 padding from a string

    :param string: The input string to unpad
    :returns: A string without padding
    :rtype: str

    """
    return string[:-ord(string[-1])]


def aes_ecb_encrypt(key, pt, padder=pkcs7_pad):
    """Encrypt a string using AES in (E)lectionic (C)ode(B)ook mode with a
    given key. It will pad the input string using PKCS7 to a 16byte blocksize.

    :param key: The key to use for encryption
    :param pt:  The plaintext to encrypt.
    :param padder: The padder to use. This must return a string
    :returns: cypher text
    :rtype: str

    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padder(pt)) + encryptor.finalize()


def aes_ecb_decrypt(key, ct, unpadder=pkcs7_unpad):
    """Encrypt a string using AES in (E)lectionic (C)ode(B)ook mode with a
    given key. It will pad the input string using PKCS7 to a 16byte blocksize.

    :param key: The key to use for decryption
    :param ct: The cyphertext to decode
    :param unpadder: Function to remove the padding.
    :returns: Plain text
    :rtype: str

    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return unpadder(decryptor.update(ct) + decryptor.finalize())
