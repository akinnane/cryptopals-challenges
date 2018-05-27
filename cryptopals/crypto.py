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
    """Remove the pkcs7 padding from a string. Raise an error if the
    padding is not valid.

    :param string: The input string to unpad.
    :returns: A string without padding
    :rtype: str

    """
    if len(set(string[-ord(string[-1]):])) != 1:
        raise ValueError
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


def xor(string1, string2):
    """XOR two strings together. If they are not the same length then

    :param c: The plaintext tring
    :param k: The key to
    :returns:
    :rtype:

    """
    string2 = (string2 * -(-len(string1) / len(string2)))[:len(string1)]
    return ''.join(
        chr(ord(a) ^ ord(b))
        for (a, b) in zip(string1, string2)
    )


def slice_array(arr, size):
    """Take an array and slice it into chunks

    :param arr: The array to slice
    :param size: The size of the chunks
    :returns: An array of arrays
    :rtype: array

    """
    return [
        arr[i:i + size]
        for i in range(0, len(arr), size)
    ]


def aes_cbc_encrypt(key, pt, iv=None, blocksize=16, padder=pkcs7_pad):
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    iv = iv if iv else chr(0) * blocksize
    slices = slice_array(padder(pt), blocksize)
    ct = []
    for i, s in enumerate(slices):
        encryptor = cipher.encryptor()
        ct.append(
            encryptor.update(xor(s, iv)) + encryptor.finalize()
        )
        iv = ct[-1]
    return ''.join(ct)


def aes_cbc_decrypt(key, ct, iv=None, blocksize=16, unpadder=pkcs7_unpad):
    """Decrypt a ciphertext using Cipher Block Chaining

    :param key: The key to use for encryption
    :param ct: The cipher text to decode
    :param iv: The Initialization vector for the first block
    :param blocksize: the block size in bytes
    :param unpadder: The unpadder to use
    :returns: Plain text
    :rtype: str

    """
    iv = iv if iv else chr(0) * blocksize
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    slices = slice_array(ct, blocksize)
    pt = []
    for i, s in enumerate(slices):
        decryptor = cipher.decryptor()
        pt.append(
            xor(
                decryptor.update(s) + decryptor.finalize(),
                iv
            )
        )
        iv = slices[i]
    return unpadder(''.join(pt))
