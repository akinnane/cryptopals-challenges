from cryptopals.crypto import (
    aes_cbc_encrypt,
    aes_cbc_decrypt
)


def clean_str(data, remove=''):
    """Removes the specified characters from a string

    :param data: The data to clean
    :param remove: The characters to remove
    :returns: The clean string
    :rtype: str

    """
    return data.translate(None, remove)


def sandwich_userdata(userdata):
    """Appends the preset comments to the userdata for a complete cookie

    :param userdata: the data to sandwich_userdata
    :returns: The whole cookie
    :rtype: str

    """
    pre = "comment1=cooking%20MCs;userdata="
    post = ";comment2=%20like%20a%20pound%20of%20bacon"
    return pre + userdata + post


def encrypt_cookie(userdata, key=None):
    """Clean, sandwich, pad and encrypt the userdata

    :param userdata: The userdata
    :returns: An encrypted cookie
    :rtype: str

    """
    key = key if key else 'YELLOW SUBMARINE'
    cookie = sandwich_userdata(
        clean_str(userdata, '=;')
    )
    return aes_cbc_encrypt(key, cookie)


def decrypt_cookie(cookie, key=None):
    """Decrypt the cookie

    :param cookie: The encrypted cookie to decrypt
    :param key: the key to use for decryption
    :returns: The decrypted cookie text
    :rtype: str
    """
    key = key if key else 'YELLOW SUBMARINE'
    return aes_cbc_decrypt(key, cookie)


def check_is_admin(cookie):
    """Check if a cookie belongs to an admin.

    :param cookie: The cookie string to check
    :returns: A boolean indication if a use is an admin
    :rtype: bool
    """
    return ';admin=true;' in cookie


def bit_fliping_userdata(padding):
    """The userdata to use in the bit flipping attack

    :returns: The string to use for userdata
    :rtype: str

    """
    padding_block = 'P' * padding
    flipping_block = 'F' * 16

    semi_colon = flipbit(';', 0)
    equals = flipbit('=', 0)
    admin_block = '{s}admin{e}true'.format(
        s=semi_colon,
        e=equals
    )
    return padding_block + flipping_block + admin_block


def flipbit(string, location):
    """Flips the lowest order bit of a specific byte in a string

    :param string: The string to modify
    :param location: The byte that contains the bit to flip
    :returns: The modified string
    :rtype: str
    """
    char = ord(string[location])
    if char % 2 == 0:
        char = chr(char + 1)
    else:
        char = chr(char - 1)
    return string[:location] + char + string[location + 1:]


def challenge_16():
    userdata = bit_fliping_userdata(3)
    encrypted_cookie = encrypt_cookie(userdata)
    flipped_cookie = flipbit(encrypted_cookie, 35)
    flipped_cookie = flipbit(flipped_cookie, 41)
    decrypted_cookie = decrypt_cookie(flipped_cookie)
    return decrypted_cookie
