from cryptopals.crypto import (
    aes_ecb_encrypt,
    aes_ecb_decrypt
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
        clean_str(userdata)
    )
    return aes_ecb_encrypt(key, cookie)


def decrypt_cookie(cookie, key=None):
    """Decrypt the cookie

    :param cookie: The encrypted cookie to decrypt
    :param key: the key to use for decryption
    :returns: The decrypted cookie text
    :rtype: str
    """
    key = key if key else 'YELLOW SUBMARINE'
    return aes_ecb_decrypt(key, cookie)


def check_is_admin(cookie):
    """Check if a cookie belongs to an admin.

    :param cookie: The cookie string to check
    :returns: A boolean indication if a use is an admin
    :rtype: bool
    """
    return ';admin=true;' in cookie
