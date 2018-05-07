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


def encrypt_cookie(userdata):
    """Clean, sandwich, pad and encrypt the userdata

    :param userdata: The userdata
    :returns: An encrypted cookie
    :rtype: str

    """
    cookie = sandwich_userdata(
        clean_str(userdata)
    )
