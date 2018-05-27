"""CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block
length and encrypt it under the random AES key.

The second function should decrypt the string and look for the
characters ";admin=true;" (or, equivalently, decrypt, split the string
on ";", convert each resulting string into 2-tuples, and look for the
"admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be
possible to provide user input to it that will generate the string the
second function is looking for. We'll have to break the crypto to do
that.

Instead, modify the ciphertext (without knowledge of the AES key) to
accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a
ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC
mode have this property?

"""
from cryptopals.challenges.s2_c16_cbc_bitflipping_attacks import (
    clean_str,
    sandwich_userdata,
    encrypt_cookie,
    decrypt_cookie,
    check_is_admin
)


def test_encrypt_userdata_sandwiches_userdata():
    """The first function should take an arbitrary input string, prepend
    the string:

    "comment1=cooking%20MCs;userdata="

    .. and append the string:

    ";comment2=%20like%20a%20pound%20of%20bacon"
    """
    userdata = 'foobarbaz'
    expected = "comment1=cooking%20MCs;userdata=" +\
        userdata +\
        ";comment2=%20like%20a%20pound%20of%20bacon"

    assert(expected == sandwich_userdata(userdata))


def test_clean_str_removes_equals():
    """The function should quote out the ";" and "=" characters."""
    data = '='
    assert('' == clean_str(data, remove='='))


def test_clean_str_removes_semi_colon():
    """The function should quote out the ";" and "=" characters."""
    data = ';'
    assert('' == clean_str(data, remove=';'))


def test_can_encrypt_cookie():
    """The function should pad out the input to the 16-byte AES block
    length and encrypt it under the random AES key."""
    expected = (
        'IIh8YdSwD6cJcPBngx/XmZ/F7glpAQJ5bSnAzkJ4vlBB3m7lgLN87ozpN1ObbEKsjgaaj'
        'ObrrvEe\nQcRnVOBBVmcc6tlpE1n6ELdJlz0OfoVtNjGY96GGF+pcES+GCFIw\n'
    )
    encrypted_cookie = encrypt_cookie('userdata1')
    assert(encrypted_cookie.encode('base64') == expected)


def test_can_decrypt_cookie():
    """Check that we can decrypt the cookies correctly and get the
    userdata back out."""
    encrypted_cookie = (
        'IIh8YdSwD6cJcPBngx/XmZ/F7glpAQJ5bSnAzkJ4vlBB3m7lgLN87ozpN1ObbEKsjgaaj'
        'ObrrvEe\nQcRnVOBBVmcc6tlpE1n6ELdJlz0OfoVtNjGY96GGF+pcES+GCFIw\n'
    )
    expected = (
        'comment1=cooking%20MCs;'
        'userdata=userdata1;'
        'comment2=%20like%20a%20pound%20of%20bacon'
    )
    decrypted_cookie = decrypt_cookie(encrypted_cookie.decode('base64'))
    assert(decrypted_cookie == expected)


def test_cookie_check_isadmin_true():
    """Check if the string ';admin=true; exitst in our cookie/ The user is
    an admin."""
    cookie = (
        'comment1=cooking%20MCs;'
        'admin=true;'
        'comment2=%20like%20a%20pound%20of%20bacon'
    )
    result = check_is_admin(cookie)
    assert(result)


def test_cookie_check_isadmin_false():
    """Check if the string ';admin=true; exitst in our cookie/ The user is
    an admin."""
    cookie = (
        'comment1=cooking%20MCs;'
        'admin=no;'
        'comment2=%20like%20a%20pound%20of%20bacon'
    )
    result = check_is_admin(cookie)
    assert(not result)
