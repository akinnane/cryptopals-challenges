from cryptopals.challenges.c13_ecb_cut_and_paste import (
    profile_for,
    encode_profile,
    ProfileCrypt
)
from cryptopals.crypto import (
    aes_ecb_decrypt
)
from cryptopals.url import (
    encode_query
)

def test_profile_for():
    email = 'aaa@bbb.com'
    e = {
        'email': 'aaa@bbb.com',
        'uid': '10',
        'role': 'user'
    }

    assert(e == profile_for(email))


def test_must_not_let_admin_set_role_to_admin():
    email = 'foo@bar.com&role=admin'

    r = encode_query(
        profile_for(email)
    )

    e = 'role=user&email=foo@bar.com&role=admin&uid=10'

    assert(e != r)
    assert(2 == r.count('&'))
    assert(3 == r.count('='))


def test_ProfileCrypt_generates_random_keys():
    pc1 = ProfileCrypt()
    pc2 = ProfileCrypt()

    assert(pc1.key != pc2.key)


def test_ProfileCrypt_encypts_correctly():
    profile = profile_for('foo@bar.com')
    pc1 = ProfileCrypt(profile)
    e = encode_profile(profile)
    r = aes_ecb_decrypt(
            pc1.key,
            pc1.encrypt()
    )

    assert(e == r)

def test_ProfileCrypt_decrypts_correctly():
    profile = profile_for('foo@bar.com')
    pc1 = ProfileCrypt(profile)
    r = pc1.decrypt(
            pc1.encrypt()
    )

    assert(profile == r)

def test_profile_encoding():
    profile = profile_for('foo@bar.com')
    e = 'role=user&email=foo@bar.com&uid=10'
    r = encode_query(profile)
    assert(e == r)
