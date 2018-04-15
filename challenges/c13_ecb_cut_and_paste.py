from cryptopals.crypto import (
    aes_ecb_encrypt,
    aes_ecb_decrypt
)
from cryptopals.random import (
    random_bytes
)
from cryptopals.url import (
    encode_query,
    decode_query
)
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('c13_ecb_cut_and_paste')
"""
# ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The
routine should take:

`foo=bar&baz=qux&zap=zazzle`

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given
an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters
(& and =). Eat them, quote them, whatever you want to do, but don't
let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to
    the "attacker".

    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate
"valid" ciphertexts) and the ciphertexts themselves, make a role=admin
profile.

"""


def profile_for(email):
    """Creates a user profile dict.

    :param email: The email address to use in the profile
    :returns: the user profile
    :rtype: dict

    """
    return {
        'email': email,
        'uid': '10',
        'role': 'user'
    }


def encode_profile(profile):
    """Encode the profile so the order of the keys is fixed to email, uid, role

    :param profile: The profile to encode
    :returns: The profile query string
    :rtype: str

    """

    query = []
    for i in ['email', 'uid', 'role']:
        query.append(encode_query({i: profile[i]}))
    return '&'.join(query)


class ProfileCrypt():
    """A class to encrypt object profiles.
    It will generate use the same key for the objects lifespan. """

    def __init__(self, profile=None):
        """Take no arguments

        :param profile: A profile to work on
        :returns: a
        :rtype: ProfileCrypt

        """
        self.key = random_bytes(16)
        self.profile = profile

    def encrypt(self, profile=None):
        """Takes a profileand encrypts it

        :param profile: A dict to profile to encrypt
        :returns: encrypt data
        :rtype: str

        """
        profile_query = encode_profile(profile if profile else self.profile)
        self.encrypted_profile = aes_ecb_encrypt(
            self.key,
            profile_query
        )
        return self.encrypted_profile

    def decrypt(self, encrypted_query):
        """Takes a profile and decrypts it

        :param profile: profile to encrypt
        :returns: encrypt data
        :rtype: str

        """
        decrypted_query = aes_ecb_decrypt(
            self.key,
            encrypted_query
        )
        profile = decode_query(decrypted_query)
        return profile
