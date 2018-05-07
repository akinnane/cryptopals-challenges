import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
r = """An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen
randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
under CBC the other half (just use random IVs each time for CBC). Use
rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You
should end up with a piece of code that, pointed at a block box that
might be encrypting ECB or CBC, tells you which one is happening.
"""

BLOCKSIZE = 16

def random_bytes(size):
    return ''.join(
        chr(c)
        for c in bytearray(os.urandom(size))
    )

def random_int(start, end):
    return ord(random_bytes(1)) % (end - start + 1) + start


def pkcs7_pad(string, blocksize=BLOCKSIZE):
    padding = blocksize - (len(string) % blocksize)
    return string + (chr(padding) * padding)


def pkcs7_unpad(string, blocksize=BLOCKSIZE):
    return string[:-ord(string[-1])]


def xor(c, k):
    k = (k * -(-len(c) / len(k)))[:len(c)]
    return ''.join(
        chr(ord(a) ^ ord(b))
        for (a, b) in zip(c, k)
    )


def slice_array(arr, size):
    return [
        arr[i:i + size]
        for i in range(0, len(arr), size)
    ]


def aes_cbc_encrypt(key, pt, iv, blocksize=BLOCKSIZE, padder=pkcs7_pad):
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    slices = slice_array(padder(pt), blocksize)
    ct = []
    for i, s in enumerate(slices):
        encryptor = cipher.encryptor()
        ct.append(
            encryptor.update(xor(s, iv)) + encryptor.finalize()
        )
        iv = ct[-1]
    return ''.join(ct)


def aes_cbc_decrypt(key, ct, iv, blocksize=BLOCKSIZE, unpadder=pkcs7_unpad):
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


def aes_ecb_encrypt(key, pt, padder=pkcs7_pad):
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padder(pt)) + encryptor.finalize()


def aes_ecb_decrypt(key, pt, unpadder=pkcs7_unpad):
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return unpadder(decryptor.update(pt) + decryptor.finalize())


def encryption_oracle(string):
    key = random_bytes(16)
    pt = random_bytes(random_int(5, 10)) + string + random_bytes(random_int(5, 10))
    if random_int(0, 1):
        ct = aes_cbc_encrypt(key, pt, iv=random_bytes(16))
    else:
        ct = aes_ecb_encrypt(key, pt)
    return ct


def detect_aes_ecb(ct):
    slices = slice_array(ct, 16)
    print slices
    return bool([True for s in slices if slices.count(s) > 1])


ct = encryption_oracle('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
print detect_aes_ecb(ct)
