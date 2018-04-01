import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
"""Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers
under ECB mode using a consistent but unknown key (for instance,
assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext,
BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the
string by hand; make your code do it. The point is that you don't know
its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to
the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time
    --- start with 1 byte ("A"), then "AA", then "AAA" and so
    on. Discover the block size of the cipher. You know it, but do
    this step anyway.

    Detect that the function is using ECB. You already know, but do
    this step anyways.

    Knowing the block size, craft an input block that is exactly 1
    byte short (for instance, if the block size is 8 bytes, make
    "AAAAAAA"). Think about what the oracle function is going to put
    in that last byte position.

    Make a dictionary of every possible last byte by feeding different
    strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
    "AAAAAAAC", remembering the first block of each invocation.

    Match the output of the one-byte-short input to one of the entries
    in your dictionary. You've now discovered the first byte of
    unknown-string.

    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break
real crypto. Lots of people know that when you encrypt something in
ECB mode, you can see penguins through it. Not so many of them can
decrypt the contents of those ciphertexts, and now you can. If our
experience is any guideline, this attack will get you code execution
in security tests about once a year.
"""

text = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

TEXT = text.translate(None, '\n').decode('base64')

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


def slice_array(arr, size):
    return [
        arr[i:i + size]
        for i in range(0, len(arr), size)
    ]


def aes_ecb_encrypt(key, pt, padder=pkcs7_pad):
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padder(pt)) + encryptor.finalize()


KEY = random_bytes(16)


def encryption_oracle(pt, key=KEY):
    pt += TEXT
    return aes_ecb_encrypt(key, pt)


def detect_block_size(cts):
    cts = sorted(list(set(len(c) for c in cts)))
    return list(
        set(
            cts[i] - cts[i-1]
            for i in range(1, len(cts))
        )
    )[0]


def detect_aes_ecb(ct):
    slices = slice_array(ct, 16)
    return bool([True for s in slices if slices.count(s) > 1])


def oracle_result(string, secret_size):
    return encryption_oracle(string)[:secret_size]


def guess_last_byte(key, secret_size):
    d = {}
    for i in range(0, 255):
        r = oracle_result(
            (key + chr(i)).rjust(secret_size, chr(0)),
            secret_size
            )
        d[r] = chr(i)
    return d


results = [
    encryption_oracle('A' * i)
    for i in range(0, 200)
]

ecb = [
    detect_aes_ecb(c)
    for c in results
]

block_size = detect_block_size(results)
is_ecb = ((ecb.count(True) + 0.0) / len(ecb) * 100)
secret_size = block_size * -(-len(min(results)) / block_size)

print '[+] Block size: %i' % block_size
print '[+] ECB detected: %.02f%%' % is_ecb
print '[+] Secret text size: %s' % secret_size

recovered_text = ''

for i in range(1, secret_size):

    payload = ''.rjust(secret_size - i, chr(0))

    oracle = oracle_result(payload, secret_size)

    guesses = guess_last_byte(recovered_text, secret_size)

    try:
        recovered_text += guesses[oracle]
    except KeyError:
        recovered_text = recovered_text[:-1]
        break

print '[+] Secret text:\n%s' % recovered_text
