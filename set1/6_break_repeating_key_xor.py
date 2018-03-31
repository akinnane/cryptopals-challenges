import itertools
from joblib import (Parallel, delayed)

"""
Break repeating-key XOR

It is officially on, now.
This challenge isn't conceptually hard, but it involves actual
error-prone coding. The other challenges in this set are there to
bring you up to speed. This one is there to qualify you. If you can do
this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with
repeating-key XOR.

Decrypt it.

Here's how:

    1. Let KEYSIZE be the guessed length of the key; try values from 2
    to (say) 40.

    2. Write a function to compute the edit distance/Hamming distance
    between two strings. The Hamming distance is just the number of
    differing bits. The distance between:

    `this is a test`

    and

    `wokka wokka!!!`

    is *37*. Make sure your code agrees before you proceed.

    3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and
    the second KEYSIZE worth of bytes, and find the edit distance
    between them. Normalize this result by dividing by KEYSIZE.

    4. The KEYSIZE with the smallest normalized edit distance is
    probably the key. You could proceed perhaps with the smallest 2-3
    KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average
    the distances.


    5.Now that you probably know the KEYSIZE: break the ciphertext
    into blocks of KEYSIZE length.

    6. Now transpose the blocks: make a block that is the first byte
    of every block, and a block that is the second byte of every
    block, and so on.

    7. Solve each block as if it was single-character XOR. You already
    have code to do this.

    8. For each block, the single-byte XOR key that produces the best
    looking histogram is the repeating-key XOR key byte for that
    block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later
on. Breaking repeating-key XOR ("Vigenere") statistically is obviously
an academic exercise, a "Crypto 101" thing. But more people "know how"
to break it than can actually break it, and a similar technique breaks
something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the
other ones. We promise, there aren't any blatant errors in this
text. In particular: the "wokka wokka!!!" edit distance really is 37.
"""

file_text = """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
"""

file_text = file_text.translate(None, '\n').decode('base64')


letter_freq = {
    'a': 	8.167,
    'b': 	1.492,
    'c': 	2.782,
    'd': 	4.253,
    'e':       12.702,
    'f': 	2.228,
    'g': 	2.015,
    'h': 	6.094,
    'i': 	6.966,
    'j': 	0.153,
    'k': 	0.772,
    'l': 	4.025,
    'm': 	2.406,
    'n': 	6.749,
    'o': 	7.507,
    'p': 	1.929,
    'q': 	0.095,
    'r': 	5.987,
    's': 	6.327,
    't': 	9.056,
    'u': 	2.758,
    'v': 	0.978,
    'w': 	2.360,
    'x': 	0.150,
    'y': 	1.974,
    'z': 	0.074,
    ' ':       17.162,
}


def xor(c, k):
    k = (k * -(-len(c) / len(k)))[:len(c)]
    return ''.join(
            chr(ord(a) ^ ord(b))
            for (a, b) in zip(c, k)
    )


def hamming_length(a, b):
    return ''.join(
        format(x, '08b')
        for x in bytearray(xor(a, b))
    ).count('1')


def calc_keysize(keysize):
    slices = list(set([
        file_text[i:i+keysize]
        for i in range(0, len(file_text), keysize)
    ]))
    hamming_lengths = [
        hamming_length(i[0], i[1]) / (keysize + 0.0)
        for i in itertools.permutations(slices, 2)
    ]
    hamming_score = reduce(
        lambda x, y: x + y, hamming_lengths,
        0
    ) / (len(hamming_lengths) + 0.0)
    results = [keysize, hamming_score]
    return results


def score(string):
    return sum(
        letter_freq.get(char, -5)
        for char in string.lower()
    )


def find_max_score(arr):
    return max(arr, key=lambda x: score(x[0]))


def decrypt_single_key_xor(c, keys=range(0, 255)):
    return find_max_score(
            (xor(c, chr(i)), i)
            for i in keys
        )


def find_keys_for_length(length):
    slices = list(set([
        file_text[i:i+keysize]
        for i in range(0, len(file_text), keysize)
    ]))
    transpose = [
        ''.join(list(x))
        for x in itertools.izip_longest(*slices, fillvalue=chr(0))
    ]
    key = [
        decrypt_single_key_xor(t)[1]
        for t in transpose
    ]
    return ''.join([chr(c) for c in key])


print '[*] Finding key sizes'
results = Parallel(n_jobs=-1)(
    delayed(calc_keysize)(keysize) for keysize in range(2, 50)
)

top_keysizes = [
    result[0]
    for result in sorted(results, key=lambda x: x[1])
][:5]

print '[*] Top key sizes: %s' % ', '.join(str(i) for i in top_keysizes)

print '[*] Brute forcing keys...'
top_keys = [
    find_keys_for_length(keysize)
    for keysize in top_keysizes
]

print '[*] Top keys are: "%s"' % '", "'.join(top_keys)

text = max(
    [
        xor(file_text, k)
        for k in top_keys
    ],
    key=score
)

print '[+] Decrypted text is: \n', text
print '[+] Key is: "%s"' % ''.join(top_keys[0])
