"""
Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
Achievement Unlocked

You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

"""

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

from itertools import izip_longest

def xor(c, k):
    return ''.join(
        [
            chr(ord(a) ^ ord(b))
            for (a, b) in izip_longest(c, k, fillvalue=k)
        ]
    )

def score(string):
    score = 0 
    for char in string.lower():
        try:
            score += letter_freq.get(char, 0)
        except:
            score += 0
    return score
    

c = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

results = [
    xor(c.decode('hex'), chr(i))
    for i in range(0, 255)
]

print max(results, key=score)
