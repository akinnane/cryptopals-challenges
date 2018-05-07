"""Fixed XOR

Write a function that takes two equal-length buffers and produces
their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179

"""

input_string_1 = r'1c0111001f010100061a024b53535009181c'
input_string_2 = r'686974207468652062756c6c277320657965'
expected_output = r'746865206b696420646f6e277420706c6179'

result = ''.join(
    [
        chr(ord(a) ^ ord(b))
        for (a, b) in zip(
                input_string_1.decode('hex'),
                input_string_2.decode('hex')
        )
    ]
).encode('hex')
print expected_output
print result
