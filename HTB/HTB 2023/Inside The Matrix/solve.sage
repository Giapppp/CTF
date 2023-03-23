#!/bin/usr/env sage
import string

#We need to find matrix ciphertext and matrix key which in GF(61) - the biggest prime in range(2**4, 2**6), because this will make all calculation after become easier
c = [(0, 29, 36, 30, 30), (38, 51, 17, 10, 19), (48, 1, 4, 50, 36), (27, 14, 47, 48, 58), (58, 56, 22, 6, 29)]
key = [(47, 29, 33, 4, 10), (10, 54, 38, 35, 59), (41, 20, 7, 7, 31), (6, 14, 20, 22, 43), (51, 13, 20, 19, 34)]

primes = [61]
alphabet = string.ascii_letters + string.digits + '{_}'

flags = []
"""
We have:

ciphertext = plaintext * key

where ciphertext and key are matrices in GF(61). This is an easy equation in linear algebra, so we have

plaintext = ciphertext * key.inverse()
"""
for prime in primes:
	try:
		ciphertext = Matrix(GF(prime), c)
		key = Matrix(GF(prime), key)
		plaintext_guess = ciphertext * key.inverse()
		flags.append(plaintext_guess.list())
		print(prime)
	except ValueError:
		continue

messages = []

"""
Because every character in messages are in GF(61) so some characters are wrong, and we need to plus these with 61 to find the correct message

You should run this code below in python, I don't know why sage run so slow with this code

###
for flag, prime in zip(flags, primes):
	for i in range(25):
		while (chr(flag[i]) not in alphabet) and (flag[i] < 127):
			flag[i] += prime
###

You can check the flag with this command: ''.join([ord(c) for c in flag[0]])
If you print the flag and some characters are not correct, you can plus these character with 61 to find the correct message, I think you need to try 10-15 times to get the correct one
#HTB{l00k_@t_7h3_st4rs!!!}
"""
