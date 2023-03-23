#!/bin/usr/env python3
"""
If we read the source code carefully, we can write the encrypt function in source code in a mathematically way:

c[i] = m[i] ^ E(c[i-1]) if i >= 1
c[1] = m[1] ^ E(IV)

with the unstanding that m[i], c[i] is the i+1 part of message and ciphertext, and they have 16-bytes (The message and the ciphertext are splited to 16-bytes block)

Because we have E(c[3]) and E(c[4]), so we get m[4] and m[5], and because message is flag which is repeated 4 times, we can find the flag and done!
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random, os

FLAG = b'HTB{??????????????????????}'

def xor(a, b):
	return b''.join([bytes([_a ^ _b]) for _a, _b in zip(a, b)])
	
ct = 'bc9bc77a809b7f618522d36ef7765e1cad359eef39f0eaa5dc5d85f3ab249e788c9bc36e11d72eee281d1a645027bd96a363c0e24efc6b5caa552b2df4979a5ad41e405576d415a5272ba730e27c593eb2c725031a52b7aa92df4c4e26f116c631630b5d23f11775804a688e5e4d5624'
r = 3
phrases = ['8b6973611d8b62941043f85cd1483244', 'cf8f71416111f1e8cdee791151c222ad']

blocks = [bytes.fromhex(ct[i:i+32]) for i in range(0, len(ct), 32)]
phrases = [bytes.fromhex(phrase) for phrase in phrases]

m4 = xor(blocks[4], phrases[0])
m5 = xor(blocks[5], phrases[1])
print(m4 + m5)
