#!/bin/usr/env python3

from os import urandom
from Crypto.Cipher import AES
import string

cts = []

alphabet = string.ascii_uppercase + "{ }"


with open("output.txt", "r") as f:
	for _ in range(1479):
		cts.append(f.readline())

syms = []
txt = []
for ct in cts:
	txt.append(bytes.fromhex(ct[:2]))
	if bytes.fromhex(ct[:2]) not in syms:
		syms.append(bytes.fromhex(ct[:2]))

message = ''
for ch in txt:
	message += alphabet[syms.index(ch)]

print(message)

