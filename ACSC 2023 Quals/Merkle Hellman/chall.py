#!/usr/bin/env python3
import random
import binascii

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

def gcd(a, b): 
	if a == 0: 
		return b 
	return gcd(b % a, a) 

flag = open("flag.txt","rb").read()
# Generate superincreasing sequence
w = [random.randint(1,256)]
s = w[0]
for i in range(6):
	num = random.randint(s+1,s+256)
	w.append(num)
	s += num

# Generate private key
total = sum(w)
q = random.randint(total+1,total+256)
r = 0
while gcd(r,q) != 1:
	r = random.randint(100, q)

# Calculate public key
b = []
for i in w:
	b.append((i * r) % q)

# Encrypting
c = []
for f in flag:
	s = 0
	for i in range(7):
		if f & (64>>i):
			s += b[i]
	c.append(s)

print(f"Public Key = {b}")
print(f"Private Key = {w,q}")
print(f"Ciphertext = {c}")

# Output:
# Public Key = [7352, 2356, 7579, 19235, 1944, 14029, 1084]
# Private Key = ([184, 332, 713, 1255, 2688, 5243, 10448], 20910)
# Ciphertext = [8436, 22465, 30044, 22465, 51635, 10380, 11879, 50551, 35250, 51223, 14931, 25048, 7352, 50551, 37606, 39550]
