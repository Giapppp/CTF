#!/bin/usr/env sage
"""
This challenge uses matrix in GL(30, Z2) with small order, and it works like RSA
We have matE = mat ^ E, so we need to find D such that DE = 1 mod ord(C) which C = GL(30, Z2)
Find D and we done!
"""

P = 2
N = 50
E = 31337

def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    bits = [int(c) for c in bin_str]
    return bits

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)
        msg += [random.randint(0, 1) for _ in range(N*N - len(msg))]
        rows = [msg[i::N] for i in range(N)]
        mat = Matrix(GF(2), rows)
        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            return mat         

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

matE = load_matrix("flag.enc") # matE = mat ^ E
n = matE.multiplicative_order()
# gcd(n, E) = 1

d = pow(E, -1, n)
mat = matE ^ d
bits_string = []
for i in range(50):
	bits_string += [mat[j][i] for j in range(50)]

temp = ""
for j in range(0, 50*50 - 4, 8):
	for c in bits_string[j:j+8]:
		temp += str(c)
	num = int(temp, 2)
	print(chr(num), end = "")
	temp = ""
