from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
import math
import hashlib

Point = namedtuple("Point", "x y")
O = 'Origin'

#Point
def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P: tuple, Q: tuple):
    # based of algo. in ICM
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P: tuple, n: int):
    # based of algo. in ICM
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R

def gen_shared_secret(Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = double_and_add(Q, n)
    return S.x

#Curve
p = 310717010502520989590157367261876774703
a = 2
b = 3

# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = Point(g_x, g_y)

# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = Point(b_x, b_y)

data ={'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}
x = 280810182131414898730378982766101210916
y = 291506490768054478159835604632710368904
P = Point(x, y)

"""
You can use sagemath to find n, this is a very powerful tool !!!
Code in Sagemath:

#!/bin/usr/env sage
M = 310717010502520989590157367261876774703
A = 2
B = 3

F = GF(M)
E = EllipticCurve(F, [A, B])

x = 280810182131414898730378982766101210916
y = 291506490768054478159835604632710368904
P = E(x, y)

g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = E(g_x, g_y)

print(discrete_log(P, G, G.order(), operation='+'))
"""

n = 47836431801801373761601790722388100620

iv = data['iv']
encrypted_flag = data['encrypted_flag']

shared_secret = gen_shared_secret(B, n)

def decrypt_flag(shared_secret: int, iv, ciphertext):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    iv = bytes.fromhex(iv)
    ciphertext = bytes.fromhex(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

print(decrypt_flag(shared_secret, iv, encrypted_flag))

#flag: crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}





















