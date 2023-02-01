#resource: https://crypto.stackexchange.com/questions/3840/a-discrete-log-like-problem-with-matrices-given-ak-x-find-k

#!/bin/usr/env sage

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad

import json
p = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row.split(' '))) for row in data.splitlines()]
    return Matrix(GF(p), rows)

output = json.loads(open('output.txt').read())
v = vector(output['v'])
w = vector(output['w'])

G = load_matrix('generator.txt')
evs_G = G.eigenvalues()
J,P = G.jordan_form(transformation=True)

v_ = (P.inverse()) * v
w_ = (P.inverse()) * w

x1 = v_[28]
x2 = v_[29]
y1 = w_[28]
y2 = w_[29]
lamd = evs_G[29]

SECRET = ((lamd * (y1*x2 - y2*x1))*pow(y2*x2, -1, p))%p


KEY_LENGTH = 128
KEY = SHA256.new(data=str(SECRET).encode()).digest()[:KEY_LENGTH]
iv = bytes.fromhex("334b1ceb2ce0d1bef2af9937cf82aad6")
ct = bytes.fromhex("543e29415bdb1f694a705b2532a5beb7ebd7009591503ef3c4fbcebf9e62fe91307e5d98efcd49f9f3b1985956cafc89")
cipher = AES.new(KEY, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
print(pt)
