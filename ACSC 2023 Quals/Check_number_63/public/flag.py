from Crypto.Util.number import *
from hashlib import sha512

p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
e = 65537
d = inverse(e,(p-1)*(q-1))

if p > q:p,q = q,p
flag = "ACSC{" + sha512( f"{p}{q}".encode() ).hexdigest() + "}" 
open("flag","w").write(flag)
open("key","w").write(str(p) + "\n" + str(q))
