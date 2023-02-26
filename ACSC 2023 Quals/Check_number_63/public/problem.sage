from Crypto.Util.number import *
import gmpy2
from flag import *

f = open("output.txt","w")
f.write(f"n = {n}\n")

while e < 66173:
  d = inverse(e,(p-1)*(q-1))
  check_number = (e*d - 1) // ( (p-1)*(q-1) )
  f.write(f"{e}:{check_number}\n")
  assert (e*d - 1) % ( (p-1)*(q-1) ) == 0
  e = gmpy2.next_prime(e)
  
f.close()
