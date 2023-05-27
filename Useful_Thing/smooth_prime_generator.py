#When we need to solve a discrete log problem and can fix the prime, a smooth prime will be a better choice

from Crypto.Util.number import *
import gmpy2
import random
original_P = getPrime(1024)

primes = [2]
for i in range(1000):
    primes.append(int(gmpy2.next_prime(primes[-1])))
primes=primes[100:]  #keep just big primes

# generate a weak prime (P) such that P>original_P
while True:
    N = 2
    factors=[]
    while (N<original_P):  
        prime=random.choice(primes)
        if prime not in factors:
            factors.append(prime)
            N*=prime
    if gmpy2.is_prime(N+1):
        break
P=N+1  
print(P)
