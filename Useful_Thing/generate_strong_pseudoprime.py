#Link: https://gist.github.com/keltecc/b5fbd533d2f203e810b43c26ff9d17cc

########################################################################

#!/usr/bin/env sage

# François Arnault. 1995. Constructing Carmichael Numbers which are Strong Pseudoprimes to Several Bases
# https://doi.org/10.1006/jsco.1995.1042


from sys import stderr
from random import choice, getrandbits


def miller_rabin(bases, n):
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    ZmodN = Zmod(n)

    for b in map(ZmodN, bases):
        x = b ^ s
        if x == 1 or x == -1:
            continue
        for _ in range(r - 1):
            x = x ^ 2
            if x == -1:
                break
        else:
            return False
    
    return True


def search_pseudoprime(bases, coeffs, rlen, iters, verbose=False):
    modules = [4 * b for b in bases]

    residues = dict()

    for b, m in zip(bases, modules):
        residues[b] = set()
        for p in primes(3, 1024 * max(bases)):
            if kronecker(b, p) == -1:
                residues[b].add(p % m)

    sets = dict()

    for b, m in zip(bases, modules):
        s = []
        for c in coeffs:
            s.append({(inverse_mod(c, m) * (r + c - 1)) % m for r in residues[b]})
        sets[b] = list(set.intersection(*s))

    # only support this
    assert len(coeffs) == 3

    coeffs_inv = [
        1, 
        coeffs[1] - inverse_mod(coeffs[2], coeffs[1]), 
        coeffs[2] - inverse_mod(coeffs[1], coeffs[2])
    ]

    mod = lcm(modules + coeffs)

    while True:
        choices = [choice(sets[b]) for b in bases]

        rem = crt(
            choices + coeffs_inv,
            bases + coeffs
        )

        if verbose:
            print(f'[*] Searching pseudoprime...', file=stderr)

        for i in range(iters):
            if verbose and i % 10000 == 0:
                print(f'{i}...')

            p1 = getrandbits(rlen) * mod + rem
            p2 = (p1 - 1) * coeffs[1] + 1
            p3 = (p1 - 1) * coeffs[2] + 1

            pprime = p1 * p2 * p3
            
            if miller_rabin(bases, pprime):
                break
        else:
            if verbose:
                print(f'[-] Failed to find pseudoprime, trying with another choices...', file=stderr)
            
            continue

        if verbose:
            print(f'[+] Found pseudoprime!', file=stderr)
            print(f'[+] P = {pprime}', file=stderr)

        return pprime, [p1, p2, p3]

 def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5)+1, 2):
        if basis[i]:
            basis[i*i::2*i] = [False]*((n-i*i-1)//(2*i)+1)
    return [2] + [i for i in range(3, n, 2) if basis[i]]
  
if __name__ == '__main__':
    rlen = 256
    iters = 30000
    verbose = True

    bases = list(primes(300))
    coeffs = [1, 313, 353]

    pprime, divisors = search_pseudoprime(bases, coeffs, rlen, iters, verbose)
    
    assert not is_prime(pprime) and \
           miller_rabin(bases, pprime)
