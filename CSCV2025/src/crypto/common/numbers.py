import random
import hashlib
import gmpy2


def jacobi_symbol(a: int, n: int) -> int:
    """Computes the Jacobi symbol (a/n)."""
    return gmpy2.jacobi(a, n)


def sample_invertible_with_neg_jacobi(n: int) -> int:
    """
    Samples a random integer 'w' in [1, n-1] such that its Jacobi
    symbol (w/n) is -1.
    """
    while True:
        w = random.randrange(1, n)
        if jacobi_symbol(w, n) == -1:
            return w


def is_quadratic_residue(x: int, n: int) -> bool:
    """
    Checks if x is a quadratic residue modulo n using the Jacobi symbol.
    """
    return jacobi_symbol(x, n) == 1


def is_in_interval(x: int, bound: int) -> bool:
    """Checks if x is in the interval [0, bound)."""
    return 0 <= x < bound


def check_invertible_and_valid_mod(modulus: int, *vals: int) -> bool:
    """
    Checks if all provided values are in the range (0, modulus) and are
    relatively prime to the modulus.
    """
    for v in vals:
        if not (0 < v < modulus):
            return False
        if gmpy2.gcd(v, modulus) != 1:
            return False
    return True


def rejection_sample(modulus: int, h: int) -> int:
    """
    Generates a uniformly random integer in [0, modulus-1] from a seed 'h'.
    """
    r = 0
    i = 0
    while r < modulus:
        inb = str(h + i).encode()
        r = (r << 256) | int.from_bytes(hashlib.sha256(inb).digest(), "big")
        i += 1
    return r % modulus
