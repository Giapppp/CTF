"""
This module provides a Python implementation of the Paillier homomorphic
cryptosystem, optimized for performance using the gmpy2 library for all
large-integer arithmetic.
"""

from typing import List, Optional, Tuple, Union
import random
from Crypto.Util.number import getPrime
import gmpy2


# --- Custom Exceptions ---


class PaillierError(Exception):
    """Base exception for Paillier-related errors."""

    pass


class MessageTooLongError(PaillierError):
    """Raised when a message or ciphertext is out of its valid range."""

    pass


class MessageMalFormedError(PaillierError):
    """Raised when a message is malformed (e.g., not in [0, N-1])."""

    pass


class WrongRandomnessError(PaillierError):
    """Raised when provided randomness is cryptographically invalid."""

    pass


# --- Helper Functions ---


def get_random_positive_relatively_prime_int(n: gmpy2.mpz) -> gmpy2.mpz:
    """Returns a random integer x where 0 < x < n and gcd(x, n) == 1."""
    while True:
        x = gmpy2.mpz(random.randrange(1, n))
        if gmpy2.gcd(x, n) == 1:
            return x


def generate_safe_prime(bits: int) -> int:
    """
    Generates a prime p of a given bit length suitable for Paillier.
    """
    while True:
        p = getPrime(bits)
        if p.bit_length() >= bits and p % 4 == 3:
            return p


# --- Core Classes ---


class PublicKey:
    """
    Represents the public part of a Paillier key pair, using gmpy2 for all
    large number arithmetic.
    """

    def __init__(self, n: Union[int, gmpy2.mpz]):
        # Store n as a gmpy2.mpz for optimized calculations.
        self.n: gmpy2.mpz = gmpy2.mpz(n)
        # Cache frequently used values.
        self._ns: Optional[gmpy2.mpz] = None
        self._ga: Optional[gmpy2.mpz] = None

    @property
    def n_square(self) -> gmpy2.mpz:
        """Returns N*N, cached for efficiency."""
        if self._ns is None:
            self._ns = self.n * self.n
        return self._ns

    @property
    def gamma(self) -> gmpy2.mpz:
        """Returns N+1, cached for efficiency."""
        if self._ga is None:
            self._ga = self.n + 1
        return self._ga

    def encrypt_and_return_randomness(self, m: int) -> Tuple[int, int]:
        """Encrypts a message and returns the ciphertext and randomness used."""
        if not (0 <= m < self.n):
            raise MessageMalFormedError("Message must be in the range [0, N-1]")

        x = get_random_positive_relatively_prime_int(self.n)

        gm = gmpy2.powmod(self.gamma, m, self.n_square)
        xn = gmpy2.powmod(x, self.n, self.n_square)

        # Uses gmpy2's fast, overloaded operators for modular multiplication.
        c = (gm * xn) % self.n_square
        return int(c), int(x)

    def encrypt(self, m: int) -> int:
        """Encrypts a message, discarding the randomness."""
        c, _ = self.encrypt_and_return_randomness(m)
        return c

    def encrypt_with_randomness(self, m: int, x: int) -> int:
        """Encrypts a message using a specified random value `x`."""
        if not (0 <= m < self.n):
            raise MessageMalFormedError("Message must be in the range [0, N-1]")
        x_mpz = gmpy2.mpz(x)
        if not (0 < x_mpz < self.n and gmpy2.gcd(x_mpz, self.n) == 1):
            raise WrongRandomnessError(
                "Randomness must be a positive integer relatively prime to N"
            )

        gm = gmpy2.powmod(self.gamma, m, self.n_square)
        xn = gmpy2.powmod(x_mpz, self.n, self.n_square)

        c = (gm * xn) % self.n_square
        return int(c)

    def homo_mult(self, m: int, c1: int) -> int:
        """Homomorphically multiplies a ciphertext by a plaintext scalar."""
        if not (0 <= m < self.n):
            raise MessageMalFormedError("Scalar must be in the range [0, N-1]")
        if not (0 <= c1 < self.n_square):
            raise MessageTooLongError("Ciphertext must be in the range [0, N^2-1]")
        c = gmpy2.powmod(c1, m, self.n_square)
        return int(c)

    def homo_mult_obfuscate(self, m: int, c1: int) -> Tuple[int, int]:
        """
        Homomorphically multiplies a ciphertext by a plaintext scalar and then
        re-randomizes the result to prevent analysis.
        """
        c2 = gmpy2.powmod(c1, m, self.n_square)
        x = get_random_positive_relatively_prime_int(self.n)
        xn = gmpy2.powmod(x, self.n, self.n_square)

        c2 = (c2 * xn) % self.n_square
        return int(c2), int(x)

    def homo_add(self, c1: int, c2: int) -> int:
        """Homomorphically adds two ciphertexts."""
        if not (0 <= c1 < self.n_square) or not (0 <= c2 < self.n_square):
            raise MessageMalFormedError("Ciphertexts must be in the range [0, N^2-1]")

        c = (gmpy2.mpz(c1) * gmpy2.mpz(c2)) % self.n_square
        return int(c)

    def as_ints(self) -> List[int]:
        """Serializes the PublicKey to a list of integers for hashing."""
        return [int(self.n), int(self.gamma)]


class PrivateKey(PublicKey):
    """
    Represents a Paillier private key, which includes all public key
    components through inheritance.
    """

    def __init__(
        self,
        n: Union[int, gmpy2.mpz],
        lambda_n: Union[int, gmpy2.mpz],
        phi_n: Union[int, gmpy2.mpz],
    ):
        super().__init__(n)
        self.lambda_n: gmpy2.mpz = gmpy2.mpz(lambda_n)
        self.phi_n: gmpy2.mpz = gmpy2.mpz(phi_n)
        self._lg_inv: Optional[gmpy2.mpz] = None

    def _L(self, u: gmpy2.mpz) -> gmpy2.mpz:
        """Implements the Paillier L function: L(u) = (u - 1) // N."""
        return (u - 1) // self.n

    def decrypt(self, c: int) -> int:
        """Decrypts a ciphertext, returning a standard Python int."""
        m_mpz = self._decrypt_mpz(gmpy2.mpz(c))
        return int(m_mpz)

    def _decrypt_mpz(self, c: gmpy2.mpz) -> gmpy2.mpz:
        """Internal decryption method that returns a gmpy2.mpz object."""
        if not (0 <= c < self.n_square and gmpy2.gcd(c, self.n_square) == 1):
            raise MessageMalFormedError(
                "Ciphertext is mal-formed or not relatively prime to N^2"
            )

        c_pow_lambda = gmpy2.powmod(c, self.lambda_n, self.n_square)
        lc = self._L(c_pow_lambda)

        if self._lg_inv is None:
            self.cache_lg_inv()

        m = (lc * self._lg_inv) % self.n
        return m

    def cache_lg_inv(self) -> bool:
        """Pre-computes and caches the modular inverse used in decryption."""
        if self._lg_inv is not None:
            return False

        g_pow_lambda = gmpy2.powmod(self.gamma, self.lambda_n, self.n_square)
        lg = self._L(g_pow_lambda)

        lg_inv = gmpy2.invert(lg, self.n)
        if lg_inv == 0:
            raise PaillierError("Could not compute modular inverse of L(g^lambda)")

        self._lg_inv = lg_inv
        return True

    def get_randomness(self, c: int) -> int:
        """Recovers the randomness `r` used to encrypt a ciphertext `c`."""
        c_mpz = gmpy2.mpz(c)
        m = self._decrypt_mpz(c_mpz)

        # We know c = g^m * r^n mod n^2. We solve for r.
        # Step 1: Isolate r^n.
        # c * g^(-m) = r^n mod n^2
        # Using binomial expansion, g^(-m) = (1+n)^(-m) ≡ 1 - m*n (mod n^2).
        term = gmpy2.sub(1, gmpy2.mul(m, self.n))
        c0 = (c_mpz * term) % self.n_square

        # Step 2: Find the n-th root of c0.
        # r = c0^(n^-1 mod phi(n)) mod n
        niv = gmpy2.invert(self.n, self.phi_n)
        if niv == 0:
            raise PaillierError("Could not compute modular inverse of N mod Phi(N)")

        r = gmpy2.powmod(c0, niv, self.n)
        return int(r)


# --- Key Generation ---


def generate_key_pair(modulus_bit_len: int) -> Tuple[PrivateKey, PublicKey, int, int]:
    """
    Generates a Paillier key pair.

    Returns:
        A tuple of (private_key, public_key, p, q), where p and q are the
        secret prime factors returned as standard Python integers.
    """
    prime_bits = modulus_bit_len // 2

    p_int = generate_safe_prime(prime_bits)
    q_int = generate_safe_prime(prime_bits)
    while p_int == q_int:
        q_int = generate_safe_prime(prime_bits)

    # Use gmpy2.mpz for fast intermediate calculations.
    p, q = gmpy2.mpz(p_int), gmpy2.mpz(q_int)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    # lambda is the Carmichael function, lcm(p-1, q-1) for n=pq.
    lambda_n = gmpy2.lcm(p - 1, q - 1)

    private_key = PrivateKey(n, lambda_n, phi_n)
    public_key = PublicKey(n)

    return private_key, public_key, p_int, q_int


# --- Example Usage ---

if __name__ == "__main__":
    print("Generating a 2048-bit Paillier key pair...")
    try:
        private_key, public_key, p, q = generate_key_pair(2048)
        print("Key pair generated successfully.")
        # Note: .bit_length() is a method on gmpy2.mpz objects.
        print(f"Public Key (N): {public_key.n.bit_length()}-bit")

        m1 = 123456789
        print(f"\nOriginal message 1: {m1}")
        c1 = public_key.encrypt(m1)
        print(f"Encrypted message 1 (ciphertext): {hex(c1)}")
        decrypted_m1 = private_key.decrypt(c1)
        print(f"Decrypted message 1: {decrypted_m1}")
        assert m1 == decrypted_m1

        m2 = 987654321
        print(f"\nOriginal message 2: {m2}")
        c2 = public_key.encrypt(m2)

        # Homomorphic property: Enc(m1) * Enc(m2) = Enc(m1 + m2)
        c_sum = public_key.homo_add(c1, c2)
        decrypted_sum = private_key.decrypt(c_sum)
        print(f"Homomorphic addition result (decrypted): {decrypted_sum}")
        print(f"Expected addition result: {m1 + m2}")
        assert (m1 + m2) == decrypted_sum

        scalar = 100
        print(f"\nPlaintext scalar: {scalar}")

        # Homomorphic property: Enc(m1)^scalar = Enc(m1 * scalar)
        c_prod = public_key.homo_mult(scalar, c1)
        decrypted_prod = private_key.decrypt(c_prod)
        print(f"Homomorphic multiplication result (decrypted): {decrypted_prod}")
        print(f"Expected multiplication result: {m1 * scalar}")
        assert (m1 * scalar) == decrypted_prod

    except TimeoutError as e:
        print(f"\nError: {e}")
    except PaillierError as e:
        print(f"\nA Paillier error occurred: {e}")
