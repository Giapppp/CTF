"""
Implements the zero-knowledge proof of knowledge for a Paillier encryption (ProofEnc),
as required by the CGGMP protocol. This implementation uses the gmpy2 library
for high-performance multi-precision integer arithmetic.
"""

from typing import List
import random
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.paillier import PublicKey
from crypto.common.ec import ECOperations
from crypto.common.numbers import (
    rejection_sample,
    check_invertible_and_valid_mod,
    is_in_interval,
)

ProofEncBytesParts = 6


class ProofEnc:
    """
    Represents a ZKP proving knowledge of a plaintext `k` and randomness `rho`
    for a given Paillier ciphertext `K = Enc(k, rho)`.
    """

    def __init__(self, S: int, A: int, C: int, Z1: int, Z2: int, Z3: int):
        self.S = S
        self.A = A
        self.C = C
        self.Z1 = Z1
        self.Z2 = Z2
        self.Z3 = Z3

    @staticmethod
    def new_proof(
        ssid: int,
        ec: ECOperations,
        pk: PublicKey,
        K: int,
        NCap: int,
        s: int,
        t: int,
        k: int,
        rho: int,
    ) -> "ProofEnc":
        """Generates a new ProofEnc instance."""
        if any(c is None for c in [ec, pk, K, NCap, s, t, k, rho]):
            raise ValueError("new_proof received a nil/zero argument")

        q = gmpy2.mpz(ec.n)
        N, NSq, gamma_pk = map(gmpy2.mpz, (pk.n, pk.n_square, pk.gamma))
        NCap, s, t, K = map(gmpy2.mpz, (NCap, s, t, K))
        k, rho = map(gmpy2.mpz, (k, rho))

        q3 = q**3
        qNCap = q * NCap
        q3NCap = q3 * NCap

        alpha = gmpy2.mpz(random.randrange(0, int(q3)))
        mu = gmpy2.mpz(random.randrange(0, int(qNCap)))
        gamma = gmpy2.mpz(random.randrange(0, int(q3NCap)))

        # Sample a random r in Z_N^* for the Paillier commitment.
        r = gmpy2.mpz(random.randrange(0, int(N - 1)) + 1)
        while gmpy2.gcd(r, N) != 1:
            r = gmpy2.mpz(random.randrange(0, int(N - 1)) + 1)

        # Create commitments.
        S = (gmpy2.powmod(s, k, NCap) * gmpy2.powmod(t, mu, NCap)) % NCap
        A = (gmpy2.powmod(gamma_pk, alpha, NSq) * gmpy2.powmod(r, N, NSq)) % NSq
        C_ = (gmpy2.powmod(s, alpha, NCap) * gmpy2.powmod(t, gamma, NCap)) % NCap

        # Generate challenge using Fiat-Shamir heuristic.
        e_hash = sha512_256i(
            ssid,
            pk.n,
            pk.gamma,
            ec.curve.b,
            ec.n,
            ec.p,
            NCap,
            s,
            t,
            K,
            S,
            A,
            C_,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # Compute responses.
        z1 = e * k + alpha
        z2 = (gmpy2.powmod(rho, e, N) * r) % N
        z3 = e * mu + gamma

        return ProofEnc(int(S), int(A), int(C_), int(z1), int(z2), int(z3))

    @staticmethod
    def from_bytes(parts: List[bytes]) -> "ProofEnc":
        """Deserializes a ProofEnc from a list of byte parts."""
        if not parts or len(parts) != ProofEncBytesParts:
            raise ValueError(
                f"expected {ProofEncBytesParts} byte parts to construct ProofEnc"
            )

        def ib(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        return ProofEnc(
            ib(parts[0]),
            ib(parts[1]),
            ib(parts[2]),
            ib(parts[3]),
            ib(parts[4]),
            ib(parts[5]),
        )

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the ProofEnc to a list of byte parts."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        return [
            bb(self.S),
            bb(self.A),
            bb(self.C),
            bb(self.Z1),
            bb(self.Z2),
            bb(self.Z3),
        ]

    def validate_basic(self) -> bool:
        """Performs basic sanity checks on the proof components."""
        return all(
            [
                self.S is not None,
                self.A is not None,
                self.C is not None,
                self.Z1 is not None,
                self.Z2 is not None,
                self.Z3 is not None,
            ]
        )

    def verify(
        self,
        ssid: int,
        ec: ECOperations,
        pk: PublicKey,
        NCap: int,
        s: int,
        t: int,
        K: int,
    ) -> bool:
        """Verifies the ProofEnc."""
        if not self.validate_basic() or not all([ec, pk, NCap, s, t, K]):
            return False

        q = gmpy2.mpz(ec.n)
        N, NSq, gamma_pk = map(gmpy2.mpz, (pk.n, pk.n_square, pk.gamma))
        NCap, s, t, K = map(gmpy2.mpz, (NCap, s, t, K))

        S, A, C = map(gmpy2.mpz, (self.S, self.A, self.C))
        Z1, Z2, Z3 = map(gmpy2.mpz, (self.Z1, self.Z2, self.Z3))

        q3 = q**3

        if not is_in_interval(Z1, q3):
            return False
        if not check_invertible_and_valid_mod(NCap, S, C):
            return False
        if not check_invertible_and_valid_mod(NSq, A):
            return False
        if not check_invertible_and_valid_mod(N, Z2):
            return False

        # Recompute challenge.
        e_hash = sha512_256i(
            ssid,
            pk.n,
            pk.gamma,
            ec.curve.b,
            ec.n,
            ec.p,
            NCap,
            s,
            t,
            K,
            self.S,
            self.A,
            self.C,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # Verify the two proof equations.
        left1 = (gmpy2.powmod(gamma_pk, Z1, NSq) * gmpy2.powmod(Z2, N, NSq)) % NSq
        right1 = (A * gmpy2.powmod(K, e, NSq)) % NSq
        if left1 != right1:
            return False

        left2 = (gmpy2.powmod(s, Z1, NCap) * gmpy2.powmod(t, Z3, NCap)) % NCap
        right2 = (C * gmpy2.powmod(S, e, NCap)) % NCap
        if left2 != right2:
            return False

        return True
