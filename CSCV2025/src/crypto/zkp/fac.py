"""
Implements the zero-knowledge Proof of Factorization (Fac) system from the CGGMP21
protocol. This implementation is optimized using the gmpy2 library for high-performance
multi-precision integer arithmetic.
"""

from typing import List
import random
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.ec import ECOperations
from crypto.common.numbers import (
    rejection_sample,
    check_invertible_and_valid_mod,
    is_in_interval,
)


ProofFacBytesParts = 11


class ProofFac:
    """
    Represents a zero-knowledge proof of knowledge of the factorization of N0.
    This proof demonstrates that a prover knows p, q such that N0 = p*q without
    revealing p and q.
    """

    def __init__(
        self,
        P: int,
        Q: int,
        A: int,
        B: int,
        T: int,
        Sigma: int,
        Z1: int,
        Z2: int,
        W1: int,
        W2: int,
        V: int,
    ) -> None:
        """Initializes the proof object with its component values."""
        self.P = P
        self.Q = Q
        self.A = A
        self.B = B
        self.T = T
        self.Sigma = Sigma
        self.Z1 = Z1
        self.Z2 = Z2
        self.W1 = W1
        self.W2 = W2
        self.V = V

    @staticmethod
    def new_proof(
        ssid: int,
        ec: ECOperations,
        N0: int,
        NCap: int,
        s: int,
        t: int,
        N0p: int,
        N0q: int,
    ) -> "ProofFac":
        """
        Generates a new ProofFac using the Fiat-Shamir heuristic.

        Args:
            ssid: A shared session identifier for the proof context.
            ec: Elliptic curve operations object.
            N0: The modulus whose factorization (N0p, N0q) is known.
            NCap: The Ring-Pedersen modulus.
            s, t: Ring-Pedersen parameters.
            N0p, N0q: The prime factors of N0.
        """
        if not all([N0, NCap, s, t, N0p, N0q]):
            raise ValueError("new_proof received a nil/zero argument")

        # Use gmpy2 for all large-integer arithmetic for performance.
        q, q3 = gmpy2.mpz(ec.n), gmpy2.mpz(ec.n) ** 3
        N0, NCap = map(gmpy2.mpz, (N0, NCap))
        s, t, N0p, N0q = map(gmpy2.mpz, (s, t, N0p, N0q))

        sqrtN0 = gmpy2.isqrt(N0)
        leSqrtN0 = q3 * sqrtN0
        lNCap = q * NCap
        lN0NCap = q * N0 * NCap
        leN0NCap = q3 * N0 * NCap
        leNCap = q3 * NCap

        # 1. Sample random values for the commitment phase.
        alpha = gmpy2.mpz(random.randrange(0, int(leSqrtN0)))
        beta = gmpy2.mpz(random.randrange(0, int(leSqrtN0)))
        mu = gmpy2.mpz(random.randrange(0, int(lNCap)))
        nu = gmpy2.mpz(random.randrange(0, int(lNCap)))
        sigma = gmpy2.mpz(random.randrange(0, int(lN0NCap)))
        x = gmpy2.mpz(random.randrange(0, int(leNCap)))
        y = gmpy2.mpz(random.randrange(0, int(leNCap)))
        r = gmpy2.mpz(random.randrange(0, int(leN0NCap)))

        # 2. Create commitments to the secret values.
        P = (gmpy2.powmod(s, N0p, NCap) * gmpy2.powmod(t, mu, NCap)) % NCap
        Q = (gmpy2.powmod(s, N0q, NCap) * gmpy2.powmod(t, nu, NCap)) % NCap
        A = (gmpy2.powmod(s, alpha, NCap) * gmpy2.powmod(t, x, NCap)) % NCap
        B = (gmpy2.powmod(s, beta, NCap) * gmpy2.powmod(t, y, NCap)) % NCap
        T = (gmpy2.powmod(Q, alpha, NCap) * gmpy2.powmod(t, r, NCap)) % NCap

        # 3. Generate Fiat-Shamir challenge from the public context and commitments.
        e_hash = sha512_256i(
            ssid,
            N0,
            NCap,
            s,
            t,
            P,
            Q,
            A,
            B,
            T,
            sigma,
            ec.curve.b,
            ec.n,
            ec.p,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # 4. Compute responses based on the challenge.
        z1 = e * N0p + alpha
        z2 = e * N0q + beta
        w1 = e * mu + x
        w2 = e * nu + y
        v = e * (sigma - (nu * N0p)) + r

        return ProofFac(
            int(P),
            int(Q),
            int(A),
            int(B),
            int(T),
            int(sigma),
            int(z1),
            int(z2),
            int(w1),
            int(w2),
            int(v),
        )

    @staticmethod
    def from_bytes(parts: List[bytes]) -> "ProofFac":
        """Deserializes a proof from a list of byte strings."""
        if not parts or len(parts) != ProofFacBytesParts:
            raise ValueError(
                f"expected {ProofFacBytesParts} byte parts to construct ProofFac"
            )

        def ib(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        return ProofFac(
            ib(parts[0]),
            ib(parts[1]),
            ib(parts[2]),
            ib(parts[3]),
            ib(parts[4]),
            ib(parts[5]),
            ib(parts[6]),
            ib(parts[7]),
            ib(parts[8]),
            ib(parts[9]),
            ib(parts[10]),
        )

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the proof into a list of byte strings."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        return [
            bb(self.P),
            bb(self.Q),
            bb(self.A),
            bb(self.B),
            bb(self.T),
            bb(self.Sigma),
            bb(self.Z1),
            bb(self.Z2),
            bb(self.W1),
            bb(self.W2),
            bb(self.V),
        ]

    def validate_basic(self) -> bool:
        """Performs a basic check to ensure all proof components are present."""
        return all(
            [
                self.P is not None,
                self.Q is not None,
                self.A is not None,
                self.B is not None,
                self.T is not None,
                self.Sigma is not None,
                self.Z1 is not None,
                self.Z2 is not None,
                self.W1 is not None,
                self.W2 is not None,
                self.V is not None,
            ]
        )

    def verify(
        self, ssid: int, ec: ECOperations, N0: int, NCap: int, s: int, t: int
    ) -> bool:
        """
        Verifies the Proof of Factorization.
        This method uses gmpy2 for all arithmetic to ensure high performance.
        """
        if not self.validate_basic() or not all([N0, NCap, s, t]):
            return False
        if N0 <= 0 or NCap <= 0:
            return False
        # Use gmpy2 for all large-integer arithmetic.
        q, q3 = gmpy2.mpz(ec.n), gmpy2.mpz(ec.n) ** 3
        N0, NCap, s, t = map(gmpy2.mpz, (N0, NCap, s, t))
        P, Q, A, B, T = map(gmpy2.mpz, (self.P, self.Q, self.A, self.B, self.T))
        Sigma, Z1, Z2 = map(gmpy2.mpz, (self.Sigma, self.Z1, self.Z2))
        W1, W2, V = map(gmpy2.mpz, (self.W1, self.W2, self.V))

        sqrtN0 = gmpy2.isqrt(N0)
        leSqrtN0 = q3 * sqrtN0

        # 1. Perform range checks on the response values.
        if not is_in_interval(Z1, leSqrtN0):
            return False
        if not is_in_interval(Z2, leSqrtN0):
            return False
        if not check_invertible_and_valid_mod(NCap, P, Q, A, B, T):
            return False
        # 2. Recompute the Fiat-Shamir challenge.
        e_hash = sha512_256i(
            ssid,
            N0,
            NCap,
            s,
            t,
            self.P,
            self.Q,
            self.A,
            self.B,
            self.T,
            self.Sigma,
            ec.curve.b,
            ec.n,
            ec.p,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # 3. Verify the three cryptographic equalities.
        # Check 1: s^Z1 * t^W1 == A * P^e (mod NCap)
        LHS1 = (gmpy2.powmod(s, Z1, NCap) * gmpy2.powmod(t, W1, NCap)) % NCap
        RHS1 = (A * gmpy2.powmod(P, e, NCap)) % NCap
        if LHS1 != RHS1:
            return False
        # Check 2: s^Z2 * t^W2 == B * Q^e (mod NCap)
        LHS2 = (gmpy2.powmod(s, Z2, NCap) * gmpy2.powmod(t, W2, NCap)) % NCap
        RHS2 = (B * gmpy2.powmod(Q, e, NCap)) % NCap
        if LHS2 != RHS2:
            return False
        # Check 3: Q^Z1 * t^V == T * (s^N0 * t^Sigma)^e (mod NCap)
        R = (gmpy2.powmod(s, N0, NCap) * gmpy2.powmod(t, Sigma, NCap)) % NCap
        LHS3 = (gmpy2.powmod(Q, Z1, NCap) * gmpy2.powmod(t, V, NCap)) % NCap
        RHS3 = (T * gmpy2.powmod(R, e, NCap)) % NCap
        if LHS3 != RHS3:
            return False
        return True
