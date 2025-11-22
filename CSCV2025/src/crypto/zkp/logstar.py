"""
Implements the Logstar zero-knowledge proof system.

This proof demonstrates that a prover knows a secret value 'x' and randomness 'rho'
that satisfy two conditions simultaneously:
1. A Paillier ciphertext 'C' is the encryption of 'x' using randomness 'rho'.
2. An elliptic curve point 'X' is the result of scalar multiplication 'x * g'.

The implementation uses the gmpy2 library for efficient multi-precision integer arithmetic.
"""

from typing import List
import random
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.paillier import PublicKey
from crypto.common.ec import ECOperations, Point
from crypto.common.numbers import (
    rejection_sample,
    check_invertible_and_valid_mod,
    is_in_interval,
)

ProofLogstarBytesParts = 8


class ProofLogstar:
    """Represents a zero-knowledge Log* proof and its associated data."""

    def __init__(self, S: int, A: int, Y: Point, D: int, Z1: int, Z2: int, Z3: int):
        self.S = S
        self.A = A
        self.Y = Y
        self.D = D
        self.Z1 = Z1
        self.Z2 = Z2
        self.Z3 = Z3

    @staticmethod
    def new_proof(
        ssid: int,
        ec: ECOperations,
        pk: PublicKey,
        C: int,
        X: Point,
        g: Point,
        rho: int,
        x: int,
        NCap: int,
        s: int,
        t: int,
    ) -> "ProofLogstar":
        """
        Generates a new Log* proof.

        Args:
            ssid: A session ID for the Fiat-Shamir transform.
            ec: Elliptic curve operations helper.
            pk: The Paillier public key.
            C: The Paillier ciphertext, Enc(pk, x, rho).
            X: The elliptic curve point, x * g.
            g: The base point for the discrete logarithm relation.
            rho: The randomness used to create the Paillier ciphertext C.
            x: The secret value (plaintext of C and scalar for X).
            NCap, s, t: Ring-Pedersen parameters for the range proof component.

        Returns:
            A new ProofLogstar instance.

        Raises:
            ValueError: If inputs are invalid or if a trivial case is detected.
        """
        if any(c is None for c in [ec, pk, C, X, g, NCap, s, t, x, rho]):
            raise ValueError("new_proof received a nil/zero argument")

        # This proof scheme is not defined for the trivial case where C=Enc(0).
        if ec.scalar_mult(C % ec.n, g) == X:
            raise ValueError("ProofLogstar cannot be generated for this trivial case")

        # Use gmpy2 for all large integer arithmetic.
        q = gmpy2.mpz(ec.n)
        N, NSq, gamma_pk = map(gmpy2.mpz, (pk.n, pk.n_square, pk.gamma))
        C, x, rho = map(gmpy2.mpz, (C, x, rho))
        NCap, s, t = map(gmpy2.mpz, (NCap, s, t))

        q3 = q**3
        qNCap = q * NCap
        q3NCap = q3 * NCap

        # Step 1: Sample random values for commitments.
        alpha = gmpy2.mpz(random.randrange(0, int(q3)))
        mu = gmpy2.mpz(random.randrange(0, int(qNCap)))
        gamma = gmpy2.mpz(random.randrange(0, int(q3NCap)))
        r = gmpy2.mpz(random.randrange(1, int(N)))
        while gmpy2.gcd(r, N) != 1:
            r = gmpy2.mpz(random.randrange(1, int(N)))

        # Step 2: Compute commitments S, A, Y, and D.
        S = (gmpy2.powmod(s, x, NCap) * gmpy2.powmod(t, mu, NCap)) % NCap
        A = (gmpy2.powmod(gamma_pk, alpha, NSq) * gmpy2.powmod(r, N, NSq)) % NSq
        Y = ec.scalar_mult(int(alpha % q), g)
        D = (gmpy2.powmod(s, alpha, NCap) * gmpy2.powmod(t, gamma, NCap)) % NCap

        # Step 3: Generate Fiat-Shamir challenge 'e'.
        e_hash = sha512_256i(
            ssid,
            pk.n,
            pk.gamma,
            ec.curve.b,
            ec.n,
            ec.p,
            C,
            X.x,
            X.y,
            g.x,
            g.y,
            S,
            A,
            Y.x,
            Y.y,
            D,
            NCap,
            s,
            t,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # Step 4: Compute final responses.
        z1 = e * x + alpha
        z2 = (gmpy2.powmod(rho, e, N) * r) % N
        z3 = e * mu + gamma

        # Return proof with standard integer types for serialization.
        return ProofLogstar(int(S), int(A), Y, int(D), int(z1), int(z2), int(z3))

    @staticmethod
    def from_bytes(ec: ECOperations, parts: List[bytes]) -> "ProofLogstar":
        """Deserializes a proof from a list of byte strings."""
        if not parts or len(parts) != ProofLogstarBytesParts:
            raise ValueError(f"expected {ProofLogstarBytesParts} byte parts")

        def ib(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        Y = Point(ib(parts[2]), ib(parts[3]), ec.curve)
        return ProofLogstar(
            ib(parts[0]),
            ib(parts[1]),
            Y,
            ib(parts[4]),
            ib(parts[5]),
            ib(parts[6]),
            ib(parts[7]),
        )

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the proof into a list of byte strings."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        return [
            bb(self.S),
            bb(self.A),
            bb(self.Y.x),
            bb(self.Y.y),
            bb(self.D),
            bb(self.Z1),
            bb(self.Z2),
            bb(self.Z3),
        ]

    def validate_basic(self) -> bool:
        """Performs a basic check for the presence of all proof components."""
        return all(
            p is not None
            for p in [self.S, self.A, self.Y, self.D, self.Z1, self.Z2, self.Z3]
        )

    def verify(
        self,
        ssid: int,
        ec: ECOperations,
        pk: PublicKey,
        C: int,
        X: Point,
        g: Point,
        NCap: int,
        s: int,
        t: int,
    ) -> bool:
        """
        Verifies the Log* proof.

        Args:
            (Same as new_proof, but without the secret values rho and x).

        Returns:
            True if the proof is valid, False otherwise.
        """
        if not self.validate_basic() or not all([ec, pk, C, X, g, NCap, s, t]):
            return False

        q = gmpy2.mpz(ec.n)
        N, NSq, gamma_pk = map(gmpy2.mpz, (pk.n, pk.n_square, pk.gamma))
        C, NCap, s, t = map(gmpy2.mpz, (C, NCap, s, t))
        S, A, D, Z1, Z2, Z3 = map(
            gmpy2.mpz, (self.S, self.A, self.D, self.Z1, self.Z2, self.Z3)
        )

        q3 = q**3
        if not is_in_interval(Z1, q3):
            return False
        if not check_invertible_and_valid_mod(NCap, S, D):
            return False
        if not check_invertible_and_valid_mod(NSq, A):
            return False
        if not check_invertible_and_valid_mod(N, Z2):
            return False

        # Recompute the Fiat-Shamir challenge 'e' to ensure binding.
        e_hash = sha512_256i(
            ssid,
            pk.n,
            pk.gamma,
            ec.curve.b,
            ec.n,
            ec.p,
            C,
            X.x,
            X.y,
            g.x,
            g.y,
            self.S,
            self.A,
            self.Y.x,
            self.Y.y,
            self.D,
            NCap,
            s,
            t,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # Verification Check 1: Paillier encryption relation.
        # Checks if gamma^z1 * z2^N == C^e * A (mod N^2).
        left1 = (gmpy2.powmod(gamma_pk, Z1, NSq) * gmpy2.powmod(Z2, N, NSq)) % NSq
        right1 = (gmpy2.powmod(C, e, NSq) * A) % NSq
        if left1 != right1:
            return False

        # Verification Check 2: Elliptic curve discrete logarithm relation.
        # Checks if z1*g == e*X + Y.
        left2 = ec.scalar_mult(int(Z1 % q), g)
        right2 = ec.point_add(ec.scalar_mult(int(e), X), self.Y)
        if left2 != right2:
            return False

        # Verification Check 3: Ring-Pedersen range proof relation.
        # Checks if s^z1 * t^z3 == D * S^e (mod N_cap).
        left3 = (gmpy2.powmod(s, Z1, NCap) * gmpy2.powmod(t, Z3, NCap)) % NCap
        right3 = (D * gmpy2.powmod(S, e, NCap)) % NCap
        if left3 != right3:
            return False

        return True
