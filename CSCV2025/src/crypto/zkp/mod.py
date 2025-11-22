"""
Implements the Zero-Knowledge Proof of Modularity from the CGGMP21 paper,
Figure 16. This module is optimized for performance using the gmpy2 library
for all multi-precision integer arithmetic.
"""

from typing import List
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.numbers import (
    sample_invertible_with_neg_jacobi,
    is_quadratic_residue,
    rejection_sample,
)


Iterations = 80
ProofModBytesParts = Iterations * 2 + 3


class ProofMod:
    """
    Represents a Zero-Knowledge Proof of Modularity.

    This proof demonstrates that a number N is a product of two safe primes
    without revealing the primes themselves.
    """

    def __init__(self, W: int, X: List[int], A: int, B: int, Z: List[int]):
        self.W = W
        self.X = X
        self.A = A
        self.B = B
        self.Z = Z

    @staticmethod
    def new_proof(ssid: int, N: int, P: int, Q: int) -> "ProofMod":
        """
        Generates a new proof that N = P * Q, where P and Q are safe primes.

        Args:
            ssid: A session-specific identifier to ensure proof uniqueness.
            N: The modulus, product of two safe primes.
            P: The first safe prime factor of N.
            Q: The second safe prime factor of N.
        """
        if not all([N, P, Q]):
            raise ValueError("Proof mod input is not valid")

        N, P, Q = map(gmpy2.mpz, (N, P, Q))
        Phi = (P - 1) * (Q - 1)

        # Step 1: Pick a quadratic non-residue W modulo N.
        W = gmpy2.mpz(sample_invertible_with_neg_jacobi(N))

        # Step 2: Derive Y_i values via Fiat-Shamir from the public context.
        Y: List[int] = [0] * Iterations
        for i in range(Iterations):
            prefix = [ssid, W, N] + Y[:i]
            ei = sha512_256i(*prefix)
            Y[i] = rejection_sample(N, ei)

        Y_mpz = [gmpy2.mpz(y) for y in Y]

        # Step 3: Compute N's inverse modulo Phi, needed for N-th roots.
        try:
            invN = gmpy2.invert(N, Phi)
        except ZeroDivisionError:  # gmpy2 raises this for non-invertible cases
            raise ValueError("N is not invertible modulo Phi")

        X: List[gmpy2.mpz] = [gmpy2.mpz(0)] * Iterations
        Z: List[gmpy2.mpz] = [gmpy2.mpz(0)] * Iterations

        # A and B act as bit-vectors, packed into large integers for efficiency.
        A = gmpy2.mpz(0xFF)
        B = gmpy2.mpz(0xFF)

        # Precompute the exponent for finding fourth roots modulo N.
        # expo = (((Phi+4)//8)^2) mod Phi
        expo = gmpy2.powmod((Phi + 4) >> 3, 2, Phi)

        for i in range(Iterations):
            # Iterate through sign/factor combinations to find one for which a fourth root exists.
            for j in range(4):
                a = j & 1
                b = (j & 2) >> 1
                Yi = Y_mpz[i]
                if a > 0:
                    Yi = -Yi % N
                if b > 0:
                    Yi = (W * Yi) % N

                if is_quadratic_residue(Yi, P) and is_quadratic_residue(Yi, Q):
                    X[i] = gmpy2.powmod(Yi, expo, N)
                    Z[i] = gmpy2.powmod(Y_mpz[i], invN, N)
                    # Pack the choice bits 'a' and 'b' into the A and B integers.
                    A = (A << 8) | a
                    B = (B << 8) | b
                    break

        return ProofMod(
            int(W), [int(x) for x in X], int(A), int(B), [int(z) for z in Z]
        )

    @staticmethod
    def from_bytes(parts: List[bytes]) -> "ProofMod":
        """Deserializes a ProofMod from a list of byte parts."""
        if not parts or len(parts) != ProofModBytesParts:
            raise ValueError(
                f"expected {ProofModBytesParts} byte parts to construct ProofMod"
            )

        ints = [int.from_bytes(b, "big") if b else 0 for b in parts]
        W = ints[0]
        X = ints[1 : Iterations + 1]
        A = ints[Iterations + 1]
        B = ints[Iterations + 2]
        Z = ints[Iterations + 3 :]
        return ProofMod(W, X, A, B, Z)

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the ProofMod into a list of byte parts."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        out: List[bytes] = [bb(self.W)]
        out += [bb(x) for x in self.X]
        out.append(bb(self.A))
        out.append(bb(self.B))
        out += [bb(z) for z in self.Z]
        return out

    def validate_basic(self) -> bool:
        """Performs basic non-null checks on proof components."""
        return all(
            [
                self.W is not None,
                self.X is not None and not any(x is None for x in self.X),
                self.A is not None,
                self.B is not None,
                self.Z is not None and not any(z is None for z in self.Z),
            ]
        )

    def verify(self, ssid: int, N: int) -> bool:
        """
        Verifies the ProofMod.

        Args:
            ssid: The session-specific identifier used to generate the proof.
            N: The modulus N that is being proven to be a product of two safe primes.
        """
        if not self.validate_basic() or not N:
            return False

        N = gmpy2.mpz(N)
        W, A, B = map(gmpy2.mpz, (self.W, self.A, self.B))
        X = [gmpy2.mpz(x) for x in self.X]
        Z = [gmpy2.mpz(z) for z in self.Z]

        if is_quadratic_residue(W, N) == 1:
            return False
        if not (0 < W < N and all(0 < z < N for z in Z) and all(0 < x < N for x in X)):
            return False

        # A and B are packed integers representing 80 bytes of choices plus a 1-byte header (0xFF).
        # Their total length must therefore be exactly 81 bytes.
        # A number k bytes long has a bit length in (8*(k-1), 8*k].
        expected_len_in_bits = 8 * (Iterations + 1)
        if not (expected_len_in_bits - 8 < A.bit_length() <= expected_len_in_bits):
            return False
        if not (expected_len_in_bits - 8 < B.bit_length() <= expected_len_in_bits):
            return False

        # Recompute Y values using the same Fiat-Shamir derivation as the prover.
        Y: List[gmpy2.mpz] = [gmpy2.mpz(0)] * Iterations
        for i in range(Iterations):
            prefix = [ssid, W, N] + [int(y) for y in Y[:i]]
            ei = sha512_256i(*prefix)
            Y[i] = gmpy2.mpz(rejection_sample(N, ei))

        if not gmpy2.is_odd(N):
            return False

        # Verify the core proof equations for each iteration.
        for i in range(Iterations):
            # Check 1: Z_i^N mod N == Y_i
            if gmpy2.powmod(Z[i], N, N) != Y[i]:
                return False

            # Unpack the choice bits 'a' and 'b' for this iteration from A and B.
            shift = 8 * (Iterations - 1 - i)
            a = (A >> shift) & 0xFF
            b = (B >> shift) & 0xFF

            if a not in (0, 1) or b not in (0, 1):
                return False

            # Check 2: X_i^4 mod N == (-1)^a * W^b * Y_i mod N
            left = gmpy2.powmod(X[i], 4, N)
            right = Y[i]
            if a > 0:
                right = -right % N
            if b > 0:
                right = (W * right) % N

            if left != right:
                return False

        return True
