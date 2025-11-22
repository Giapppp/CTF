"""
Implements the Paillier PRM zero-knowledge proof from the CGGMP21 protocol.

This proof demonstrates knowledge of a discrete logarithm `lambda` such that
`s = t^lambda mod N`, where `s` and `t` are elements of Z_N^*.
"""

from typing import List
import random
import gmpy2

from crypto.zkp.hash import sha512_256i


Iterations = 80
ProofPrmBytesParts = Iterations * 2


class ProofPrm:
    """Represents a zero-knowledge proof of knowledge for Paillier PRM."""

    def __init__(self, A: List[int], Z: List[int]):
        self.A = A
        self.Z = Z

    @staticmethod
    def new_proof(ssid: int, s: int, t: int, N: int, Phi: int, lam: int) -> "ProofPrm":
        """Generates a new Prm proof."""
        if not all([s, t, N, Phi, lam]):
            raise ValueError("Prm proof input is not valid")

        s, t, N, Phi, lam = map(gmpy2.mpz, (s, t, N, Phi, lam))

        # 1. Sample random exponents and compute commitments.
        a = [gmpy2.mpz(random.randrange(0, int(Phi))) for _ in range(Iterations)]
        A = [gmpy2.powmod(t, ai, N) for ai in a]

        # 2. Compute Fiat-Shamir challenge. The hash interface expects standard ints.
        e = sha512_256i(*([ssid, int(s), int(t), int(N)] + [int(val) for val in A]))

        # 3. Compute responses.
        Z = [(a[i] + (((e >> i) & 1) * lam)) % Phi for i in range(Iterations)]

        return ProofPrm([int(val) for val in A], [int(val) for val in Z])

    @staticmethod
    def from_bytes(parts: List[bytes]) -> "ProofPrm":
        """Deserializes a proof from a list of byte strings."""
        if not parts or len(parts) != ProofPrmBytesParts:
            raise ValueError(
                f"expected {ProofPrmBytesParts} byte parts to construct ProofPrm"
            )
        bis = [int.from_bytes(b, "big") if b else 0 for b in parts]
        A = bis[:Iterations]
        Z = bis[Iterations:]
        return ProofPrm(A, Z)

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the proof into a list of byte strings for transport."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        out: List[bytes] = []
        out += [bb(a) for a in self.A]
        out += [bb(z) for z in self.Z]
        return out

    def validate_basic(self) -> bool:
        """Performs basic structural validation of the proof components."""
        if self.A is None or any(a is None for a in self.A):
            return False
        if self.Z is None or any(z is None for z in self.Z):
            return False
        return True

    def verify(self, ssid: int, s: int, t: int, N: int) -> bool:
        """Verifies the Prm proof."""
        if not self.validate_basic() or not all([s, t, N]) or N <= 0:
            return False

        s_mpz, t_mpz, N_mpz = map(gmpy2.mpz, (s, t, N))
        A_mpz = [gmpy2.mpz(a) for a in self.A]
        Z_mpz = [gmpy2.mpz(z) for z in self.Z]

        # Recompute the Fiat-Shamir challenge.
        e = sha512_256i(*([ssid, s, t, N] + self.A))

        # Perform security checks to ensure values are valid group elements.
        s_, t_ = s_mpz % N_mpz, t_mpz % N_mpz
        if not (1 < s_ < N_mpz) or not (1 < t_ < N_mpz) or s_ == t_:
            return False
        for a in A_mpz:
            if not (1 < a < N_mpz):
                return False
        # The `Z` values are exponents, not group elements, so they only need
        # to be non-negative.
        for z in Z_mpz:
            if z < 0:
                return False
        # Verify the proof equation for each iteration.
        for i in range(Iterations):
            ei = (e >> i) & 1

            # Check: t^Z_i == A_i * s^e_i (mod N)
            left = gmpy2.powmod(t_mpz, Z_mpz[i], N_mpz)
            right_term = gmpy2.powmod(s_mpz, ei, N_mpz)
            right = (A_mpz[i] * right_term) % N_mpz

            if left != right:
                return False

        return True
