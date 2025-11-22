from typing import List, Tuple
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.ec import ECOperations, Point
from crypto.common.numbers import rejection_sample


ProofSchBytesParts = 3


class ProofSch:
    """
    Implements a Schnorr proof of knowledge for a discrete logarithm on an
    elliptic curve. It proves knowledge of a scalar `x` for a public key `X = xG`.
    """

    def __init__(self, A: Point, Z: int):
        """
        Constructs a Schnorr proof.

        :param A: The commitment point, `A = alpha * G`.
        :param Z: The response scalar, `z = alpha + e*x`.
        """
        self.A = A
        self.Z = Z

    @staticmethod
    def new_proof(ssid: int, ec: ECOperations, X: Point, x: int) -> "ProofSch":
        """
        Generates a new Schnorr proof for the secret scalar `x`.
        """
        if x is None or X is None:
            raise ValueError("Cannot generate proof from invalid input.")

        alpha, A = ProofSch.new_alpha(ec)
        return ProofSch.new_proof_with_alpha(ssid, ec, X, A, alpha, x)

    @staticmethod
    def new_alpha(ec: ECOperations) -> Tuple[int, Point]:
        """Generates a random nonce scalar `alpha` and its corresponding point `A`."""
        alpha = ec.random_scalar()
        A = ec.scalar_mult(alpha)
        return alpha, A

    @staticmethod
    def new_proof_with_alpha(
        ssid: int, ec: ECOperations, X: Point, A: Point, alpha: int, x: int
    ) -> "ProofSch":
        """
        Generates a Schnorr proof using a pre-computed nonce `alpha` and point `A`.
        """
        if None in (x, X, A, alpha):
            raise ValueError("Cannot generate proof from invalid input.")

        q = ec.n
        g = ec.G

        e_hash = sha512_256i(
            ssid,
            ec.curve.b,
            ec.n,
            ec.p,
            X.x,
            X.y,
            g.x,
            g.y,
            A.x,
            A.y,
        )
        e = rejection_sample(q, e_hash)

        # Use gmpy2 for fast modular arithmetic: z = alpha + e*x mod q
        q_mpz, alpha_mpz, e_mpz, x_mpz = map(gmpy2.mpz, (q, alpha, e, x))
        z_mpz = (alpha_mpz + e_mpz * x_mpz) % q_mpz

        return ProofSch(A, int(z_mpz))

    @staticmethod
    def from_bytes(ec: ECOperations, parts: List[bytes]) -> "ProofSch":
        """Deserializes a proof from a list of byte strings."""
        if not parts or len(parts) != ProofSchBytesParts:
            raise ValueError(
                f"Expected {ProofSchBytesParts} parts to construct ProofSch"
            )

        x = int.from_bytes(parts[0], "big") % ec.p
        y = int.from_bytes(parts[1], "big") % ec.p
        z = int.from_bytes(parts[2], "big") % ec.n

        A = Point(x, y, ec.curve)
        return ProofSch(A, z)

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the proof into a list of byte strings."""
        return [
            self.A.x.to_bytes((self.A.x.bit_length() + 7) // 8, "big")
            if self.A.x != 0
            else b"",
            self.A.y.to_bytes((self.A.y.bit_length() + 7) // 8, "big")
            if self.A.y != 0
            else b"",
            self.Z.to_bytes((self.Z.bit_length() + 7) // 8, "big")
            if self.Z != 0
            else b"",
        ]

    def verify(self, ssid: int, ec: ECOperations, X: Point) -> bool:
        """
        Verifies the Schnorr proof.
        """
        if self.A is None or self.Z is None or X is None:
            return False

        q = ec.n
        g = ec.G

        e_hash = sha512_256i(
            ssid,
            ec.curve.b,
            ec.n,
            ec.p,
            X.x,
            X.y,
            g.x,
            g.y,
            self.A.x,
            self.A.y,
        )
        e = rejection_sample(q, e_hash)

        # Verify the core Schnorr equation: z*G == A + e*X
        left = ec.scalar_mult(self.Z)
        right = ec.point_add(self.A, ec.scalar_mult(e, X))

        return left == right
