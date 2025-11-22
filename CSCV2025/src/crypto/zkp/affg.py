from typing import List
import random
import gmpy2

from crypto.zkp.hash import sha512_256i
from crypto.common.paillier import PublicKey
from crypto.common.paillier import get_random_positive_relatively_prime_int
from crypto.common.ec import ECOperations, Point
from crypto.common.numbers import (
    rejection_sample,
    check_invertible_and_valid_mod,
    is_in_interval,
)

ProofAffgBytesParts = 14


class ProofAffg:
    """
    Implements a zero-knowledge proof for the Aff-g relation from CGGMP21.

    This proof demonstrates that two Paillier ciphertexts, D and Y, encrypt
    values x and y respectively (D=Enc(x), Y=Enc(y)), and that a public elliptic
    curve point X is the generator G multiplied by x (X=xG), without revealing
    the secret values x, y, or the randomness used for encryption.

    The implementation is optimized to use gmpy2 for all cryptographic integer operations.
    """

    def __init__(
        self,
        S: int,
        T: int,
        A: int,
        Bx: Point,
        By: int,
        E: int,
        F: int,
        Z1: int,
        Z2: int,
        Z3: int,
        Z4: int,
        W: int,
        Wy: int,
    ) -> None:
        """Initializes the proof object with all its components."""
        self.S = S
        self.T = T
        self.A = A
        self.Bx = Bx
        self.By = By
        self.E = E
        self.F = F
        self.Z1 = Z1
        self.Z2 = Z2
        self.Z3 = Z3
        self.Z4 = Z4
        self.W = W
        self.Wy = Wy

    @staticmethod
    def new_proof(
        ssid: int,
        ec: ECOperations,
        pk0: PublicKey,
        pk1: PublicKey,
        NCap: int,
        s: int,
        t: int,
        C: int,
        D: int,
        Y: int,
        X: Point,
        x: int,
        y: int,
        rho: int,
        rhoy: int,
    ) -> "ProofAffg":
        """Generates a new zero-knowledge proof for the Aff-g relation."""
        if not all([ec, pk0, pk1, NCap, s, t, C, D, Y, X, x, y, rho, rhoy]):
            raise ValueError("new_proof() received a nil/zero argument")

        q = gmpy2.mpz(ec.n)
        N0, NSq0, gamma0 = map(gmpy2.mpz, (pk0.n, pk0.n_square, pk0.gamma))
        N1, NSq1, gamma1 = map(gmpy2.mpz, (pk1.n, pk1.n_square, pk1.gamma))
        NCap, s, t = map(gmpy2.mpz, (NCap, s, t))
        C, D, Y = map(gmpy2.mpz, (C, D, Y))
        x, y, rho, rhoy = map(gmpy2.mpz, (x, y, rho, rhoy))

        q3 = q**3
        q7 = q**7
        qNCap = q * NCap
        q3NCap = q3 * NCap

        # Sample random values for the commitment phase.
        alpha = gmpy2.mpz(random.randrange(0, q3))
        beta = gmpy2.mpz(random.randrange(0, q7))
        r = gmpy2.mpz(get_random_positive_relatively_prime_int(pk0.n))
        ry = gmpy2.mpz(get_random_positive_relatively_prime_int(pk1.n))
        gamma = gmpy2.mpz(random.randrange(0, q3NCap))
        m = gmpy2.mpz(random.randrange(0, qNCap))
        delta = gmpy2.mpz(random.randrange(0, q3NCap))
        mu = gmpy2.mpz(random.randrange(0, qNCap))

        # Create commitments to the random values.
        # A = C^alpha * (1+N0)^beta * r^N0 mod N0^2
        A_term1 = gmpy2.powmod(C, alpha, NSq0)
        A_term2 = gmpy2.powmod(gamma0, beta, NSq0)
        A_term3 = gmpy2.powmod(r, N0, NSq0)
        A = (A_term1 * A_term2 * A_term3) % NSq0

        Bx = ec.scalar_mult(int(alpha % q))  # Bx = alpha*G
        By = (gmpy2.powmod(gamma1, beta, NSq1) * gmpy2.powmod(ry, N1, NSq1)) % NSq1

        E = (gmpy2.powmod(s, alpha, NCap) * gmpy2.powmod(t, gamma, NCap)) % NCap
        S = (gmpy2.powmod(s, x, NCap) * gmpy2.powmod(t, m, NCap)) % NCap
        F = (gmpy2.powmod(s, beta, NCap) * gmpy2.powmod(t, delta, NCap)) % NCap
        T = (gmpy2.powmod(s, y, NCap) * gmpy2.powmod(t, mu, NCap)) % NCap

        # Create Fiat-Shamir challenge `e`.
        e_hash = sha512_256i(
            ssid,
            ec.curve.b,
            ec.n,
            ec.p,
            pk0.n,
            pk1.n,
            NCap,
            s,
            t,
            C,
            D,
            Y,
            X.x,
            X.y,
            S,
            T,
            A,
            Bx.x,
            Bx.y,
            By,
            E,
            F,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # Compute responses based on the challenge `e`.
        z1 = e * x + alpha
        z2 = e * y + beta
        z3 = e * m + gamma
        z4 = e * mu + delta
        w = (gmpy2.powmod(rho, e, N0) * r) % N0
        wy = (gmpy2.powmod(rhoy, e, N1) * ry) % N1

        return ProofAffg(
            int(S),
            int(T),
            int(A),
            Bx,
            int(By),
            int(E),
            int(F),
            int(z1),
            int(z2),
            int(z3),
            int(z4),
            int(w),
            int(wy),
        )

    @staticmethod
    def from_bytes(ec: ECOperations, parts: List[bytes]) -> "ProofAffg":
        """Deserializes the proof from a list of byte parts."""
        if not parts or len(parts) != ProofAffgBytesParts:
            raise ValueError(
                f"expected {ProofAffgBytesParts} parts to construct ProofAffg"
            )

        def ib(b: bytes) -> int:
            return int.from_bytes(b, "big") if b else 0

        Bx = Point(ib(parts[3]), ib(parts[4]), ec.curve)
        return ProofAffg(
            ib(parts[0]),
            ib(parts[1]),
            ib(parts[2]),
            Bx,
            ib(parts[5]),
            ib(parts[6]),
            ib(parts[7]),
            ib(parts[8]),
            ib(parts[9]),
            ib(parts[10]),
            ib(parts[11]),
            ib(parts[12]),
            ib(parts[13]),
        )

    def to_bytes_parts(self) -> List[bytes]:
        """Serializes the proof into a list of byte parts."""

        def bb(i: int) -> bytes:
            return i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b""

        return [
            bb(self.S),
            bb(self.T),
            bb(self.A),
            bb(self.Bx.x),
            bb(self.Bx.y),
            bb(self.By),
            bb(self.E),
            bb(self.F),
            bb(self.Z1),
            bb(self.Z2),
            bb(self.Z3),
            bb(self.Z4),
            bb(self.W),
            bb(self.Wy),
        ]

    def validate_basic(self) -> bool:
        """Performs a basic check to ensure all proof components are present."""
        return all(
            [
                self.S is not None,
                self.T is not None,
                self.A is not None,
                self.Bx is not None,
                self.By is not None,
                self.E is not None,
                self.F is not None,
                self.Z1 is not None,
                self.Z2 is not None,
                self.Z3 is not None,
                self.Z4 is not None,
                self.W is not None,
                self.Wy is not None,
            ]
        )

    def verify(
        self,
        ssid: int,
        ec: ECOperations,
        pk0: PublicKey,
        pk1: PublicKey,
        NCap: int,
        s: int,
        t: int,
        C: int,
        D: int,
        Y: int,
        X: Point,
    ) -> bool:
        """Verifies the zero-knowledge proof for the Aff-g relation."""
        if not self.validate_basic():
            return False

        q = gmpy2.mpz(ec.n)
        N0, NSq0, gamma0 = map(gmpy2.mpz, (pk0.n, pk0.n_square, pk0.gamma))
        N1, NSq1, gamma1 = map(gmpy2.mpz, (pk1.n, pk1.n_square, pk1.gamma))
        NCap, s, t = map(gmpy2.mpz, (NCap, s, t))
        C, D, Y = map(gmpy2.mpz, (C, D, Y))

        S, T, A, By = map(gmpy2.mpz, (self.S, self.T, self.A, self.By))
        E, F, W, Wy = map(gmpy2.mpz, (self.E, self.F, self.W, self.Wy))
        Z1, Z2, Z3, Z4 = map(gmpy2.mpz, (self.Z1, self.Z2, self.Z3, self.Z4))

        q3 = q**3
        q7 = q**7

        # Perform range and validity checks on proof components.
        if not is_in_interval(Z1, q3):
            return False
        if not is_in_interval(Z2, q7):
            return False
        if not check_invertible_and_valid_mod(NSq0, A):
            return False
        if not check_invertible_and_valid_mod(NSq1, By):
            return False
        if not check_invertible_and_valid_mod(N0, W):
            return False
        if not check_invertible_and_valid_mod(N1, Wy):
            return False
        if not check_invertible_and_valid_mod(NCap, E, F, S, T):
            return False
        if min(Z1, Z2, Z3, Z4) <= 0:
            return False

        # Recompute Fiat-Shamir challenge `e`.
        e_hash = sha512_256i(
            ssid,
            ec.curve.b,
            ec.n,
            ec.p,
            pk0.n,
            pk1.n,
            NCap,
            s,
            t,
            C,
            D,
            Y,
            X.x,
            X.y,
            self.S,
            self.T,
            self.A,
            self.Bx.x,
            self.Bx.y,
            self.By,
            self.E,
            self.F,
        )
        e = gmpy2.mpz(rejection_sample(int(q), e_hash))

        # --- Verification Checks ---

        # Check 1: Verify Paillier encryption relation for D.
        # C^Z1 * (1+N0)^Z2 * W^N0 must equal D^e * A (mod N0^2)
        left1 = gmpy2.powmod(C, Z1, NSq0)
        left1 = (left1 * gmpy2.powmod(gamma0, Z2, NSq0)) % NSq0
        left1 = (left1 * gmpy2.powmod(W, N0, NSq0)) % NSq0
        right1 = (gmpy2.powmod(D, e, NSq0) * A) % NSq0
        if left1 != right1:
            return False

        # Check 2: Verify elliptic curve relation for X.
        # Z1*G must equal e*X + Bx
        g_exp_z1 = ec.scalar_mult(int(Z1 % q))
        x_exp_e = ec.scalar_mult(int(e), X)
        bx_sum = ec.point_add(x_exp_e, self.Bx)
        if g_exp_z1 != bx_sum:
            return False

        # Check 3: Verify Paillier encryption relation for Y.
        # (1+N1)^Z2 * Wy^N1 must equal Y^e * By (mod N1^2)
        left3 = (gmpy2.powmod(gamma1, Z2, NSq1) * gmpy2.powmod(Wy, N1, NSq1)) % NSq1
        right3 = (gmpy2.powmod(Y, e, NSq1) * By) % NSq1
        if left3 != right3:
            return False

        # Check 4: Verify Pedersen commitment relations.
        # s^Z1 * t^Z3 must equal S^e * E (mod NCap)
        left4a = (gmpy2.powmod(s, Z1, NCap) * gmpy2.powmod(t, Z3, NCap)) % NCap
        right4a = (gmpy2.powmod(S, e, NCap) * E) % NCap
        if left4a != right4a:
            return False

        # s^Z2 * t^Z4 must equal T^e * F (mod NCap)
        left4b = (gmpy2.powmod(s, Z2, NCap) * gmpy2.powmod(t, Z4, NCap)) % NCap
        right4b = (gmpy2.powmod(T, e, NCap) * F) % NCap
        if left4b != right4b:
            return False

        return True
