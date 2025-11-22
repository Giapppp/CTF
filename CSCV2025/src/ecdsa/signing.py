import hashlib
import gmpy2

from crypto.common.ec import Point, ECOperations
from ecdsa.messages import PresigOutputData, SigningMessage
from ecdsa.errors import VerificationError


class Signing:
    """
    Handles the final signing phase of the two-party ECDSA protocol.

    This class uses pre-computed signature components (R, k_i, chi_i) from the
    presigning phase and the final public key X. It computes a signature share
    for a given message and can combine shares to verify the final signature.
    """

    def __init__(
        self, id: int, ec: ECOperations, presig_data: PresigOutputData, X: Point
    ):
        """
        Initializes the signing context for a party.

        Args:
            id: The party's identifier.
            ec: The elliptic curve operations handler.
            presig_data: Output from the presigning phase, containing R, k_i, and chi_i.
            X: The final combined public key for signature verification.

        Raises:
            ValueError: If the signature's r component is zero, which is invalid.
        """
        self.id = id
        self.ec = ec
        self.X = X
        self.R = presig_data.R

        # The 'r' component of an ECDSA signature is the x-coordinate of the nonce point R.
        self.r = gmpy2.mpz(self.R.x) % self.ec.n
        if self.r == 0:
            raise ValueError("r cannot be 0 in ECDSA")

        # Each party's secret shares for this specific signature.
        self.k_i = gmpy2.mpz(presig_data.k_i)
        self.chi_i = gmpy2.mpz(presig_data.chi_i)
        self.sigma_i: gmpy2.mpz = None

    def sign(self, message: bytes) -> SigningMessage:
        """
        Computes this party's signature share (sigma_i) for a given message.

        The share is calculated as: sigma_i = k_i * h + chi_i * r (mod n),
        where h is the SHA-256 hash of the message.

        Args:
            message: The message to be signed, as bytes.

        Returns:
            A SigningMessage containing the computed signature share.
        """
        h = gmpy2.mpz(int.from_bytes(hashlib.sha256(message).digest(), "big"))
        self.sigma_i = (self.k_i * h + self.chi_i * self.r) % self.ec.n
        return SigningMessage(sigma=int(self.sigma_i))

    def verify(self, message: bytes, msg_j: SigningMessage) -> bool:
        """
        Verifies the final combined ECDSA signature.

        This method combines its own share (sigma_i) with the other party's
        share (sigma_j) to compute the final signature value s. It then performs
        a standard ECDSA verification using the public key X, message hash h,
        and the signature pair (r, s).

        Args:
            message: The original message that was signed, as bytes.
            msg_j: A SigningMessage containing the other party's signature share.

        Returns:
            True if the signature is valid, False otherwise.
        """
        h = gmpy2.mpz(int.from_bytes(hashlib.sha256(message).digest(), "big"))
        # Combine shares to form the final 's' component of the signature.
        s = (self.sigma_i + gmpy2.mpz(msg_j.sigma)) % self.ec.n
        if s == 0:
            raise VerificationError("Signature S cannot be 0.")

        # Perform standard ECDSA verification.
        if not self.ec.verify(self.X, int(h), (int(self.r), int(s))):
            raise VerificationError("Signature verification failed.")

        return True
