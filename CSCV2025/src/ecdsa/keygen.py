import os
import gmpy2

from crypto.common.ec import ECOperations, Point
from crypto.zkp.hash import sha512_256i
from crypto.zkp.sch import ProofSch
from ecdsa.errors import VerificationError
from ecdsa.messages import (
    KeygenRound1Message,
    KeygenRound2Message,
    KeygenRound3Message,
    KeygenOutputData,
)


class Keygen:
    """
    Implements Phase 1 of the CGGMP protocol: Key Generation.

    This class manages the state for a single party through the interactive
    protocol to securely generate a shared ECDSA public key (X) without
    revealing the individual secret key shares (xi).
    """

    def __init__(self, id: int, ec: ECOperations):
        """Initializes the key generation state for a party."""
        self.id = id
        self.ec = ec

        # Initialize this party's secret share (xi) and public values (Xi, Ai).
        self.xi = gmpy2.mpz(self.ec.random_scalar())
        self.Xi = self.ec.scalar_mult(int(self.xi))
        self.rid = gmpy2.mpz(int.from_bytes(os.urandom(32), "big"))
        self.alphai, self.Ai = ProofSch.new_alpha(self.ec)

        # Create a commitment Vi to this party's public values.
        self.Vi = gmpy2.mpz(
            sha512_256i(
                self.id, int(self.rid), self.Xi.x, self.Xi.y, self.Ai.x, self.Ai.y
            )
        )

        # State from the other party, populated in subsequent rounds.
        self.Xj: Point = None
        self.Aj: Point = None
        self.srid: gmpy2.mpz = None

    def round1(self) -> KeygenRound1Message:
        """Generates the commitment message for the first round."""
        return KeygenRound1Message(id=self.id, V=int(self.Vi))

    def round2(self) -> KeygenRound2Message:
        """Generates the decommitment message for the second round."""
        return KeygenRound2Message(rid=int(self.rid), X=self.Xi, A=self.Ai)

    def round3(
        self, msg_j_r1: KeygenRound1Message, msg_j_r2: KeygenRound2Message
    ) -> KeygenRound3Message:
        """
        Verifies the other party's commitment and generates Schnorr proofs.

        Args:
            msg_j_r1: The other party's Round 1 commitment message.
            msg_j_r2: The other party's Round 2 decommitment message.

        Returns:
            A message containing Schnorr proofs of knowledge for this party's secrets.
        """
        self.Xj = msg_j_r2.X
        self.Aj = msg_j_r2.A

        # Verify that the other party's decommitment matches their Round 1 commitment.
        expected_Vj = sha512_256i(
            msg_j_r1.id, msg_j_r2.rid, self.Xj.x, self.Xj.y, self.Aj.x, self.Aj.y
        )
        if msg_j_r1.V != expected_Vj:
            raise VerificationError("Keygen Round 1 commitment verification failed.")

        # `srid` is the shared randomness used for Fiat-Shamir transforms.
        self.srid = self.rid ^ gmpy2.mpz(msg_j_r2.rid)

        # The ZKP library expects standard integer types for scalar values.
        schXi = ProofSch.new_proof_with_alpha(
            self.srid, self.ec, self.Xi, self.Ai, self.alphai, int(self.xi)
        )
        schAi = ProofSch.new_proof(self.srid, self.ec, self.Ai, self.alphai)

        # Create a commitment to the generated proofs.
        psii = sha512_256i(
            self.id, int(self.srid), schXi.A.x, schXi.Z, schAi.A.x, schAi.Z
        )

        return KeygenRound3Message(
            schX=schXi.to_bytes_parts(), schA=schAi.to_bytes_parts(), psi=psii
        )

    def round_out(self, idj: int, msg_j_r3: KeygenRound3Message) -> KeygenOutputData:
        """
        Verifies the other party's proofs and computes the final shared public key.

        Args:
            idj: The ID of the other party.
            msg_j_r3: The other party's Round 3 proof message.

        Returns:
            An object containing the results of the key generation phase.
        """
        schXj = ProofSch.from_bytes(self.ec, msg_j_r3.schX)
        schAj = ProofSch.from_bytes(self.ec, msg_j_r3.schA)

        # Verify the other party's commitment to their proofs.
        expected_psij = sha512_256i(
            idj, int(self.srid), schXj.A.x, schXj.Z, schAj.A.x, schAj.Z
        )
        if msg_j_r3.psi != expected_psij:
            raise VerificationError(
                "Keygen Round 3 psi commitment verification failed."
            )

        if schXj.A != self.Aj:
            raise VerificationError("Keygen Round 3 proof A value mismatch for schX.")

        # Verify the Schnorr proofs themselves.
        if not schXj.verify(self.srid, self.ec, self.Xj) or not schAj.verify(
            self.srid, self.ec, self.Aj
        ):
            raise VerificationError("Keygen Round 3 Schnorr proof verification failed.")

        # Compute the final shared public key by adding the parties' public shares.
        X = self.ec.point_add(self.Xi, self.Xj)

        return KeygenOutputData(
            ssid=int(self.srid), xi=int(self.xi), Xi=self.Xi, Xj=self.Xj, X=X
        )
