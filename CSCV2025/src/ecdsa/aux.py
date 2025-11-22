import random
import gmpy2

from crypto.common.ec import ECOperations
from crypto.common.paillier import PublicKey, generate_key_pair
from crypto.zkp.hash import sha512_256i
from crypto.zkp.fac import ProofFac
from crypto.zkp.mod import ProofMod
from crypto.zkp.prm import ProofPrm
from ecdsa.errors import VerificationError
from ecdsa.messages import (
    AuxRound1Message,
    AuxRound2Message,
    AuxRound3Message,
    AuxOutputData,
)


class Aux:
    """
    Implements the Auxiliary Information Generation protocol (Phase 2).

    This phase securely generates and exchanges Paillier public keys and
    Ring-Pedersen parameters (`s`, `t`). These parameters are crucial for the
    Multiplicative-to-Additive (MtA) sub-protocol used in the presigning phase.
    The protocol uses a commit-and-reveal scheme and several Zero-Knowledge
    Proofs (ZKPs) to ensure the parameters are well-formed without revealing
    any secret information.
    """

    def __init__(self, party_id: int, ec: ECOperations, ssid: int):
        """
        Initializes the state for the Aux protocol.

        Args:
            party_id: The identifier for this party.
            ec: The elliptic curve operations instance.
            ssid: A unique Session ID for domain separation in hashes and proofs.
        """
        self.id = party_id
        self.ec = ec
        self.ssid = ssid

        # Generate this party's Paillier key pair. The modulus N must be a
        # product of two safe primes, but its factorization (p, q) is secret.
        paillier_priv_i, paillier_pub_i, p_int, q_int = generate_key_pair(2048)
        self.paillier_priv_i = paillier_priv_i
        self.paillier_pub_i = paillier_pub_i
        self.p = gmpy2.mpz(p_int)
        self.q = gmpy2.mpz(q_int)

        # Generate this party's Ring-Pedersen parameters (s, t) where s = t^lambda.
        # Lambda is a secret exponent.
        self.lamd = gmpy2.mpz(random.randrange(1, int(self.paillier_priv_i.phi_n)))
        r = gmpy2.mpz(random.randrange(1, int(self.paillier_pub_i.n)))
        self.rhoi = gmpy2.mpz(random.randrange(1, int(self.paillier_priv_i.n)))
        self.ti = gmpy2.powmod(r, 2, self.paillier_pub_i.n)
        self.si = gmpy2.powmod(self.ti, self.lamd, self.paillier_pub_i.n)

        # Generate a ZKP proving that we know lambda such that s_i = t_i^lambda mod N_i.
        prm = ProofPrm.new_proof(
            int(self.ssid),
            int(self.si),
            int(self.ti),
            int(self.paillier_priv_i.n),
            int(self.paillier_priv_i.phi_n),
            int(self.lamd),
        )
        self.prm_parts_i = prm.to_bytes_parts()

        # Placeholders for the other party's data, received in later rounds.
        self.paillier_pub_j: PublicKey = None
        self.sj: gmpy2.mpz = None
        self.tj: gmpy2.mpz = None

        self.rho: gmpy2.mpz = None

    def round1(self) -> AuxRound1Message:
        """
        Generates and returns a commitment to this party's public values.

        The commitment `V` prevents the other party from choosing their values
        based on ours in this interactive protocol.
        """
        prm_parts_i_ints = [int.from_bytes(part, "big") for part in self.prm_parts_i]
        Vi = sha512_256i(
            self.ssid,
            self.id,
            int(self.paillier_pub_i.n),
            int(self.si),
            int(self.ti),
            *prm_parts_i_ints,
            int(self.rhoi),
        )
        return AuxRound1Message(id=self.id, V=Vi)

    def round2(self) -> AuxRound2Message:
        """Returns the public values that were committed to in Round 1."""
        return AuxRound2Message(
            n=int(self.paillier_pub_i.n),
            s=int(self.si),
            t=int(self.ti),
            prm=self.prm_parts_i,
            rho=int(self.rhoi),
        )

    def round3(
        self, msg_j_r1: AuxRound1Message, msg_j_r2: AuxRound2Message
    ) -> AuxRound3Message:
        """
        Verifies the other party's commitment and proofs from previous rounds.

        If verification succeeds, it generates and returns ZKPs (Mod, Fac) about
        this party's Paillier modulus N_i.
        """
        if msg_j_r2.n.bit_length() < 2047:
            raise VerificationError(
                f"Other party's Paillier N is too small: {msg_j_r2.n.bit_length()} bits"
            )

        # Verify that the received values match the commitment from Round 1.
        prm_parts_j_ints = [int.from_bytes(part, "big") for part in msg_j_r2.prm]
        expected_Vj = sha512_256i(
            self.ssid,
            msg_j_r1.id,
            msg_j_r2.n,
            msg_j_r2.s,
            msg_j_r2.t,
            *prm_parts_j_ints,
            msg_j_r2.rho,
        )
        if msg_j_r1.V != expected_Vj:
            raise VerificationError("Aux Round 1 commitment verification failed.")

        self.sj = gmpy2.mpz(msg_j_r2.s)
        self.tj = gmpy2.mpz(msg_j_r2.t)
        self.paillier_pub_j = PublicKey(msg_j_r2.n)
        self.rho = self.rhoi ^ msg_j_r2.rho

        # Verify the other party's proof that they know the secret exponent for their s_j, t_j.
        prm_j = ProofPrm.from_bytes(msg_j_r2.prm)
        if not prm_j.verify(self.ssid, msg_j_r2.s, msg_j_r2.t, msg_j_r2.n):
            raise VerificationError("Other party's Prm proof verification failed.")

        # Prove that our N_i is a product of two safe primes (Mod proof).
        mod = ProofMod.new_proof(
            self.ssid ^ self.rho, int(self.paillier_pub_i.n), int(self.p), int(self.q)
        )

        # Prove that our N_i has no small factors, using the other party's N_j (Fac proof).
        fac = ProofFac.new_proof(
            self.ssid ^ self.rho,
            self.ec,
            int(self.paillier_pub_i.n),
            int(self.paillier_pub_j.n),
            int(self.sj),
            int(self.tj),
            int(self.p),
            int(self.q),
        )

        return AuxRound3Message(mod=mod.to_bytes_parts(), fac=fac.to_bytes_parts())

    def round_out(self, msg_j_r3: AuxRound3Message) -> AuxOutputData:
        """
        Verifies the final proofs from the other party and finalizes the protocol.

        If successful, it returns all necessary data for subsequent phases.
        """
        # Verify the other party's proof that their N_j is a product of two safe primes.
        mod_j = ProofMod.from_bytes(msg_j_r3.mod)
        if not mod_j.verify(self.ssid ^ self.rho, int(self.paillier_pub_j.n)):
            raise VerificationError("Other party's Mod proof verification failed.")

        # Verify the other party's proof that their N_j has no small factors.
        fac_j = ProofFac.from_bytes(msg_j_r3.fac)
        if not fac_j.verify(
            self.ssid ^ self.rho,
            self.ec,
            int(self.paillier_pub_j.n),
            int(self.paillier_pub_i.n),
            int(self.si),
            int(self.ti),
        ):
            raise VerificationError("Other party's Fac proof verification failed.")

        # All checks passed. Package the results for the next protocol phase.
        return AuxOutputData(
            paillier_priv_i=self.paillier_priv_i,
            paillier_pub_i=self.paillier_pub_i,
            si=int(self.si),
            ti=int(self.ti),
            paillier_pub_j=self.paillier_pub_j,
            sj=int(self.sj),
            tj=int(self.tj),
        )
