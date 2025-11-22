"""
Implements the Multiplicative-to-Additive (MtA) share conversion protocol
as described in the CGGMP paper.
"""

from dataclasses import dataclass
import random
import gmpy2

from crypto.zkp.affg import ProofAffg
from crypto.common.ec import ECOperations, Point
from crypto.common.paillier import PublicKey
from crypto.common.numbers import rejection_sample


@dataclass
class MtAOut:
    """
    Represents the output of one party's MtA computation.

    This data is sent to the other party, who uses it to compute their
    additive share of the product.
    """

    # Enc_j(gamma_i * k_j + beta_neg), sent to party j
    Dji: int
    # Enc_i(beta_neg), used by party i to recover their share
    Fji: int
    # Randomness used for Paillier encryption of Dji and Fji
    sij: int
    rij: int
    # The additive share beta_ij
    beta: int
    # Zero-knowledge proof of correctness
    Proofji: ProofAffg


def new_mta(
    ssid: int,
    ec: ECOperations,
    Kj: int,
    gamma_i: int,
    BigGamma_i: Point,
    pkj: PublicKey,
    pki: PublicKey,
    NCap: int,
    s: int,
    t: int,
) -> MtAOut:
    """
    Executes Party i's computations for the MtA protocol.

    The goal is to securely convert a multiplicative sharing (gamma_i * k_j)
    into an additive sharing (alpha + beta) without revealing the inputs.

    Args:
        ssid: A unique session identifier for Fiat-Shamir ZKPs.
        ec: Elliptic curve operations.
        Kj: Paillier ciphertext of party j's secret, Enc_j(k_j).
        gamma_i: Party i's secret scalar.
        BigGamma_i: Public EC point corresponding to gamma_i (gamma_i * G).
        pkj: Party j's Paillier public key.
        pki: Party i's Paillier public key.
        NCap, s, t: Public Ring-Pedersen parameters for ZKPs.

    Returns:
        An MtAOut object containing ciphertexts and a ZKP for party j.
    """
    q = gmpy2.mpz(ec.n)
    q5 = q**5
    gamma_i_mpz = gmpy2.mpz(gamma_i)
    Kj_mpz = gmpy2.mpz(Kj)

    # Generate a large random blinding factor, beta_neg.
    # This value masks the product gamma_i * k_j.
    beta_neg = gmpy2.mpz(rejection_sample(int(q5), ssid))
    beta = q5 - beta_neg

    # 1. Homomorphically compute Enc_j(gamma_i * k_j).
    # This is done by raising the ciphertext of k_j to the plaintext power gamma_i.
    gamma_i_mod_nj = gamma_i_mpz % pkj.n
    gammaK = pkj.homo_mult(int(gamma_i_mod_nj), int(Kj_mpz))

    # 2. Homomorphically add the blinding factor to get Dji = Enc_j(gamma_i * k_j + beta_neg).
    # This ciphertext is sent to party j, who can decrypt it to get their share, alpha_ji.
    beta_neg_mod_nj = beta_neg % pkj.n
    Dji, sij = pkj.encrypt_and_return_randomness(int(beta_neg_mod_nj))
    Dji = pkj.homo_add(gammaK, Dji)

    # 3. Encrypt the blinding factor under our own key to get Fji = Enc_i(beta_neg).
    # This is not sent but is used in the ZKP to prove consistency.
    beta_neg_mod_ni = beta_neg % pki.n
    Fji, rij = pki.encrypt_and_return_randomness(int(beta_neg_mod_ni))

    # 4. Generate an Aff-g ZKP.
    # This proves that Dji and Fji were constructed correctly from the secret inputs
    # gamma_i and beta_neg, without revealing them.
    gamma_i_mod_q = gamma_i_mpz % q
    proof = ProofAffg.new_proof(
        ssid, ec, pkj, pki, NCap, s, t,
        int(Kj_mpz), Dji, Fji,
        BigGamma_i, int(gamma_i_mod_q), int(beta_neg),
        sij, rij,
    )

    return MtAOut(
        Dji=Dji,
        Fji=Fji,
        sij=sij,
        rij=rij,
        beta=int(beta),
        Proofji=proof,
    )
