from dataclasses import dataclass, asdict, is_dataclass
from typing import List, get_type_hints, get_origin, get_args
import json
import gmpy2

from crypto.common.utils import (
    serialize_point,
    deserialize_point,
    serialize_bytes_list,
    deserialize_bytes_list,
)
from crypto.common.ec import Point
from crypto.common.paillier import PrivateKey, PublicKey


class ProtocolMessage:
    """
    Base class for protocol messages, providing JSON serialization and deserialization.
    It automatically handles the conversion of custom types like `Point` and `List[bytes]`.
    """

    def to_dict(self) -> dict:
        """Serializes the dataclass instance to a dictionary for JSON conversion."""
        data = {}
        for key, value in asdict(self).items():
            if isinstance(value, Point):
                data[key] = serialize_point(value)
            elif isinstance(value, list) and value and isinstance(value[0], bytes):
                data[key] = serialize_bytes_list(value)
            elif isinstance(value, gmpy2.mpz):
                # Convert gmpy2 integers to standard Python ints for JSON.
                data[key] = int(value)
            else:
                data[key] = value
        return data

    @classmethod
    def from_dict(cls, data: dict):
        """Deserializes a dictionary into a dataclass instance."""
        if not is_dataclass(cls):
            raise TypeError("from_dict can only be called on a dataclass")

        kwargs = {}
        type_hints = get_type_hints(cls)

        for field_name, field_type in type_hints.items():
            if field_name not in data:
                continue

            value = data[field_name]

            if field_type is Point:
                kwargs[field_name] = deserialize_point(value)
                continue

            origin = get_origin(field_type)
            args = get_args(field_type)
            if origin is list and args and args[0] is bytes:
                kwargs[field_name] = deserialize_bytes_list(value)
            else:
                kwargs[field_name] = value

        return cls(**kwargs)

    def to_json(self) -> str:
        """Serializes the message object to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str):
        """Deserializes a JSON string into a message object."""
        return cls.from_dict(json.loads(json_str))


# --- Phase 1: Keygen Messages ---


@dataclass
class KeygenRound1Message(ProtocolMessage):
    """Contains a party's ID and commitment `V` for the first round of key generation."""

    id: int
    V: int


@dataclass
class KeygenRound2Message(ProtocolMessage):
    """Contains a party's public key share `X`, Schnorr commitment `A`, and `rid`."""

    rid: int
    X: Point
    A: Point


@dataclass
class KeygenRound3Message(ProtocolMessage):
    """Contains Schnorr proofs for the knowledge of secret `xi` and randomness `alphai`."""

    schX: List[bytes]
    schA: List[bytes]
    psi: int


@dataclass
class KeygenOutputMessage(ProtocolMessage):
    """Broadcasts the final, commonly agreed-upon public key `X`."""

    X: Point


# --- Phase 2: Aux Data Messages ---


@dataclass
class AuxRound1Message(ProtocolMessage):
    """Contains a party's ID and commitment `V` for Paillier/RP parameter generation."""

    id: int
    V: int


@dataclass
class AuxRound2Message(ProtocolMessage):
    """Reveals a party's Paillier modulus `n` and Ring-Pedersen parameters `s`, `t`."""

    n: int
    s: int
    t: int
    prm: List[bytes]
    rho: int


@dataclass
class AuxRound3Message(ProtocolMessage):
    """Contains proofs of modulus primality (`mod`) and factor correctness (`fac`)."""

    mod: List[bytes]
    fac: List[bytes]


@dataclass
class AuxOutputMessage(ProtocolMessage):
    """Confirms the other party's Paillier modulus `n` after verification."""

    n: int


# --- Phase 3: Presigning Messages ---


@dataclass
class PresigningRound1Message(ProtocolMessage):
    """Contains encrypted ephemeral key shares `K_ct`, `G_ct`, and a proof of encryption."""

    K_ct: int
    G_ct: int
    proofenc: List[bytes]


@dataclass
class PresigningRound2Message(ProtocolMessage):
    """Contains the results of two MtA protocols and a proof of knowledge for `gamma_i`."""

    Gamma: Point
    D: int
    _D: int
    F: int
    _F: int
    psi_affg_gamma: List[bytes]  # Proof for MtA(k_j, gamma_i)
    psi_affg_xi: List[bytes]  # Proof for MtA(k_j, xi)
    psi_logstar_gamma: List[bytes]  # Proof for Enc(gamma_i)


@dataclass
class PresigningRound3Message(ProtocolMessage):
    """Contains this party's `delta_i` share and a proof of its correct computation."""

    delta: int
    vdelta: Point
    psi: List[bytes]


@dataclass
class PresigningOutputMessage(ProtocolMessage):
    """Broadcasts the final, commonly agreed-upon nonce commitment point `R`."""

    R: Point


# --- Phase 4: Signing Messages ---


@dataclass
class SigningMessage(ProtocolMessage):
    """Contains a party's signature share `sigma_i`."""

    sigma: int


# --- Internal State Containers ---
# These are not network messages. They are used internally to pass the verified
# results of one protocol phase as inputs to the next.


@dataclass
class KeygenOutputData:
    """Holds the verified state after the Keygen phase is complete."""

    ssid: int  # Shared Session ID, derived from both parties' inputs.
    xi: int  # This party's secret key share.
    Xi: Point  # This party's public key share.
    Xj: Point  # The other party's public key share.
    X: Point  # The final combined public key.


@dataclass
class AuxOutputData:
    """Holds the verified state after the Aux phase is complete."""

    paillier_priv_i: PrivateKey  # This party's Paillier private key.
    paillier_pub_i: PublicKey  # This party's Paillier public key.
    si: int  # This party's Ring-Pedersen `s` parameter.
    ti: int  # This party's Ring-Pedersen `t` parameter.
    paillier_pub_j: PublicKey  # The other party's Paillier public key.
    sj: int  # The other party's Ring-Pedersen `s` parameter.
    tj: int  # The other party's Ring-Pedersen `t` parameter.


@dataclass
class PresigOutputData:
    """Holds the presignature data generated in the Presigning phase."""

    R: Point  # The R point of the ECDSA signature (nonce commitment).
    k_i: int  # This party's nonce share.
    chi_i: int  # This party's `chi_i = k_i * x_i` share.
