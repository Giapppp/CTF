from crypto.common.ec import Point, ECOperations
from crypto.common.paillier import PublicKey
from ecdsa.keygen import Keygen
from ecdsa.aux import Aux
from ecdsa.presigning import Presigning
from ecdsa.signing import Signing
from ecdsa.messages import (
    KeygenRound1Message,
    KeygenRound2Message,
    KeygenRound3Message,
    KeygenOutputMessage,
    AuxRound1Message,
    AuxRound2Message,
    AuxRound3Message,
    AuxOutputMessage,
    PresigningRound1Message,
    PresigningRound2Message,
    PresigningRound3Message,
    PresigningOutputMessage,
    SigningMessage,
    KeygenOutputData,
    AuxOutputData,
    PresigOutputData,
)


class Party:
    """
    Orchestrates the two-party threshold ECDSA protocol for a single participant.

    This class acts as a state machine, guiding the protocol through its phases:
    1. Keygen: Creates and agrees upon a shared public key.
    2. Aux: Generates auxiliary data like Paillier keys.
    3. Presigning: Creates a signature nonce (R value) without a message.
    4. Signing: Uses the presignature to sign a message.

    It manages the lifecycle of protocol handlers for each phase and the state
    that is passed between them.
    """

    def __init__(self, id: int):
        self.id = id
        self.ec = ECOperations()

        # Protocol-specific handlers, instantiated for the duration of a phase.
        self.keygen_protocol: Keygen = None
        self.aux_protocol: Aux = None
        self.presigning_protocol: Presigning = None
        self.signing_protocol: Signing = None

        # Stores the other party's messages between rounds within a single phase.
        self.p_other_msg_r1 = None

        # Stores the final, agreed-upon state from completed phases.
        self.keygen_data: KeygenOutputData = None
        self.aux_data: AuxOutputData = None
        self.presig_data: PresigOutputData = None

    def start_phase1(self):
        """Initializes the Keygen protocol."""
        self.keygen_protocol = Keygen(self.id, self.ec)

    def phase1_round1(self) -> KeygenRound1Message:
        return self.keygen_protocol.round1()

    def phase1_round2(self, msg_j_r1: KeygenRound1Message) -> KeygenRound2Message:
        # Store the other party's round 1 message for verification in round 3.
        self.p_other_msg_r1 = msg_j_r1
        return self.keygen_protocol.round2()

    def phase1_round3(self, msg_j_r2: KeygenRound2Message) -> KeygenRound3Message:
        return self.keygen_protocol.round3(self.p_other_msg_r1, msg_j_r2)

    def phase1_round_out(self, msg_j_r3: KeygenRound3Message) -> KeygenOutputMessage:
        """Finalizes the Keygen phase, stores its output, and cleans up."""
        idj = self.p_other_msg_r1.id
        self.keygen_data = self.keygen_protocol.round_out(idj, msg_j_r3)
        self.keygen_protocol = None
        self.p_other_msg_r1 = None
        return KeygenOutputMessage(X=self.keygen_data.X)

    def start_phase2(self):
        """Initializes the Aux protocol."""
        self.aux_protocol = Aux(self.id, self.ec, self.keygen_data.ssid)

    def phase2_round1(self) -> AuxRound1Message:
        return self.aux_protocol.round1()

    def phase2_round2(self, msg_j_r1: AuxRound1Message) -> AuxRound2Message:
        self.p_other_msg_r1 = msg_j_r1
        return self.aux_protocol.round2()

    def phase2_round3(self, msg_j_r2: AuxRound2Message) -> AuxRound3Message:
        return self.aux_protocol.round3(self.p_other_msg_r1, msg_j_r2)

    def phase2_round_out(self, msg_j_r3: AuxRound3Message) -> AuxOutputMessage:
        """Finalizes the Aux phase, stores its output, and cleans up."""
        self.aux_data = self.aux_protocol.round_out(msg_j_r3)
        self.aux_protocol = None
        self.p_other_msg_r1 = None
        return AuxOutputMessage(n=int(self.aux_data.paillier_pub_j.n))

    def start_phase3(self):
        """Initializes the Presigning protocol with state from previous phases."""
        if not self.keygen_data or not self.aux_data:
            raise RuntimeError(
                "Cannot start presigning without completing keygen and aux phases."
            )
        self.presigning_protocol = Presigning(
            self.id, self.ec, self.keygen_data, self.aux_data
        )

    def phase3_round1(self) -> PresigningRound1Message:
        return self.presigning_protocol.round1()

    def phase3_round2(
        self, msg_j_r1: PresigningRound1Message
    ) -> PresigningRound2Message:
        self.p_other_msg_r1 = msg_j_r1
        return self.presigning_protocol.round2(msg_j_r1)

    def phase3_round3(
        self, msg_j_r2: PresigningRound2Message
    ) -> PresigningRound3Message:
        # Round 3 needs the other party's G_ct from their Round 1 message.
        G_j_ct = self.p_other_msg_r1.G_ct
        return self.presigning_protocol.round3(G_j_ct, msg_j_r2)

    def phase3_round_out(
        self, msg_j_r3: PresigningRound3Message
    ) -> PresigningOutputMessage:
        """Finalizes the Presigning phase, stores its output, and cleans up."""
        self.presig_data = self.presigning_protocol.round_out(msg_j_r3)
        self.presigning_protocol = None
        self.p_other_msg_r1 = None
        return PresigningOutputMessage(R=self.presig_data.R)

    def start_phase4(self):
        """Initializes the Signing protocol handler."""
        if not self.keygen_data or not self.presig_data:
            raise RuntimeError(
                "Cannot start signing without completing keygen and presigning phases."
            )
        self.signing_protocol = Signing(
            self.id, self.ec, self.presig_data, self.keygen_data.X
        )

    def phase4_sign(self, message: bytes) -> SigningMessage:
        return self.signing_protocol.sign(message)

    def phase4_verify(self, message: bytes, msg_j: SigningMessage) -> bool:
        """Verifies the final signature and consumes the presignature data."""
        result = self.signing_protocol.verify(message, msg_j)

        # A presignature is a one-time-use object. Clear it to prevent reuse.
        # The protocol loops back to the presigning phase to generate a new one.
        self.signing_protocol = None
        self.presig_data = None
        return result

    def get_secret_key_xi(self) -> int:
        """Exposes the secret key share for the CTF challenge."""
        if self.keygen_data:
            return self.keygen_data.xi
        return None
