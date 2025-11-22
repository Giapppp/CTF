import json
import sys
import traceback
from pathlib import Path

from party import Party
from ecdsa.errors import VerificationError
from ecdsa.messages import (
    KeygenRound1Message,
    KeygenRound2Message,
    KeygenRound3Message,
    AuxRound1Message,
    AuxRound2Message,
    AuxRound3Message,
    PresigningRound1Message,
    PresigningRound2Message,
    PresigningRound3Message,
    SigningMessage,
)


class Party1Client:
    """
    Acts as the server for Party 1, communicating with a client (Party 0) via JSON.
    It manages the protocol state machine, routing commands to the `Party` orchestrator
    and handling all serialization and deserialization of protocol messages.
    """

    def __init__(self):
        self.party = Party(1)
        self.current_phase = 1
        self.expected_action = "start_phase"
        self.message_cache = None  # Caches the message between sign and verify steps.
        self.signing_completed = (
            False  # Flag to enable guessing after a successful signature.
        )

        # Maps an incoming (phase, action) to the DTO class needed for deserialization.
        self.REQUEST_DTO_MAP = {
            (1, "round2"): KeygenRound1Message,
            (1, "round3"): KeygenRound2Message,
            (1, "round_out"): KeygenRound3Message,
            (2, "round2"): AuxRound1Message,
            (2, "round3"): AuxRound2Message,
            (2, "round_out"): AuxRound3Message,
            (3, "round2"): PresigningRound1Message,
            (3, "round3"): PresigningRound2Message,
            (3, "round_out"): PresigningRound3Message,
            (4, "verify"): SigningMessage,
        }

    def handle_guess_key(self, data: dict) -> dict:
        """
        Handles the CTF challenge action: guessing Party 1's secret key share.
        This action can only be called after at least one signing round is complete.
        """
        if not self.signing_completed:
            return {
                "correct": False,
                "message": "You must complete at least one successful signing round before guessing.",
            }

        guess = data.get("guess")
        if guess is None:
            return {"correct": False, "message": "No 'guess' key provided in data."}

        secret_key = self.party.get_secret_key_xi()
        if secret_key is None:
            return {
                "correct": False,
                "message": "Party1's key (phase 1) has not been generated yet.",
            }

        try:
            guessed_key = int(guess)
        except (ValueError, TypeError):
            return {
                "correct": False,
                "message": f"Guess must be an integer, but got: {type(guess)}",
            }

        if guessed_key == secret_key:
            try:
                flag = open(str(Path(__file__).parent / "flag.txt"), "r").read().strip()
                return {"correct": True, "flag": flag}
            except FileNotFoundError:
                return {"correct": True, "flag": "FLAG_FILE_NOT_FOUND"}
        else:
            return {"correct": False, "message": "Incorrect guess."}

    def process_command(self, command_json: str) -> dict:
        """Processes a single JSON command from the client."""
        try:
            command = json.loads(command_json)
            phase = command.get("phase")
            action = command.get("action")
            data = command.get("data", {})

            # Handle the CTF challenge action, which is exempt from the state machine.
            if action == "guess_key":
                result = self.handle_guess_key(data)
                return {"status": "ok", "action": "guess_key", "result": result}

            # Enforce the strict, sequential flow of the protocol.
            if phase != self.current_phase or action != self.expected_action:
                return {
                    "status": "error",
                    "message": "Protocol flow violation.",
                    "expected_phase": self.current_phase,
                    "expected_action": self.expected_action,
                    "received_phase": phase,
                    "received_action": action,
                }

            # Route the command to the appropriate handler.
            response_payload = None
            if action == "start_phase":
                getattr(self.party, f"start_phase{phase}")()
                response_payload = {"message": f"Started phase {phase}"}

            # Handle signing, which takes a raw message.
            elif phase == 4 and action == "sign":
                message_hex = data.get("message", "")
                message = bytes.fromhex(message_hex)
                self.message_cache = message
                response_payload = self.party.phase4_sign(message)

            # Handle verification.
            elif phase == 4 and action == "verify":
                msg_j = SigningMessage.from_dict(data)
                result = self.party.phase4_verify(self.message_cache, msg_j)
                response_payload = {"verify": result}
                self.message_cache = None
                # If verification was successful, allow the user to guess the key.
                if result is True:
                    self.signing_completed = True

            # Handle all other standard, round-based actions.
            else:
                party_method = getattr(self.party, f"phase{phase}_{action}")
                request_dto_cls = self.REQUEST_DTO_MAP.get((phase, action))

                args = []
                if request_dto_cls:
                    args.append(request_dto_cls.from_dict(data))

                response_payload = party_method(*args)

            # Serialize the response payload to a dictionary.
            if hasattr(response_payload, "to_dict"):
                result = response_payload.to_dict()
            else:
                result = response_payload  # For simple types like bool or dict.

            # Advance the state machine to the next expected action.
            if phase == 1:
                if action == "start_phase":
                    self.expected_action = "round1"
                elif action == "round1":
                    self.expected_action = "round2"
                elif action == "round2":
                    self.expected_action = "round3"
                elif action == "round3":
                    self.expected_action = "round_out"
                elif action == "round_out":
                    self.current_phase, self.expected_action = 2, "start_phase"
            elif phase == 2:
                if action == "start_phase":
                    self.expected_action = "round1"
                elif action == "round1":
                    self.expected_action = "round2"
                elif action == "round2":
                    self.expected_action = "round3"
                elif action == "round3":
                    self.expected_action = "round_out"
                elif action == "round_out":
                    self.current_phase, self.expected_action = 3, "start_phase"
            elif phase == 3:
                if action == "start_phase":
                    self.expected_action = "round1"
                elif action == "round1":
                    self.expected_action = "round2"
                elif action == "round2":
                    self.expected_action = "round3"
                elif action == "round3":
                    self.expected_action = "round_out"
                elif action == "round_out":
                    self.current_phase, self.expected_action = 4, "start_phase"
            elif phase == 4:
                if action == "start_phase":
                    self.expected_action = "sign"
                elif action == "sign":
                    self.expected_action = "verify"
                elif (
                    action == "verify"
                ):  # Loop back to presigning for another signature.
                    self.current_phase, self.expected_action = 3, "start_phase"

            return {"status": "ok", "action": action, "phase": phase, "result": result}

        except VerificationError as e:
            return {
                "status": "error",
                "message": f"Protocol verification failed: {e}",
                "type": "VerificationError",
            }
        except Exception:
            return {
                "status": "error",
                "message": "An unexpected server error occurred.",
                "traceback": traceback.format_exc(),
            }


def main():
    """Starts the Party 1 server and processes commands from stdin."""
    client = Party1Client()
    print("Party1 client started. Waiting for commands from party0...")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = client.process_command(line)
        print(json.dumps(response))
        sys.stdout.flush()
        if response["status"] != "ok":
            return


if __name__ == "__main__":
    main()
