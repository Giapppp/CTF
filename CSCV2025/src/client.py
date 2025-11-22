import json
import socket
import os
import sys

from party import Party
from crypto.common.utils import deserialize_point
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

class RemoteParty:
    """A wrapper for a socket connection to handle JSON-based protocol communication."""

    def __init__(self, host: str, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host, port))
        except ConnectionRefusedError:
            print(f"[-] Connection refused at {host}:{port}. Is the server running?")
            sys.exit(1)
            
        # Create file-like objects for easy reading/writing of lines
        self.rfile = self.sock.makefile('r', encoding='utf-8')
        self.wfile = self.sock.makefile('w', encoding='utf-8')

        print(self.rfile.readline())

    def send_json(self, data: dict):
        """Sends a dictionary as a JSON string to the remote party, newline-terminated."""
        json_str = json.dumps(data)
        self.wfile.write(json_str + '\n')
        self.wfile.flush()

    def recv_json(self) -> dict:
        """Receives a newline-terminated JSON string from the remote party and parses it."""
        line = self.rfile.readline()
        if not line:
            raise EOFError("Connection closed by remote party.")
        
        response = json.loads(line)

        if response.get("status") != "ok":
            print("[!] Server returned an error!")
            print(json.dumps(response, indent=2))
            raise RuntimeError(
                f"Server error: {response.get('message', 'Unknown error')}"
            )

        return response.get("result", {})

    def command(self, phase: int, action: str, data=None) -> dict:
        """
        Sends a command to the remote party and returns the result from its response.
        Handles serialization of DTOs automatically.
        """
        payload = {
            "phase": phase,
            "action": action,
            "data": data.to_dict()
            if hasattr(data, "to_dict")
            else (data if data is not None else {}),
        }
        self.send_json(payload)
        return self.recv_json()

    def close(self):
        """Closes the connection to the remote party."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass # Socket might already be closed
        self.sock.close()


def main():
    """Main function to run the client and interact with the server."""
    HOST = os.environ.get("HOST", "localhost")
    PORT = int(os.environ.get("PORT", 1337))
    
    print(f"[*] Connecting to {HOST}:{PORT}...")
    p1 = RemoteParty(HOST, PORT)
    p0 = Party(0)

    try:
        # --- Phase 1: Keygen ---
        print("[+] --- Phase 1: Keygen ---")
        p1.command(phase=1, action="start_phase")
        p0.start_phase1()

        # Round 1 -> 2
        p0_r1_msg = p0.phase1_round1()
        p1_r1_data = p1.command(phase=1, action="round1")
        p1_r1_msg = KeygenRound1Message.from_dict(p1_r1_data)
        print("[*] Round 1 complete.")

        # Round 2 -> 3
        p0_r2_msg = p0.phase1_round2(p1_r1_msg)
        p1_r2_data = p1.command(phase=1, action="round2", data=p0_r1_msg)
        p1_r2_msg = KeygenRound2Message.from_dict(p1_r2_data)
        print("[*] Round 2 complete.")

        # Round 3 -> Out
        p0_r3_msg = p0.phase1_round3(p1_r2_msg)
        p1_r3_data = p1.command(phase=1, action="round3", data=p0_r2_msg)
        p1_r3_msg = KeygenRound3Message.from_dict(p1_r3_data)
        print("[*] Round 3 complete.")

        # Final Round
        p0_out_msg = p0.phase1_round_out(p1_r3_msg)
        p1_final_data = p1.command(phase=1, action="round_out", data=p0_r3_msg)
        X1 = deserialize_point(p1_final_data["X"])

        assert p0_out_msg.X == X1
        print(f"[+] Phase 1 (Keygen) successful. Agreed public key: {p0_out_msg.X.x}")

        # --- Phase 2: Aux ---
        print("[+] --- Phase 2: Aux Data Generation ---")
        p1.command(phase=2, action="start_phase")
        p0.start_phase2()

        p0_r1_msg = p0.phase2_round1()
        p1_r1_data = p1.command(phase=2, action="round1")
        p1_r1_msg = AuxRound1Message.from_dict(p1_r1_data)
        print("[*] Round 1 complete.")

        p0_r2_msg = p0.phase2_round2(p1_r1_msg)
        p1_r2_data = p1.command(phase=2, action="round2", data=p0_r1_msg)
        p1_r2_msg = AuxRound2Message.from_dict(p1_r2_data)
        print("[*] Round 2 complete.")

        p0_r3_msg = p0.phase2_round3(p1_r2_msg)
        p1_r3_data = p1.command(phase=2, action="round3", data=p0_r2_msg)
        p1_r3_msg = AuxRound3Message.from_dict(p1_r3_data)
        print("[*] Round 3 complete.")

        p0.phase2_round_out(p1_r3_msg)
        p1.command(phase=2, action="round_out", data=p0_r3_msg)
        print("[+] Phase 2 (Aux) successful.")

        # --- Phase 3 & 4 Loop ---
        for i in range(1, 4):
            print(f"\n[+] --- Signature #{i} ---")
            # --- Presigning ---
            print("[+] --- Phase 3: Presigning ---")
            p1.command(phase=3, action="start_phase")
            p0.start_phase3()

            p0_r1_msg = p0.phase3_round1()
            p1_r1_data = p1.command(phase=3, action="round1")
            p1_r1_msg = PresigningRound1Message.from_dict(p1_r1_data)
            print("[*] Round 1 complete.")

            p0_r2_msg = p0.phase3_round2(p1_r1_msg)
            p1_r2_data = p1.command(phase=3, action="round2", data=p0_r1_msg)
            p1_r2_msg = PresigningRound2Message.from_dict(p1_r2_data)
            print("[*] Round 2 complete.")

            p0_r3_msg = p0.phase3_round3(p1_r2_msg)
            p1_r3_data = p1.command(phase=3, action="round3", data=p0_r2_msg)
            p1_r3_msg = PresigningRound3Message.from_dict(p1_r3_data)
            print("[*] Round 3 complete.")

            p0_out_msg = p0.phase3_round_out(p1_r3_msg)
            p1_final_data = p1.command(phase=3, action="round_out", data=p0_r3_msg)
            R1 = deserialize_point(p1_final_data["R"])

            assert p0_out_msg.R == R1
            assert p0.presig_data.R == p0_out_msg.R
            print(f"[+] Phase 3 (Presigning) successful. Agreed R point: {p0_out_msg.R.x}")

            # --- Signing ---
            print("[+] --- Phase 4: Signing ---")
            p1.command(phase=4, action="start_phase")
            p0.start_phase4()

            message = f"This is test message #{i} for the CGGMP protocol".encode()
            message_hex = message.hex()

            p0_sigma_msg = p0.phase4_sign(message)
            p1_sigma_data = p1.command(phase=4, action="sign", data={"message": message_hex})
            p1_sigma_msg = SigningMessage.from_dict(p1_sigma_data)

            is_valid = p0.phase4_verify(message, p1_sigma_msg)
            p1.command(phase=4, action="verify", data=p0_sigma_msg)

            assert is_valid
            print("[+] Phase 4 (Signing) successful. Signature verified!")

        print("\n[+] Full protocol completed successfully.")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        print("[*] Closing connection.")
        p1.close()


if __name__ == "__main__":
    main()