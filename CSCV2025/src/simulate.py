from party import Party


def main():
    """
    Simulates a full run of the 2-party ECDSA protocol using the API.
    This acts as an integration test for the entire system.
    """
    print("--- Initializing Parties ---")
    p0 = Party(0)
    p1 = Party(1)
    print("Parties initialized.\n")

    # --- Phase 1: Keygen ---
    print("--- Phase 1: Keygen ---")
    p0.start_phase1()
    p1.start_phase1()

    # Round 1: Exchange commitments
    p0_keygen_r1 = p0.phase1_round1()
    p1_keygen_r1 = p1.phase1_round1()
    print("Round 1 messages exchanged.")

    # Round 2: Exchange public shares
    p0_keygen_r2 = p0.phase1_round2(p1_keygen_r1)
    p1_keygen_r2 = p1.phase1_round2(p0_keygen_r1)
    print("Round 2 messages exchanged.")

    # Round 3: Exchange ZKPs
    p0_keygen_r3 = p0.phase1_round3(p1_keygen_r2)
    p1_keygen_r3 = p1.phase1_round3(p0_keygen_r2)
    print("Round 3 messages exchanged.")

    # Round Out: Finalize and compute public key
    p0_keygen_out = p0.phase1_round_out(p1_keygen_r3)
    p1_keygen_out = p1.phase1_round_out(p0_keygen_r3)

    assert p0_keygen_out.X == p1_keygen_out.X
    assert p0.keygen_data.X == p1.keygen_data.X
    print(f"Keygen successful. Agreed public key: {p0_keygen_out.X.x}")
    print("-----------------------\n")

    # --- Phase 2: Aux ---
    print("--- Phase 2: Aux Data ---")
    p0.start_phase2()
    p1.start_phase2()

    # Round 1: Exchange commitments
    p0_aux_r1 = p0.phase2_round1()
    p1_aux_r1 = p1.phase2_round1()
    print("Round 1 messages exchanged.")

    # Round 2: Exchange Paillier public keys and proofs
    p0_aux_r2 = p0.phase2_round2(p1_aux_r1)
    p1_aux_r2 = p1.phase2_round2(p0_aux_r1)
    print("Round 2 messages exchanged.")

    # Round 3: Exchange Mod and Fac proofs
    p0_aux_r3 = p0.phase2_round3(p1_aux_r2)
    p1_aux_r3 = p1.phase2_round3(p0_aux_r2)
    print("Round 3 messages exchanged.")

    # Round Out: Finalize and verify proofs
    p0_aux_out = p0.phase2_round_out(p1_aux_r3)
    p1_aux_out = p1.phase2_round_out(p0_aux_r3)

    assert p0_aux_out.n == p1.aux_data.paillier_pub_i.n
    assert p1_aux_out.n == p0.aux_data.paillier_pub_i.n
    print("Aux successful. Paillier keys exchanged and verified.")
    print("-------------------------\n")

    # --- Phase 3: Presigning ---
    print("--- Phase 3: Presigning ---")
    p0.start_phase3()
    p1.start_phase3()

    # Round 1: Exchange encrypted k_i, gamma_i
    p0_presig_r1 = p0.phase3_round1()
    p1_presig_r1 = p1.phase3_round1()
    print("Round 1 messages exchanged.")

    # Round 2: Exchange MtA results
    p0_presig_r2 = p0.phase3_round2(p1_presig_r1)
    p1_presig_r2 = p1.phase3_round2(p0_presig_r1)
    print("Round 2 messages exchanged.")

    # Round 3: Exchange delta shares
    p0_presig_r3 = p0.phase3_round3(p1_presig_r2)
    p1_presig_r3 = p1.phase3_round3(p0_presig_r2)
    print("Round 3 messages exchanged.")

    # Round Out: Finalize and compute R
    p0_presig_out = p0.phase3_round_out(p1_presig_r3)
    p1_presig_out = p1.phase3_round_out(p0_presig_r3)

    assert p0_presig_out.R == p1_presig_out.R
    # Also verify internal state was set correctly
    assert p0.presig_data.R == p0_presig_out.R
    print(f"Presigning successful. Agreed R point: {p0_presig_out.R.x}")
    print("-------------------------\n")

    # --- Phase 4: Signing ---
    print("--- Phase 4: Signing ---")
    p0.start_phase4()
    p1.start_phase4()

    message = b"Never gonna give you up, never gonna let you down"
    print(f"Signing message: '{message.decode()}'")

    # Sign: Exchange sigma shares
    sigma_msg_0 = p0.phase4_sign(message)
    sigma_msg_1 = p1.phase4_sign(message)
    print("Sigma shares exchanged.")

    # Verify: Combine shares and verify final signature
    is_valid_0 = p0.phase4_verify(message, sigma_msg_1)
    is_valid_1 = p1.phase4_verify(message, sigma_msg_0)

    assert is_valid_0 is True
    assert is_valid_1 is True
    print("Verification successful. Both parties produced a valid signature.")
    print("----------------------\n")

    print("✅ Full protocol simulation completed successfully!")


if __name__ == "__main__":
    main()
