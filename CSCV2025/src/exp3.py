from pwn import *
import json
import math
import random
from sympy.ntheory.modular import crt
from dataclasses import astuple

from party import Party
from crypto.common.paillier import PublicKey, PrivateKey
from crypto.common.utils import serialize_point, deserialize_point, serialize_bytes_list, deserialize_bytes_list
from crypto.common.numbers import rejection_sample
from crypto.zkp.hash import sha512_256i
from crypto.zkp.prm import ProofPrm
from crypto.zkp.fac import ProofFac
from crypto.zkp.mod import ProofMod
from crypto.zkp.enc import ProofEnc
from crypto.zkp.logstar import ProofLogstar
from ecdsa.messages import *

def fake_mod_proof(ssid):
    pp = 164749022791188168631108908353403539035877921964276742418479713685623260643820944101104876318866742086619804587146844986287538445967320769639316849574286542038554967406262189485040459345102848218437027445769347835877251544977102383181474250605498126694266774100516051935157780534765989961839889283767115772383
    primes = [65353, 65357, 65371, 65381, 65393, 65407, 65413, 65419, 65423, 65437, 65447, 65449, 65479, 65497, 65519, 65521, 1522035470629694688903332768596209601109379557248362010792270177137371031475167911269450390692771537893181600961292276711490594023287255890997039661150749853297831195138035609632101937249221888418574393121562350303258114954171602127]
    N = 28286761241577418235930045487351479996889106127340471524168946617451064714126706717588815495595165234933543146017339266382047199102844690007448598256344800547354677395594753212044476776193748017813862565940984967821695883166363044612541913186009069844071013818115040544218339037153778647824102472195068126418482606820295295535505795190182266285931739584695475614419538510279037923321956661238410193917669209340434350236876522817010002108485134640826884726981689721896525764004594357913926440891210033526380375856203798436908729649012598545711860936269494665898492731139433425867274626981134292704657533135956197019487
    Iterations = 80
    phi_N = (pp - 1) * math.prod([pi - 1 for pi in primes])
    invN = pow(N, -1, phi_N)
    W = math.prod(primes)
    Y = [0] * Iterations
    for i in range(Iterations):
        prefix = [ssid, W, N] + Y[:i]
        ei = sha512_256i(*prefix)
        Y[i] = rejection_sample(N, ei)
    X = [0] * Iterations
    Z = [0] * Iterations
    Abz = bytearray([0xFF])
    Bbz = bytearray([0xFF])
    mp = (pp + 1)//4
    for i in range(Iterations):
        for j in range(4):
            a = (j & 1)
            b = 1
            Yi = Y[i] % N
            if a > 0:
                Yi = (-Yi) % N
            if b > 0:
                Yi = (W * Yi) % N
            Xpi = pow(Yi, pow(mp, 2, pp - 1), pp)
            Xi = (Xpi * W * pow(W, -1, pp)) % N
            if Yi != pow(Xi, 4, N):
                continue
            Zi = pow(Y[i] % N, invN, N)
            X[i], Z[i] = Xi, Zi
            Abz.append(a)
            Bbz.append(b)
            break
    A = int.from_bytes(bytes(Abz), 'big')
    B = int.from_bytes(bytes(Bbz), 'big')
    mod = ProofMod(W, X, A, B, Z)
    assert mod.verify(ssid, N)
    return N, primes, mod

def fake_logstar_proof(ssid, ec, pk, C, X, g, rho, x, NCap, s, t, prime):
    if any([c is None for c in[ec, pk, C, X, g, NCap, s, t, x, rho]]):
        raise ValueError("ProveLogstar constructor received nil value(s)")
    if ec.scalar_mult(C % ec.n, g) == X:
        raise ValueError("ProveLogstar is not provable")
    q = ec.n
    q3 = q * q * q
    qNCap = q * NCap
    q3NCap = q3 * NCap
    alpha = 1
    mu = random.randint(1, qNCap)
    r = random.randint(1, pk.n - 1)
    while math.gcd(r, pk.n) != 1:
        r = random.randint(1, pk.n - 1)
    gamma = random.randint(1, q3NCap)
    S = (pow(s, x, NCap) * pow(t, mu, NCap)) % NCap
    A = (pow(pk.gamma, alpha, pk.n_square) * pow(r, pk.n, pk.n_square)) % pk.n_square
    Y = ec.scalar_mult(alpha % q, g)
    D = (pow(s, alpha, NCap) * pow(t, gamma, NCap)) % NCap
    while True:
        e_hash = sha512_256i(ssid, pk.n, pk.gamma, ec.curve.b, ec.n, ec.p, C, X.x, X.y, g.x, g.y, S, A, Y.x, Y.y, D, NCap, s, t)
        e = rejection_sample(q, e_hash)
        if e % prime == 0:
            z1 = e * x + alpha
            z2 = (pow(rho % pk.n, e, pk.n) * (r % pk.n)) % pk.n
            z3 = e * mu + gamma
            return ProofLogstar(S, A, Y, D, z1, z2, z3).to_bytes_parts()
        else:
            alpha += 1
            A = (A * pk.gamma) % pk.n_square
            Y = ec.point_add(Y, g)
            D = (D * s) % NCap

def fake_enc_proof(ssid, ec, pk, K, NCap, s, t, k, rho, prime):
    q = ec.n
    q3 = q * q * q
    qNCap = q * NCap
    q3NCap = q3 * NCap
    alpha = 1
    mu = random.randint(1, qNCap)
    r = random.randint(1, pk.n - 1)
    while math.gcd(r, pk.n) != 1:
        r = random.randint(1, pk.n - 1)
    gamma = random.randint(1, q3NCap)
    S = (pow(s, k, NCap) * pow(t, mu, NCap)) % NCap
    A = (pow(pk.gamma, alpha, pk.n_square) * pow(r, pk.n, pk.n_square)) % pk.n_square
    C_ = (pow(s, alpha, NCap) * pow(t, gamma, NCap)) % NCap
    while True:
        e_hash = sha512_256i(ssid, pk.n, pk.gamma, ec.curve.b, ec.n, ec.p, NCap, s, t, K, S, A, C_)
        e = rejection_sample(q, e_hash)
        if e % prime == 0:
            z1 = e * k + alpha
            z2 = (pow(rho % pk.n, e, pk.n) * (r % pk.n)) % pk.n
            z3 = e * mu + gamma
            return ProofEnc(S, A, C_, z1, z2, z3)
        else:
            alpha += 1
            A = (A * pk.gamma) % pk.n_square
            C_ = (C_ * s) % NCap

io = process(["python3", "main.py"])
io.recvline()
p0 = Party(0)

p0.start_phase1()
io.sendline(json.dumps({"phase":1, "action":"start_phase"}).encode())
io.recvline()

recv = p0.phase1_round1()
id0, V0 = recv.id, recv.V
io.sendline(json.dumps({"phase":1, "action":"round1"}).encode())
recv = json.loads(io.recvline())["result"]
id1, V1 = [c for _, c in recv.items()]

msg_1_r1 = KeygenRound1Message(id=id1, V=V1)
recv = p0.phase1_round2(msg_1_r1)
rid0, X0, A0 = recv.rid, recv.X, recv.A
io.sendline(json.dumps({"phase":1, "action":"round2", "data":{"id": id0, "V": V0}}).encode())
recv = json.loads(io.recvline())["result"]
rid1, X1, A1 = [c for _, c in recv.items()]
X1 = deserialize_point(X1)
A1 = deserialize_point(A1)

msg_1_r2 = KeygenRound2Message(rid=rid1, X=X1, A=A1)
recv = p0.phase1_round3(msg_1_r2)
schX0, schA0, psi0 = recv.schX, recv.schA, recv.psi
io.sendline(json.dumps({"phase":1, "action":"round3", "data":{"rid": rid0, "X": serialize_point(X0), "A": serialize_point(A0)}}).encode())
recv = json.loads(io.recvline())["result"]
schX1, schA1, psi1 = [c for _, c in recv.items()]
schX1 = deserialize_bytes_list(schX1)
schA1 = deserialize_bytes_list(schA1)

msg_1_r3 = KeygenRound3Message(schX=schX1, schA=schA1, psi=psi1)
p0.phase1_round_out(msg_1_r3)
ssid0 = p0.keygen_data.ssid
io.sendline(json.dumps({"phase":1, "action":"round_out", "data":{"schX": serialize_bytes_list(schX0), "schA": serialize_bytes_list(schA0), "psi": psi0}}).encode())
recv = json.loads(io.recvline())["result"]

p0.start_phase2()
io.sendline(json.dumps({"phase":2, "action":"start_phase"}).encode())
io.recvline()

# Cheat in aux - part 1
recv = p0.phase2_round1()
id0, _ = recv.id, recv.V
paillier_pub_0_n, primes, _ = fake_mod_proof(ssid0)
p0.aux_protocol.p = math.prod(primes)
p0.aux_protocol.q = paillier_pub_0_n // math.prod(primes)
p0.aux_protocol.paillier_pub_i = PublicKey(paillier_pub_0_n)
p0.aux_protocol.paillier_priv_i = PrivateKey(paillier_pub_0_n, math.lcm(*[pi - 1 for pi in primes + [p0.aux_protocol.q]]), math.prod([pi - 1 for pi in primes + [p0.aux_protocol.q]]))
p0.aux_protocol.lamd = random.randint(1, p0.aux_protocol.paillier_priv_i.phi_n - 1)
r = random.randint(1, p0.aux_protocol.paillier_pub_i.n - 1)
p0.aux_protocol.ti = pow(r, 2, p0.aux_protocol.paillier_pub_i.n)
p0.aux_protocol.si = pow(p0.aux_protocol.ti, p0.aux_protocol.lamd, p0.aux_protocol.paillier_pub_i.n)
p0.aux_protocol.rhoi = random.randint(1, paillier_pub_0_n)
prm = ProofPrm.new_proof(ssid0, p0.aux_protocol.si, p0.aux_protocol.ti, p0.aux_protocol.paillier_priv_i.n, p0.aux_protocol.paillier_priv_i.phi_n, p0.aux_protocol.lamd)
p0.aux_protocol.prm_parts_i = prm.to_bytes_parts()
prm_parts_0_ints = [int.from_bytes(part, "big") for part in p0.aux_protocol.prm_parts_i]
V0 = sha512_256i(ssid0, id0, paillier_pub_0_n, p0.aux_protocol.si, p0.aux_protocol.ti, *prm_parts_0_ints, p0.aux_protocol.rhoi)
# Done 

io.sendline(json.dumps({"phase":2, "action":"round1"}).encode())
recv = json.loads(io.recvline())["result"]
id1, V1 = [c for _, c in recv.items()]

msg_1_r1 = AuxRound1Message(id=id1, V=V1)
_ = p0.phase2_round2(msg_1_r1)
io.sendline(json.dumps({"phase":2, "action":"round2", "data":{"id": id0, "V": V0}}).encode())
recv = json.loads(io.recvline())["result"]
paillier_pub_1_n, s1, t1, prm1, rho1 = [c for _, c in recv.items()]
prm1 = deserialize_bytes_list(prm1)

# Cheat in aux - part 2
msg_1_r2 = AuxRound2Message(n=paillier_pub_1_n, s=s1, t=t1, prm=prm1, rho=rho1)
_ = p0.phase2_round3(msg_1_r2)
rho = p0.aux_protocol.rhoi ^ rho1
_, _, mod0 = fake_mod_proof(ssid0 ^ rho)
mod_parts_0 = mod0.to_bytes_parts()
fac0 = ProofFac.new_proof(ssid0 ^ rho, p0.aux_protocol.ec, paillier_pub_0_n, paillier_pub_1_n, s1, t1, p0.aux_protocol.p, p0.aux_protocol.q)
fac_parts_0 = fac0.to_bytes_parts()
# Done

io.sendline(json.dumps({"phase":2, "action":"round3", "data":{"n": paillier_pub_0_n, "s": int(p0.aux_protocol.si), "t": int(p0.aux_protocol.ti), "prm": serialize_bytes_list(p0.aux_protocol.prm_parts_i), "rho": int(p0.aux_protocol.rhoi)}}).encode())
recv = json.loads(io.recvline())["result"]
mod1, fac1 = [c for _, c in recv.items()]
mod1 = deserialize_bytes_list(mod1)
fac1 = deserialize_bytes_list(fac1)
p0.aux_protocol.sj = s1
p0.aux_protocol.tj = t1
p0.aux_protocol.paillier_pub_j = PublicKey(paillier_pub_1_n)

msg_1_r3 = AuxRound3Message(mod=mod1, fac=fac1)
p0.phase2_round_out(msg_1_r3)
io.sendline(json.dumps({"phase":2, "action":"round_out", "data":{"n": paillier_pub_0_n, "mod": serialize_bytes_list(mod_parts_0), "fac": serialize_bytes_list(fac_parts_0)}}).encode())
recv = json.loads(io.recvline())["result"]

res = []
print(f"{primes[:-1] = }") 
for primei in primes[:-1]:
    np0 = paillier_pub_0_n // primei
    p0.start_phase3()
    io.sendline(json.dumps({"phase":3, "action":"start_phase"}).encode())
    io.recvline()

    # Cheat in Presigning - part 1
    _ = p0.phase3_round1()
    p0.presigning_protocol.k_i = 0
    p0.presigning_protocol.K_i_ct, p0.presigning_protocol.rho_i = p0.presigning_protocol.paillier_pub_i.encrypt_and_return_randomness(np0)
    p0.presigning_protocol.proof_enck_i = fake_enc_proof(ssid0, p0.ec, p0.presigning_protocol.paillier_pub_i, p0.presigning_protocol.K_i_ct, p0.presigning_protocol.paillier_pub_j.n, p0.presigning_protocol.sj, p0.presigning_protocol.tj, p0.presigning_protocol.k_i, p0.presigning_protocol.rho_i, primei)
    p0.presigning_protocol.proof_enck_part_i = p0.presigning_protocol.proof_enck_i.to_bytes_parts()
    K0ct, G0ct, proofenc0 = p0.presigning_protocol.K_i_ct, p0.presigning_protocol.G_i_ct, p0.presigning_protocol.proof_enck_part_i
    # Done

    io.sendline(json.dumps({"phase":3, "action":"round1"}).encode())
    recv = json.loads(io.recvline())["result"]
    K1ct, G1ct, proofenc1 = [c for _, c in recv.items()]
    proofenc1 = deserialize_bytes_list(proofenc1)

    msg_1_r1 = PresigningRound1Message(K_ct = K1ct, G_ct = G1ct, proofenc=proofenc1)
    recv = p0.phase3_round2(msg_1_r1)
    Gamma0, D10, _D10, F10, _F10, psi_10, _psi_10, __psi_10 = astuple(recv)
    io.sendline(json.dumps({"phase":3, "action":"round2", "data":{"proofenc": serialize_bytes_list(proofenc0), "K_ct": K0ct, "G_ct": G0ct}}).encode())
    recv = json.loads(io.recvline())["result"]
    Gamma1, D01, _D01, F01, _F01, psi_01, _psi_01, __psi_01 = [c for _, c in recv.items()]
    Gamma1 = deserialize_point(Gamma1)
    D01 = int(D01)
    _D01 = int(_D01)
    F01 = int(F01)
    _F01 = int(_F01)
    psi_01 = deserialize_bytes_list(psi_01)
    _psi_01 = deserialize_bytes_list(_psi_01)
    __psi_01 = deserialize_bytes_list(__psi_01)

    msg_1_r2 = PresigningRound2Message(Gamma=Gamma1, D=D01, _D=_D01, F=F01, _F=_F01, psi_affg_gamma=psi_01, psi_affg_xi=_psi_01, psi_logstar_gamma=__psi_01)
    _ = p0.phase3_round3(msg_1_r2)

    alpha_ij = p0.presigning_protocol.paillier_priv_i.decrypt(msg_1_r2.D)
    _alpha_ij = p0.presigning_protocol.paillier_priv_i.decrypt(msg_1_r2._D)
    yj = (alpha_ij - (alpha_ij % np0)) // np0
    _yj = (_alpha_ij - (_alpha_ij % np0)) // np0
    xpi = _yj
    print(f"x1 = {xpi} (mod {primei})")
    res.append(xpi)

    # Cheat in presigning - part 2
    alpha_ij %= np0
    _alpha_ij %= np0
    delta_0 = (p0.presigning_protocol.gamma_i * p0.presigning_protocol.k_i + alpha_ij + p0.presigning_protocol.beta_ij) % p0.ec.n
    vdelta_0 = p0.ec.scalar_mult(p0.presigning_protocol.k_i, p0.presigning_protocol.Gamma)
    p0.presigning_protocol.vdelta_i = vdelta_0
    p0.presigning_protocol.delta_i = delta_0
    p0.presigning_protocol.chi_i = (p0.presigning_protocol.xi * p0.presigning_protocol.k_i + _alpha_ij + p0.presigning_protocol._beta_ij) % p0.ec.n
    psi_10_ = fake_logstar_proof(ssid0, p0.ec, p0.presigning_protocol.paillier_pub_i, p0.presigning_protocol.K_i_ct, p0.presigning_protocol.vdelta_i, p0.presigning_protocol.Gamma, p0.presigning_protocol.rho_i, p0.presigning_protocol.k_i, p0.presigning_protocol.paillier_pub_j.n, p0.presigning_protocol.sj, p0.presigning_protocol.tj, primei)
    # Done

    io.sendline(json.dumps({"phase":3, "action":"round3", "data":{"Gamma": serialize_point(Gamma0), "G_ct": G0ct, "D": D10, "_D": _D10, "F": F10, "_F": _F10, "psi_affg_gamma": serialize_bytes_list(psi_10), "psi_affg_xi": serialize_bytes_list(_psi_10), "psi_logstar_gamma": serialize_bytes_list(__psi_10)}}).encode())
    recv = json.loads(io.recvline())["result"]
    delta_1, vdelta_1, psi_01_ = [c for _, c in recv.items()]
    delta_1 = int(delta_1)
    vdelta_1 = deserialize_point(vdelta_1)
    psi_01_ = deserialize_bytes_list(psi_01_)

    msg_1_r3 = PresigningRound3Message(delta=delta_1, vdelta=vdelta_1, psi=psi_01_)
    recv = p0.phase3_round_out(msg_1_r3)
    R0 = astuple(recv)
    io.sendline(json.dumps({"phase":3, "action":"round_out", "data":{"delta": int(delta_0), "vdelta": serialize_point(vdelta_0), "psi": serialize_bytes_list(psi_10_)}}).encode())
    recv = json.loads(io.recvline())["result"]
    R1 = [c for _, c in recv.items()]

    p0.start_phase4()
    io.sendline(json.dumps({"phase":4, "action":"start_phase"}).encode())
    io.recvline()

    msg = b"Hello, world!"
    recv = p0.phase4_sign(msg)
    sigma0 = recv.sigma
    io.sendline(json.dumps({"phase":4, "action":"sign", "data":{"message": msg.hex()}}).encode())
    recv = json.loads(io.recvline())["result"]
    sigma1 = int(recv["sigma"])

    msg_j = SigningMessage(sigma1)
    assert p0.phase4_verify(msg, msg_j)
    io.sendline(json.dumps({"phase":4, "action":"verify", "data":{"sigma": sigma0}}).encode())
    io.recvline()

x1 = crt(primes[:-1], res)[0] % p0.ec.n
print(f"{x1 = }")
io.sendline(json.dumps({"action":"guess_key", "data":{"guess":int(x1)}}).encode())
print(io.recvline())