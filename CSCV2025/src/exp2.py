from pwn import *
import json
import math
import random
from sympy.ntheory.modular import crt
from dataclasses import astuple

from party import Party
from crypto.common.ec import ECOperations
from crypto.common.paillier import PublicKey, PrivateKey, generate_safe_prime
from crypto.common.utils import serialize_point, deserialize_point, serialize_bytes_list, deserialize_bytes_list
from crypto.zkp.hash import sha512_256i
from crypto.zkp.prm import ProofPrm
from crypto.zkp.affg import ProofAffg
from ecdsa.messages import *

def fake_prm_proof(ssid):
    p = 1393153522304808162483935201213706528350666865440694332820778681363446066163856175049373021208882797112097152287558175584764865508470282498564142843930576429006635483028253512987248901275409423314156948792786766805798106431905607187
    q = 17768028735300701855768854829727448694916861342130324853185063026349772037563356836192894094524360123150417483213973186647502824081699306731497458566500701322425292767224652553022383186450795205519289824453498645667173855822192817988842236421077380040697732609302918715532982608345108429684245821624346463874102137781704448715263175424773053435149822431578001862130175269211501063822383
    N = p * q
    g = pow(2, p - 1, N)
    Iterations = 80
    
    from sage.all import GF
    k = 0
    while True:
        try:
            k += 1
            alpha = k * p + 1
            tau = int(GF(q)(alpha).log(GF(q)(g)))    
            a = int.to_bytes(alpha, (alpha.bit_length() + 7) // 8, "big")
            beta = int.from_bytes(a + b"$" + a, "big")
            h = (alpha * pow(beta, -1, N)) % N

            Tau = [tau] * Iterations
            for l in range(Iterations):
                Alpha = [alpha] * l + [beta] * (Iterations - l)
                E = sha512_256i(* ([ssid, h, g, N] + Alpha))
                e = [(E >> i) & 1 for i in range(Iterations)]
                if sum(e) == Iterations - l:
                    for i in range(Iterations):
                        Alpha[i] = (alpha if e[i] == 0 else beta)
                    prm = ProofPrm(Alpha, Tau)
                    assert prm.verify(ssid, h, g, N) == True
                    return tau, N, p, g, h, ProofPrm(Alpha, Tau)
        except:
            continue

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


### Cheat in aux
recv = p0.phase2_round1()
id0, _ = recv.id, recv.V

tau0, n0, prime0, t0, s0, prm0 = fake_prm_proof(ssid0)
paillier_pub_0_n = n0
p0.aux_protocol.p = prime0
p0.aux_protocol.q = paillier_pub_0_n // prime0
p0.aux_protocol.paillier_pub_i = PublicKey(paillier_pub_0_n)
p0.aux_protocol.paillier_priv_i = PrivateKey(paillier_pub_0_n, math.lcm(p0.aux_protocol.p - 1, p0.aux_protocol.q - 1), math.prod([p0.aux_protocol.p - 1, p0.aux_protocol.q - 1]))

p0.aux_protocol.ti = t0
p0.aux_protocol.si = s0
p0.aux_protocol.rhoi = random.randint(1, paillier_pub_0_n)
p0.aux_protocol.prm_parts_i = prm0.to_bytes_parts()
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

msg_1_r2 = AuxRound2Message(n=paillier_pub_1_n, s=s1, t=t1, prm=prm1, rho=rho1)
recv = p0.phase2_round3(msg_1_r2)
mod0, fac0 = recv.mod, recv.fac
paillier_pub_0_n = p0.aux_protocol.paillier_pub_i.n

io.sendline(json.dumps({"phase":2, "action":"round3", "data":{"n": int(paillier_pub_0_n), "s": int(p0.aux_protocol.si), "t": int(p0.aux_protocol.ti), "prm": serialize_bytes_list(p0.aux_protocol.prm_parts_i), "rho": int(p0.aux_protocol.rhoi)}}).encode())
recv = json.loads(io.recvline())["result"]

mod1, fac1 = [c for _, c in recv.items()]
mod1 = deserialize_bytes_list(mod1)
fac1 = deserialize_bytes_list(fac1)
p0.aux_protocol.sj = s1
p0.aux_protocol.tj = t1
p0.aux_protocol.paillier_pub_j = PublicKey(paillier_pub_1_n)

msg_1_r3 = AuxRound3Message(mod=mod1, fac=fac1)
p0.phase2_round_out(msg_1_r3)
io.sendline(json.dumps({"phase":2, "action":"round_out", "data":{"n": int(paillier_pub_0_n), "mod": serialize_bytes_list(mod0), "fac": serialize_bytes_list(fac0)}}).encode())
recv = json.loads(io.recvline())["result"]

p0.start_phase3()
io.sendline(json.dumps({"phase":3, "action":"start_phase"}).encode())
io.recvline()
recv = p0.phase3_round1()
K0ct, G0ct, proofenc0 = recv.K_ct, recv.G_ct, recv.proofenc

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


paillier_priv_0 = p0.presigning_protocol.paillier_priv_i
k_0 = p0.presigning_protocol.k_i

msg_1_r2 = PresigningRound2Message(Gamma=Gamma1, D=D01, _D=_D01, F=F01, _F=_F01, psi_affg_gamma=psi_01, psi_affg_xi=_psi_01, psi_logstar_gamma=__psi_01)
recv = p0.phase3_round3(msg_1_r2)
delta_0, vdelta_0, psi_10_ = recv.delta, recv.vdelta, recv.psi

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

_psi_01 = ProofAffg.from_bytes(ECOperations(), _psi_01)
S = _psi_01.S

qrime0 = n0 // prime0

Si = pow(S, qrime0 - 1, n0)
s0i = pow(s0, qrime0 - 1, n0)
t0i = pow(t0, qrime0 - 1, n0)
assert s0i != 1 and t0i == 1

from sage.all import GF
x1 = int(GF(prime0)(Si).log(GF(prime0)(s0i)))
print(f"{x1 = }")
io.sendline(json.dumps({"action":"guess_key", "data":{"guess":int(x1)}}).encode())
print(io.recvline())