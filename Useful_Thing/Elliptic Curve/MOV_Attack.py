"""
When the embedding degree k is small, we can use MOV Attack to transfer the discrete log from E(F_p) to F_p^k, which is easier to solve:

Resource: https://crypto.stanford.edu/pbc/notes/elliptic/movattack.html
"""

#Code: From ConnorM
#----------------------------------------------------------------------------#
#Check the embedding 
k = 1
while (p**k - 1) % E.order() != 0:
    k += 1

#MOV attack !!!
def MOV_attack(E, G, A, k):
    E2 = EllipticCurve(GF(p**k), [a,b])
    T = E2.random_point()
    M = T.order()
    N = G.order()
    T1 = (M//gcd(M, N)) * T
    _G = E2(G).weil_pairing(T1, N)
    _A = E2(A).weil_pairing(T1, N)
    nA = _A.log(_G)
    return nA
