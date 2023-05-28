from pwn import *

target = remote("http://tjc.tf", int(31103))
msg = Integer(int(target.recvline().decode()))
s = Integer(int(target.recvline().decode()))

p = Integer(186568598167193943150281947234168669596704325205505209777649543618597641044067064505029420823614201204893878223541219243439921202321026283084690808922606812050293056628966983533373688918552403630496105017229792051753611307092746707247441926556199861172063152250642647282842168483517111867342214536507807550207)

q = 3

target.sendlineafter(b":", str(p).encode())
target.sendlineafter(b":", str(q).encode())

n = p * q
K = Zmod(n)

msg = K(msg)
s = K(s)
e = s.log(msg)
print(e)
target.sendlineafter(b":", str(e).encode())
print(target.recvline().decode())
print(target.recvline().decode())
