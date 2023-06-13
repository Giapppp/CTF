from pwn import *
import random
import time
from tqdm import tqdm

target = remote("win.the.seetf.sg", int(3002))

p = int(target.recvline()[3:])
g = int(target.recvline()[3:])
y = int(target.recvline()[3:])

target.recvline()
target.recvline()

K = GF(p)
g = K(g)
y = K(y)

for i in range(30):
    print(f"Round {i+1}")
    check = target.recv()
    if check == b'Enter r: ':
        C = random.randint(1, p)
        C = K(C)
        r = C.log(g)
        target.sendline(str(r))
        target.sendlineafter(b":", str(C))
    else:
        C = K(random.randint(1, p))
        vt = K(C * y)
        w = vt.log(g)
        target.sendline(str(w))
        target.sendlineafter(b":", str(C))
    target.recvline()
    time.sleep(int(1))

print(target.recvline())
print(target.recvline())


