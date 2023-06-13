# SEETF 2023 

Lời giải của mình cho một số bài Cryptography trong giải SEETF 2023

## BabyRC4
> I have a simple RC4 encryption oracle. Shouldn't be that hard to break...right?

```python
from Crypto.Cipher import ARC4
from os import urandom
key = urandom(16)
flag = b'SEE{?????????????????????????????????}'[::-1]

def enc(ptxt):
    cipher = ARC4.new(key)
    return cipher.encrypt(ptxt)

print(f"c0 = bytes.fromhex('{enc(flag).hex()}')")
print(f"c1 = bytes.fromhex('{enc(b'a'*36).hex()}')")

"""
c0 = bytes.fromhex('b99665ef4329b168cc1d672dd51081b719e640286e1b0fb124403cb59ddb3cc74bda4fd85dfc')
c1 = bytes.fromhex('a5c237b6102db668ce467579c702d5af4bec7e7d4c0831e3707438a6a3c818d019d555fc')
"""
```

Bài này sử dụng thuật toán mã hóa RC4 là một loại stream cipher, trong đó keystream được sử dụng lại 2 lần, tức là: $$\begin{align*} flag \oplus keystream &= c_0 \\ msg1 \oplus keystream&= c_1 \end{align*}$$
trong đó `msg1 = b'a' * 36`

Ta có thể làm như sau để tìm flag: $$\begin{align*} flag \oplus msg1 &= c_0 \oplus c_1 \\ flag &= c_0 \oplus c_1 \oplus msg1 \end{align*}$$

`solve.py`
```python
from pwn import *

c0 = bytes.fromhex('b99665ef4329b168cc1d672dd51081b719e640286e1b0fb124403cb59ddb3cc74bda4fd85dfc')
c1 = bytes.fromhex('a5c237b6102db668ce467579c702d5af4bec7e7d4c0831e3707438a6a3c818d019d555fc')

ans = xor(c0, c1)
flag = xor(ans, b'a'*36)
print(flag[::-1])
```

## OpenEndedRSA

>I was told my RSA implementation is extremely insecure and vulnerable... I'll make this open ended for yall to take a look...find the vulnerability and I'll give you the flag!

```python
from Crypto.Util.number import *
from gmpy2 import iroot # this helps with super accurate square root calculations!

flag = b'????????????????????????'
m = bytes_to_long(flag)
e = 0x10001
pp = bytes_to_long(b'????????????????')
s = 1
assert isPrime(pp)

while not isPrime(s):
    p = getPrime(512)
    s = p**2 + pp**2 

assert iroot(s-pp**2,2) == (p, True)  # quick demo on how to use iroot()
assert s%2 == 1                       # duh, s is a prime number after all!

q = getPrime(512)
n = p*q
c = pow(m,e,n)

print(f'n = {n}')
print(f'e = {e}')
print(f'c = {c}')
print(f's = {s}')

"""
n = 102273879596517810990377282423472726027460443064683939304011542123196710774901060989067270532492298567093229128321692329740628450490799826352111218401958040398966213264648582167008910307308861267119229380385416523073063233676439205431787341959762456158735901628476769492808819670332459690695414384805355960329
e = 65537
c = 51295852362773645802164495088356504014656085673555383524516532497310520206771348899894261255951572784181072534252355368923583221684536838148556235818725495078521334113983852688551123368250626610738927980373728679163439512668552165205712876265795806444660262239275273091657848381708848495732343517789776957423
s = 128507372710876266809116441521071993373501360950301439928940005102517141449185048274058750442578112761334152960722557830781512085114879670147631965370048855192288440768620271468214898335819263102540763641617908275932788291551543955368740728922769245855304034817063220790250913667769787523374734049532482184053
"""
```
Do pp là rất nhỏ so với s (128 bits so với 512 bits) nên $\sqrt{s} \sim p$, từ đó ta có thể phân tích n. 
```python
from gmpy2 import iroot
from Crypto.Util.number import *
n = ...
e = ...
c = ...
s = ...

p = iroot(s, 2)[0]
assert GCD(p, n) > 1

q = n // p
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
flag = pow(c, d, n)
print(long_to_bytes(flag))
```

## Dumb Chall
>This sus pigeon wants to prove that an object is ultraviolet in colour, but I'm ultraviolet-blind!

```python
import random
import time
from Crypto.Util.number import bytes_to_long, isPrime

from secret import FLAG


def fail():
    print("You have disappointed the pigeon.")
    exit(-1)


def generate_prime_number(bits: int = 128) -> int:
    num = random.getrandbits(bits)
    while not isPrime(num):
        num += 1
    return num


def generate_random_boolean() -> bool:
    return bool(random.getrandbits(1))


def first_verify(g, p, y, C, w, r) -> bool:
    assert w
    return ((y * C) % p) == pow(g, w, p)


def second_verify(g, p, y, C, w, r) -> bool:
    assert r
    return pow(g, r, p) == C


p = generate_prime_number()
g = random.getrandbits(128)
x = bytes_to_long(FLAG.encode())
y = pow(g, x, p)

print(f"p = {p}")
print(f"g = {g}")
print(f"y = {y}")

print("Something something zero-knowledge proofs blah blah...")
print("Why not just issue the challenge and the verification at the same time? Saves TCP overhead!")

seen_c = set()
for round in range(30):
    w, r = None, None
    choice = generate_random_boolean()
    if not choice:
        w = int(input("Enter w: "))
        C = int(input("Enter C: "))
        if C in seen_c:
            fail()
        seen_c.add(C)
        verify = first_verify
    else:
        r = int(input("Enter r: "))
        C = int(input("Enter C: "))
        if C in seen_c:
            fail()
        seen_c.add(C)
        verify = second_verify
    if not verify(g, p, y, C, w, r):
        fail()
    else:
        print(f"You passed round {round + 1}.")
time.sleep(1)
print(
    "You were more likely to get hit by lightning than proof correctly 30 times in a row, you must know the secret right?"
)
print(f"A flag for your troubles - {FLAG}")
```

Trong bài này, ta được cho trước các số p, g, y. 
Challenge yêu cầu ta phải vượt qua 30 test, mỗi test sẽ yêu cầu chúng ta nhập cặp số (w, C) sao cho thỏa mãn `((y * C) % p) == pow(g, w, p)` hoặc (r, C) sao cho `pow(g, r, p) == C`.

Để vượt qua 30 test, trước mỗi test ta cần check xem challenge yêu cầu nhập 2 số (w, C) hay (r, C), sau đó random số C và tìm dlog trên $F_p$ . Lặp lại 30 lần như vậy và ta sẽ có flag
```python
#!/usr/bin/env sage
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
```

