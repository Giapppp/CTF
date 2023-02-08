from pwn import *
import string

target = remote("mercury.picoctf.net", 29350)

def send(text):

    target.recvuntil("encrypted:")
    target.sendline(text)
    target.recvline()
    target.recvline()
    return int(target.recvline())

flag = "picoCTF{"
alphabet = string.ascii_letters + "}" + "_"

length = send(flag)

while "}" not in flag:
    try:
        for c in alphabet:
            if send(flag + c) == length:
                flag += c
                print(flag)
    except:
        target = remote("mercury.picoctf.net", 29350)
