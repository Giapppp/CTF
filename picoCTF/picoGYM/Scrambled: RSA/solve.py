from pwn import *
import string
import time

def send(text):
    target.recvuntil("me:")
    target.sendline(text)
    return str(target.recvline().strip())[15:-1]

def remove(check_str, txt):
    for c in check_str:
        txt = txt.replace(c, "")
    return txt

flag = "p"
target = remote("mercury.picoctf.net", 6276)
flag_full = str(target.recvline().strip())[8:-1]
alphabet = string.ascii_letters + "}" + "_" + string.digits + "{"
check_str = [send(flag)]


while "}" not in flag:
    try:
        for char in alphabet:
            print("check: " + char)
            temp_str = flag + char
            temp_chr = remove(check_str, send(temp_str))
            if temp_chr in flag_full:
                check_str.append(temp_chr)
                flag += char
                print("Flagggggggggggggggggggggggg: " + flag)
                break
    except:
        alphabet = string.ascii_letters + "}" + "_" + string.digits + "{"
        alphabet = flag + alphabet
        flag = "p"
        target = remote("mercury.picoctf.net", 6276)
        flag_full = str(target.recvline().strip())[8:-1]
        check_str = [send(flag)]
else:
    print(flag)
    print("Done!")
