#!/usr/bin/env python3

from random import randint

LFSR_SIZE = 8
flag = open("flag.txt", "rb").read()

def paddedbin(n: int, padding: int = LFSR_SIZE):
    return f"0b{bin(n)[2:].rjust(padding, '0')}"


def xor_all(things: list[int]):
    if len(things) == 0:
        return 0
    return things.pop(0) ^ xor_all(things)


def next_val(current_state: int, taps: list[int]) -> int:
    new_msb = xor_all([(current_state >> LFSR_SIZE-tap) & 1 for tap in taps])
    return (current_state >> 1) | (new_msb << LFSR_SIZE-1)


if __name__ == '__main__':
    current = 1 << LFSR_SIZE-1
    for _ in range(randint(2**8, 2**10)):
        current = next_val(current, [8, 5, 6, 4])
    flag_encryption_taps = [7, 8]
    total = []
    for char in flag:
        total.append(str(next_val(char, flag_encryption_taps) ^ current))
    print(" ".join(total))
