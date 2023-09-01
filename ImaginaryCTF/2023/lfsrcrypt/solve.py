"""
s_{k+1}[7] = s_{k}[0] ^ s_{k}[1]
s_{k}[1] = s_{k+1}[0]

=> s_{k}[0] = s_{k+1}[7] ^ s_{k+1}[0]
"""
def xor_all(things: list[int]):
    if len(things) == 0:
        return 0
    return things.pop(0) ^ xor_all(things)

def next_val(current_state: int, taps: list[int]) -> int:
    new_msb = xor_all([(current_state >> LFSR_SIZE-tap) & 1 for tap in taps])
    return (current_state >> 1) | (new_msb << LFSR_SIZE-1)

def prev_val(current_state:int) -> int:
    old_lsb = xor_all([(current_state >> tap) & 1 for tap in [0, 7]])
    return ((current_state << 1) & 0xff) | old_lsb

LFSR_SIZE = 8
current = 1 << LFSR_SIZE-1

enc = "40 173 166 47 161 170 47 165 37 165 179 44 37 46 179 44 170 165 171 179 38 165 46 174 179 40 43 179 166 46 166 37 40 165 179 135 46 47 4 0 4 135 0 44 132 7 34"
enc = [int(c) for c in enc.split(" ")]

all_currents = []

for i in range(2**8, 2**10):
    for _ in range(i):
        current = next_val(current, [8, 5, 6, 4])
        all_currents.append(current)

#print(all_currents)
for current in all_currents:
    flag = []
    for c in enc:
        flag += [prev_val(c) ^ current]
    temp = bytes(flag)
    if b'ictf{' in temp:
        print(temp)
        break
