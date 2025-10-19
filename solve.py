from pwn import *
from Crypto.Util.number import long_to_bytes
import time

N = 16

p = process(['python3', 'chal.py'])
# context.log_level = 'DEBUG'
#p = remote("127.0.0.1", 11111)
# p = remote("107.167.176.135", 11111)

p.recvuntil(b"key: ")
cipher = p.recvline()
cipher = bytes.fromhex(cipher.decode())
p.recvline()
p.recvline()

IV = cipher[:16]
FB = cipher[16:32]
Z = b"\x00"*16
I = [255]*16
known = b'{"key": "hitcon{'[:16]
IV0 = xor(IV, known)

oracle_count = 0

def oracle(m):
    global oracle_count
    oracle_count += 1
    p.sendline(m.hex().encode())
    return not b"weirdo" in p.recvline()

# async send to reduce network lag
def oracle_multi(ms):

    # res = [oracle(m) for m in ms]
    # return res

    global oracle_count
    l = len(ms)
    oracle_count += l
    for m in ms:
        p.sendline(m.hex().encode())
    res = [0] * l
    for i in range(l):
        res[i] = not b"weirdo" in p.recvline()
    return res

offset_db = [-1 for i in range(16)]

def get_offset_db():
    cur = 0
    for i in range(256):
        if not -1 in offset_db:
            break
        ciphers = []
        for offset in range(16):
            OFF = (offset ^ FB[-1]) % 16
            check = I[:]
            check[offset] = 0
            cipher = xor(IV0, check, i) + FB + xor(IV0, i) + FB
            ciphers.append(cipher)
        res = oracle_multi(ciphers)
        if res.count(True) == 1:
            offset = res.index(True)
            OFF = (offset ^ FB[-1]) % 16
            offset_db[OFF] = i
    return offset_db


def oracle_block_top(BIV, BC):
    res = [0] * 16

    for offset in range(16):
        # get top 7 bit
        real_offset = (offset ^ BC[-1]) % 16
        IVL = xor(IV0, offset_db[offset])
        top_7 = -1
        ciphers = []
        for diff in range(0, 256, 2):
            check = list(BIV[:])
            check[real_offset] ^= diff
            cipher = xor(BIV, check) + BC + IVL + FB
            ciphers.append(cipher)

        res2 = oracle_multi(ciphers)
        result = list(zip(res2, range(0, 256, 2)))
        for ora, diff in result:
            if ora:
                print(offset, diff)
                top_7 = (diff ^ BIV[real_offset] ^ offset_db[offset]) & 0xfe
                res[real_offset] = top_7
                break
        else:
            # honestly I don't know what happned here
            # Sometime things just fall through for some reason...
            raise ValueError("Padding not found")

    return res

def oracle_block_lower(BIV, BC, Mtop):
    # 14th byte first, use as anchor
    # make sure Mtop[-1] != Mtop[-2]
    # cipher: control IV1 | control IV2 | BC
    # IV2 -> BIV + offset to control Mtop decrypt result -> partial known X, Y
    # IV1 -> use to bruteforce all permutation
    lowers = [0] * 16

    baseIV = xor(BIV, Mtop) # so decrypt(BC, iv = baseIV) will only contain 0 or 1
    diff = [0] * 16
    diff[-2] = 0xf0 # make sure it don't propagate
    IV2 = xor(baseIV, diff)

    # we check if some value in the first location match
    # yes -> last bit of Mtop[-2] is 0
    # no  -> last bit of Mtop[-2] is 1
    ciphers = []
    for brute in range(0, 256, 2):
        IV1 = [brute] + [0] * 15
        ciphers.append(bytes(IV1) + IV2 + BC)

    if oracle_multi(ciphers).count(True) == 1:
        lowers[-2] = 0
    else:
        lowers[-2] = 1

    # now we check if the last bit is the same as Mtop[-2]
    diff = [0] * 16
    diff[-3] = 0xf8 # make sure it don't propagate
    IV2 = xor(baseIV, diff, lowers)
    # we check if some value in the first location match
    # yes -> Mtop[-2] is X -> last bit of Mtop[-1] is 1
    # no  -> Mtop[-2] is not X -> last bit of Mtop[-1] is 0
    ciphers = []
    for brute in range(0, 256, 2):
        IV1 = [brute] + [0] * 15
        ciphers.append(bytes(IV1) + IV2 + BC)

    if oracle_multi(ciphers).count(True) == 1:
        lowers[-1] = 1
    else:
        lowers[-1] = 0

    # now we can consistantly form repeating tail
    # fill the rest of the lower bits
    for loc in range(13, -1, -1):
        diff = [0] * 16
        diff[loc] = 0xf0 # make sure it don't propagate
        IV2 = xor(baseIV, diff, lowers)
        ciphers = []
        for brute in range(0, 256, 2):
            IV1 = [brute] + [0] * 15
            ciphers.append(bytes(IV1) + IV2 + BC)

        if oracle_multi(ciphers).count(True) == 1:
            lowers[loc] = 0
        else:
            lowers[loc] = 1

    return [i+j for i, j in zip(Mtop, lowers)]

def oracle_block(BIV, BC):
    tops = oracle_block_top(BIV, BC)
    full = oracle_block_lower(BIV, BC, tops)
    return full


def attack():
    offset_db = get_offset_db()
    print(offset_db)
    print(offset_db, oracle_count)
    m = known
    for loc in range(32, len(cipher), 16):
        m+=bytes(oracle_block(cipher[loc-16:loc], cipher[loc:loc+16]))
        print(m)

    print(m)
    print(oracle_count)


if __name__ == "__main__":
    attack()