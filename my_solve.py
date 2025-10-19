from pwn import *

r = process(['python3', 'chal.py'])
# context.log_level = 'DEBUG'
r.recvuntil(b"here's your encrypted key: ")

ciphertext = bytes.fromhex(r.recvline().decode().strip())
IV = ciphertext[0:16]
FB = ciphertext[16:32]
known = b'{"key": "hitcon{'

db = []

# to make 256 version of X
def create_256_padding_version():
    for i in range(256):
        db.append(xor(IV, known, i) + FB)

def get_7_bits_top(C1, C2):
    # 2 blocks in db
    P2 = [b''] * 16
    cnt = 0
    for Y in range(256):

        for pos in range(16):
            found = False
            if P2[pos] != b'':
                continue
            for diff in range(0, 256, 2):
                first_cipher_bl = [255 ^ Y] * 16  
                first_cipher_bl[pos] = diff      
                IV1 = bytes(first_cipher_bl)    
                cipher = IV1 + C2 + db[Y]

                if check(cipher):
                    if diff == 0:
                        first_cipher_bl = [255 ^ Y] * 16  
                        first_cipher_bl[pos] = diff + 2    
                        IV1 = bytes(first_cipher_bl)     
                        test_cipher = IV1 + C2 + db[Y]
                        if check(test_cipher):
                            continue
                    else: 
                        found = True
                        found_diff = diff
                        break
            if found:
                P2[pos] = (C1[pos] ^ Y ^ found_diff) & 0xfe
                print(f"Found P2[{pos}] = {P2[pos]:02x} (Y={Y}, diff={found_diff})")
                break
    print(P2)
    return P2

# P1 is full, P2 is partial
def get_low_bit_in_byte14(C1, C2, top):
    lower = [0] * 16
    lower[14] = 0xf0
    for i in range(0, 256, 2):
        IV = [i] + [0] * 15
        cipher = bytes(IV) + xor(lower, C1, top) + C2
        if check(cipher):
            return 0
    return 1

def get_low_bit_in_byte15(C1, C2, top):
    pos = top[14] & 1
    for i in range(0, 256, 2):
        IV = [0] * 16
        IV[pos] = i
        cipher = bytes(IV) + xor(C1, top) + C2
        if check(cipher):
            return 1 - pos
    return pos

def get_bit_at_pos(C1, C2, top, pos):
    lower = [0] * 16
    lower[pos] = 0xf0
    for i in range(0, 256, 2):
        IV = [i] + [0] * 15
        cipher = bytes(IV) + xor(lower, C1, top) + C2
        if check(cipher):
            return 0
    return 1


def get_low_bit(C1, C2, top):
    top[14] ^= get_low_bit_in_byte14(C1, C2, top)
    top[15] ^= get_low_bit_in_byte15(C1, C2, top)
    for pos in range(13, -1, -1):
        top[pos] ^= get_bit_at_pos(C1, C2, top, pos)

    return top

def check(cipher):
    r.recvuntil(b'Try unlock:')
    r.sendline(cipher.hex().encode())
    
    return not b'weirdo' in r.recvline()

def attack():
    create_256_padding_version()
    flag = []
    for c in known:
        flag.append(c)
    for i in range(32, len(ciphertext), 16):
        IV = ciphertext[i - 32: i - 16]
        C1 = ciphertext[i - 16: i]
        C2 = ciphertext[i: i + 16]
        top = get_7_bits_top(C1, C2)
        full = get_low_bit(C1, C2, top)
        flag += full
        print(full)
    flag = [chr(i) for i in flag]
    flag = ''.join(flag)
    print(flag)
    print(len(flag))
    real_flag = b'{"key": "hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}"}8888888888'
    print(flag.encode() == real_flag)
    # for i in range(0 ,len(real_flag), 16):
    #     print(chr(real_flag[i + 15]))
if __name__ == "__main__":
    attack()

