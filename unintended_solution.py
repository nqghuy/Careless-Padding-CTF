from pwn import *

N = 16
KNOWN_PLAINTEXT = b'{"key": "hitcon{'

class PaddingOracle:
    def __init__(self):
        self.r = process(['python3', 'chal.py'])
        self.r.recvuntil(b"here's your encrypted key: ")

        self.message = bytes.fromhex(self.r.recvline().decode().strip())
        self.IV = self.message[0:16]
        self.FB = self.message[16:32]

        self.padding_db = []
        self._create_padding_database()
    
    def _create_padding_database(self):
        for i in range(256):
            special_iv = xor(self.IV, KNOWN_PLAINTEXT, i)
            self.padding_db.append(special_iv + self.FB)


    def check_padding(self, cipher):
        self.r.sendlineafter(b'Try unlock:', cipher.hex().encode())
        return b'weirdo' not in self.r.recvline()


    def leak_7_bits_last_2_bytes(self, _IV, C1):
        plaintext = [None] * N

        for pos in range(14, 16):
            for Y in range(256):
                match_count = 0
                found_diff = None

                for diff in range(0, 256, 2):
                    IV1_list = [255 ^ Y] * N
                    IV1_list[pos] = diff
                    cipher = bytes(IV1_list) + C1 + self.padding_db[Y]

                    if self.check_padding(cipher):
                        match_count += 1
                        found_diff = diff
                        if match_count >= 2:
                            break

                if match_count == 1:
                    plaintext[pos] = (_IV[pos] ^ Y ^ found_diff) & 0xfe
                    print(f"Byte {pos}: 0x{plaintext[pos]:02x}")
                    break
        print("abc", plaintext)
        return plaintext

    
    def leak_low_bit_byte14(self, _IV, C1, plaintext):
        pos = plaintext[14] % 16
        match_count = 0

        for j in range(0, 256, 2):
            block = [0] * N
            block[pos] = j
            block[14] ^= 0xf0
            cipher = xor(bytes(block), _IV) + C1

            if self.check_padding(cipher):
                match_count += 1
                if match_count >= 2:
                    return 1
        
        return 1 if match_count == 0 else 0
    
    def leak_7_bits_other_bytes(self, _IV, C1, plaintext):
        for i in range(14):
            block = [0] * N
            block[14] = plaintext[14] ^ i

            for j in range(256):
                block[i] = j
                cipher = xor(bytes(block), _IV) + C1

                if self.check_padding(cipher):
                    plaintext[i] = j ^ plaintext[15]
                    print(f"Byte {i}: 0x{plaintext[i]:02x}")
                    break

        return plaintext

    
    def leak_low_bit_byte15(self, _IV, C1, plaintext):
        cnt = 0
        for j in range(0, 256, 2):
            block = [0] * N
            block[13] = plaintext[13] ^ 2
            block[0] = j
            block[14] = plaintext[14]
            block[15] = plaintext[15]
            if self.check_padding(xor(bytes(block), _IV) + C1):
                cnt += 1
        return 1 if cnt == 1 else 0
    
    def leak_low_bits_other_bytes(self, C1, C2, plaintext):
        for pos in range(13, 0, -1):
            M = [0] * N

            for j in range(pos + 1, 15):
                M[j] = plaintext[j] ^ plaintext[15]
            M[pos] = plaintext[pos]

            match_count = 0
            for i in range(0, 256, 2):
                M[0] = i
                if self.check_padding(xor(bytes(M), C1) + C2):
                    match_count += 1
                    if match_count >= 2:
                        break
            if match_count == 0:
                plaintext[pos] += 1

        block = [0] * N
        for k in range(1, 15):
            block[k] = plaintext[k] ^ plaintext[15]
        block[0] = plaintext[0]

        if self.check_padding(xor(bytes(block), C1) + C2):
            plaintext[0] += 1
        return plaintext

    def decrypt_block(self, _IV, C1):
        print(f"\n[*] Leaking 7 bits of last 2 bytes...")
        plaintext = self.leak_7_bits_last_2_bytes(_IV, C1)

        print(f"[*] Leaking low bit of byte 14...")
        plaintext[14] += self.leak_low_bit_byte14(_IV, C1, plaintext)

        print(f"[*] Leaking 7 bits of other bytes...")
        plaintext = self.leak_7_bits_other_bytes(_IV, C1, plaintext)

        print(f"[*] Leaking low bit of byte 15...")
        plaintext[15] += self.leak_low_bit_byte15(_IV, C1, plaintext)

        print(f"[*] Leaking low bits of other bytes...")
        plaintext = self.leak_low_bits_other_bytes(_IV, C1, plaintext)

        plaintext_bytes = bytes(plaintext)
        print(f"[+] Plaintext: {plaintext_bytes}")
        return plaintext_bytes

    def attack(self):
        flag = bytearray(KNOWN_PLAINTEXT)

        for i in range(32, len(self.message), N):
            _IV = self.message[i - 16: i]
            C1 = self.message[i: i + 16]

            plaintext = self.decrypt_block(_IV, C1)
            flag.extend(plaintext)

        flag_str = flag.decode('utf-8', errors='ignore')
        print(f"\n{'='*60}")
        print(f"FLAG: {flag_str}")
        print(f"{'='*60}")
        real_flag = '{"key": "hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}"}8888888888'
        print(flag_str == real_flag)
        return flag_str

def main():
    oracle = PaddingOracle()
    oracle.attack()
    oracle.r.close()

if __name__ == "__main__":
    main()