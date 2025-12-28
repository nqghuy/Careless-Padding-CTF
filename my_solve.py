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
    
    def leak_7_high_bits(self, _IV, C1):
        plaintext = [None] * N

        for Y in range(256):
            # i from 0 to 15
            for i in range(N):
                if plaintext[i] is not None:
                    continue

                match_count = 0
                found_j = None

                for j in range(0, 256, 2):
                    IV1_list = [0] * N
                    IV1_list[i] = j
                    cipher = bytes(IV1_list) + C1 + self.padding_db[Y]

                    if self.check_padding(cipher):
                        match_count += 1
                        found_j = j
                        # false positive
                        if match_count >= 2:
                            break
                
                if match_count == 1:
                    plaintext[i] = (_IV[i] ^ Y ^ found_j) & 0xfe # get 7 high bits
                    print(f"Padding: {Y}   Found_j: {found_j}   IV'[{i}]: {_IV[i]}   Byte {i:2d}: 0x{plaintext[i]:02x}")
                    break

        return plaintext
        
    def leak_low_bit_byte14(self, C1, C2, high_bits):
        diff = [0] * N
        diff[14] = 0xf0
        
        for brute in range(0, 256, 2):
            IV1 = bytes([brute] + [0] * 15)
            IV2 = xor(bytes(diff), C1, bytes(high_bits))
            cipher = IV1 + IV2 + C2
            
            if self.check_padding(cipher):
                return 0
        return 1
    
    def leak_low_bit_byte15(self, _IV, C1, high_bits):
        pos = high_bits[14] & 1

        for j in range(0, 256, 2):
            IV1 = [0] * N
            IV1[pos] = j
            IV2 = xor(_IV, bytes(high_bits))
            cipher = bytes(IV1) + IV2 + C1

            if self.check_padding(cipher):
                return 1 - pos
        return pos
    
    def leak_low_bit_at_pos(self, _IV, C1, plaintext, pos):
        block = [0] * N
        block[pos] = 0xf0

        match_count = 0
        for j in range(0, 256, 2):
            IV1 = bytes([j] + [0] * 15)
            IV2 = xor(bytes(block), _IV, bytes(plaintext))
            cipher = IV1 + IV2 + C1

            if self.check_padding(cipher):
                match_count += 1
                if match_count >= 2:
                    break
        
        return 0 if match_count == 1 else 1
    
    def leak_low_bits(self, C1, C2, high_bits):
        plaintext = list(high_bits)
        
        plaintext[14] ^= self.leak_low_bit_byte14(C1, C2, plaintext)
        plaintext[15] ^= self.leak_low_bit_byte15(C1, C2, plaintext)
        
        for pos in range(13, -1, -1):
            plaintext[pos] ^= self.leak_low_bit_at_pos(C1, C2, plaintext, pos)
        
        return bytes(plaintext)
    
    def decrypt_block(self, _IV, C1):
        print(f"\n[*] Leaking 7 high bits...")
        high_bits = self.leak_7_high_bits(_IV, C1)

        print(f"[*] Leaking low bits...")
        # Lưu ý: Hàm leak_low_bits này cần bạn tự định nghĩa để gọi các hàm leak_low_bit_... ở trên
        plaintext = self.leak_low_bits(_IV, C1, high_bits) 

        print(f"[+] Plaintext: {plaintext}")
        return plaintext

    def attack(self):
        flag = bytearray(KNOWN_PLAINTEXT)

        for i in range(32, len(self.message), N):
            _IV = self.message[i - 16: i]
            C1 = self.message[i: i + 16]

            plaintext = self.decrypt_block(_IV, C1)
            flag.extend(plaintext)

        flag_str = flag.decode('utf-8', errors='ignore')
        print(f"{'='*60}")
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