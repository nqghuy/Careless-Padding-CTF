from pwn import *

BLOCK_SIZE = 16
KNOWN_PLAINTEXT = b'{"key": "hitcon{'

class PaddingOracle:
    def __init__(self):
        self.r = process(['python3', 'chal.py'])
        self.r.recvuntil(b"here's your encrypted key: ")
        
        self.ciphertext = bytes.fromhex(self.r.recvline().decode().strip())
        self.IV = self.ciphertext[0:16]
        self.FB = self.ciphertext[16:32]
        
        self.padding_db = []
        self._create_padding_database()
    
    def _create_padding_database(self):
        for i in range(256):
            special_iv = xor(self.IV, KNOWN_PLAINTEXT, i)
            self.padding_db.append(special_iv + self.FB)
    
    def check_padding(self, cipher):
        self.r.sendlineafter(b'Try unlock:', cipher.hex().encode())
        return b'weirdo' not in self.r.recvline()
    
    def leak_7_high_bits(self, C1, C2):
        plaintext = [None] * BLOCK_SIZE
        
        for Y in range(256):
            for pos in range(BLOCK_SIZE):
                if plaintext[pos] is not None:
                    continue
                
                match_count = 0
                found_diff = None
                
                for diff in range(0, 256, 2):
                    IV1_list = [255 ^ Y] * BLOCK_SIZE
                    IV1_list[pos] = diff
                    cipher = bytes(IV1_list) + C2 + self.padding_db[Y]
                    
                    if self.check_padding(cipher):
                        match_count += 1
                        found_diff = diff
                        if match_count >= 2:
                            break
                
                if match_count == 1:
                    plaintext[pos] = (C1[pos] ^ Y ^ found_diff) & 0xfe
                    print(f"Byte {pos:2d}: 0x{plaintext[pos]:02x}")
                    break
        
        return plaintext
    
    def leak_low_bit_byte14(self, C1, C2, high_bits):
        diff = [0] * BLOCK_SIZE
        diff[14] = 0xf0
        
        for brute in range(0, 256, 2):
            IV1 = bytes([brute] + [0] * 15)
            IV2 = xor(bytes(diff), C1, bytes(high_bits))
            cipher = IV1 + IV2 + C2
            
            if self.check_padding(cipher):
                return 0
        return 1
    
    def leak_low_bit_byte15(self, C1, C2, high_bits):
        pos = high_bits[14] & 1
        
        for brute in range(0, 256, 2):
            IV1 = [0] * BLOCK_SIZE
            IV1[pos] = brute
            IV2 = xor(C1, bytes(high_bits))
            cipher = bytes(IV1) + IV2 + C2
            
            if self.check_padding(cipher):
                return 1 - pos
        return pos
    
    def leak_low_bit_at_pos(self, C1, C2, high_bits, pos):
        diff = [0] * BLOCK_SIZE
        diff[pos] = 0xf0
        
        match_count = 0
        for brute in range(0, 256, 2):
            IV1 = bytes([brute] + [0] * 15)
            IV2 = xor(bytes(diff), C1, bytes(high_bits))
            cipher = IV1 + IV2 + C2
            
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
    
    def decrypt_block(self, C1, C2):
        print(f"\n[*] Leaking 7 high bits...")
        high_bits = self.leak_7_high_bits(C1, C2)
        
        print(f"[*] Leaking low bits...")
        plaintext = self.leak_low_bits(C1, C2, high_bits)
        
        print(f"[+] Plaintext: {plaintext}")
        return plaintext
    
    def attack(self):
        flag = bytearray(KNOWN_PLAINTEXT)
        
        for i in range(32, len(self.ciphertext), BLOCK_SIZE):
            C1 = self.ciphertext[i - 16: i]
            C2 = self.ciphertext[i: i + 16]
            
            plaintext = self.decrypt_block(C1, C2)
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