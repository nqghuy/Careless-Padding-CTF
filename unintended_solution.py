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
    
    def leak_7_bits_last_2_bytes(self, C1, C2):
        plaintext = [None] * BLOCK_SIZE
        
        for pos in range(14, 16):
            for Y in range(256):
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
                    print(f"Byte {pos}: 0x{plaintext[pos]:02x}")
                    break
        
        return plaintext
    
    def leak_low_bit_byte14(self, C1, C2, plaintext):
        pos = plaintext[14] % 16
        match_count = 0
        
        for i in range(256):
            tmp = [0] * BLOCK_SIZE
            tmp[pos] = i
            tmp[14] ^= 0xf0
            cipher = xor(bytes(tmp), C1) + C2
            
            if self.check_padding(cipher):
                match_count += 1
                if match_count >= 3:
                    return 1
        
        return 1 if match_count == 0 else 0
    
    def leak_7_bits_other_bytes(self, C1, C2, plaintext):
        for pos in range(14):
            tmp = [0] * BLOCK_SIZE
            tmp[14] = plaintext[14] ^ pos
            
            for i in range(256):
                tmp[pos] = i
                cipher = xor(bytes(tmp), C1) + C2
                
                if self.check_padding(cipher):
                    plaintext[pos] = i ^ plaintext[15]
                    print(f"Byte {pos}: 0x{plaintext[pos]:02x}")
                    break
        
        return plaintext
    
    def leak_low_bit_byte15(self, C1, C2, plaintext):
        add = 2 if plaintext[15] % 16 == 0 else 0
        cnt1 = cnt2 = 0
        
        for i in range(0, 256, 2):
            tmp1 = [0] * BLOCK_SIZE
            tmp1[13] = plaintext[13]
            tmp1[0 + add] = i
            tmp1[14] = plaintext[14] ^ plaintext[15]
            
            tmp2 = [0] * BLOCK_SIZE
            tmp2[13] = plaintext[13]
            tmp2[1 + add] = i
            tmp2[14] = plaintext[14] ^ plaintext[15]
            
            if self.check_padding(xor(bytes(tmp1), C1) + C2):
                cnt1 += 1
            if self.check_padding(xor(bytes(tmp2), C1) + C2):
                cnt2 += 1
        
        return 0 if cnt1 == 1 or cnt2 == 1 else 1
    
    def leak_low_bits_other_bytes(self, C1, C2, plaintext):
        for pos in range(13, 0, -1):
            tmp = [0] * BLOCK_SIZE
            
            for j in range(pos + 1, 15):
                tmp[j] = plaintext[j] ^ plaintext[15]
            tmp[pos] = plaintext[pos]
            
            match_count = 0
            for i in range(0, 256, 2):
                tmp[0] = i
                if self.check_padding(xor(bytes(tmp), C1) + C2):
                    match_count += 1
                    if match_count >= 2:
                        break
            
            if match_count != 1:
                plaintext[pos] += 1
        
        tmp = [0] * BLOCK_SIZE
        for j in range(1, 15):
            tmp[j] = plaintext[j] ^ plaintext[15]
        tmp[0] = plaintext[0]
        
        if self.check_padding(xor(bytes(tmp), C1) + C2):
            plaintext[0] += 1
        
        return plaintext
    
    def decrypt_block(self, C1, C2):
        print(f"\n[*] Leaking 7 bits of last 2 bytes...")
        plaintext = self.leak_7_bits_last_2_bytes(C1, C2)
        
        print(f"[*] Leaking low bit of byte 14...")
        plaintext[14] += self.leak_low_bit_byte14(C1, C2, plaintext)
        
        print(f"[*] Leaking 7 bits of other bytes...")
        plaintext = self.leak_7_bits_other_bytes(C1, C2, plaintext)
        
        print(f"[*] Leaking low bit of byte 15...")
        plaintext[15] += self.leak_low_bit_byte15(C1, C2, plaintext)
        
        print(f"[*] Leaking low bits of other bytes...")
        plaintext = self.leak_low_bits_other_bytes(C1, C2, plaintext)
        
        plaintext_bytes = bytes(plaintext)
        print(f"[+] Plaintext: {plaintext_bytes}")
        return plaintext_bytes
    
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