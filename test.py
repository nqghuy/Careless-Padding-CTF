from pwn import *
from Crypto.Cipher import AES
import os

# Giả lập challenge
def simulate_oracle(iv, ciphertext, key):
    """Mô phỏng padding oracle của challenge"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # Simulate my_unpad with block_count = 1
    if len(plaintext) == 0:
        return False
    
    X = plaintext[-1]
    Y = plaintext[-1]  # Vì chỉ có 1 block
    
    # Index calculation với block_count = 1
    idx = (1-2)*16 + (X % 16)  # = -16 + (X%16)
    
    try:
        _Y = plaintext[idx]  # Negative indexing!
        # Padding valid nếu Y == _Y hoặc Y == _Y^1
        return (Y == _Y or Y == (_Y ^ 1))
    except:
        return False


def attack_single_block(oracle_func, target_ciphertext):
    """
    Tấn công single block để khôi phục plaintext
    
    Oracle: Hàm nhận (IV, ciphertext) và trả về True/False
    """
    C = target_ciphertext  # 16 bytes
    D = [None] * 16  # Decrypted intermediate state
    
    print("[*] Starting single block oracle attack...")
    print(f"[*] Target ciphertext: {C.hex()}")
    
    # Bước 1: Tìm D[15] (byte cuối)
    print("\n[*] Step 1: Finding D[15]...")
    for guess in range(256):
        # Tạo IV sao cho P[15] = guess
        IV = bytes([0]*15 + [guess])
        
        if oracle_func(IV, C):
            # Nếu padding valid với X = D[15] ⊕ guess
            X = D[15] ^ guess if D[15] is not None else 0
            
            # Thử xác nhận
            test_IV = bytes([0]*15 + [guess ^ 1])
            if oracle_func(test_IV, C):
                continue  # False positive
            
            D[15] = guess
            print(f"[+] Found D[15] = 0x{guess:02x}")
            break
    
    # Bước 2: Tìm các byte còn lại
    print("\n[*] Step 2: Finding remaining bytes...")
    
    for pos in range(14, -1, -1):
        print(f"[*] Finding D[{pos}]...")
        
        for guess in range(256):
            # Tạo plaintext có:
            # - P[15] = pos (để X%16 = pos, trỏ về P[pos])
            # - P[pos] = test_value
            
            IV = [0] * 16
            IV[15] = D[15] ^ pos  # Để P[15] = pos
            IV[pos] = guess       # Để P[pos] = D[pos] ⊕ guess
            
            if oracle_func(bytes(IV), C):
                # Padding valid: P[pos] == P[15] hoặc P[pos] == P[15]^1
                # P[pos] = D[pos] ⊕ guess
                # P[15] = pos
                
                # Test để xác nhận
                candidates = []
                
                # Case 1: P[pos] = pos (Y == _Y)
                if (D[pos] ^ guess if D[pos] is not None else guess) == pos:
                    candidates.append(guess)
                
                # Case 2: P[pos] = pos^1 (Y == _Y^1)
                if (D[pos] ^ guess if D[pos] is not None else guess) == (pos ^ 1):
                    candidates.append(guess)
                
                if candidates:
                    # Verify với một IV khác
                    test_guess = candidates[0]
                    test_IV = [1] * 16
                    test_IV[15] = D[15] ^ pos
                    test_IV[pos] = test_guess ^ 1
                    
                    if not oracle_func(bytes(test_IV), C):
                        D[pos] = test_guess
                        print(f"[+] Found D[{pos}] = 0x{test_guess:02x}")
                        break
    
    # Bước 3: Khôi phục plaintext gốc
    print("\n[*] Step 3: Recovering original plaintext...")
    # Cần IV gốc để khôi phục, nhưng với oracle ta có thể brute-force
    
    return D


def efficient_attack(oracle_func, target_ciphertext):
    """
    Tấn công hiệu quả sử dụng negative indexing vulnerability
    
    Thuật toán:
    1. Với mỗi vị trí i (0-15), ta muốn tìm D[i]
    2. Set IV để P[15] = i (trỏ về vị trí i)
    3. Brute-force D[i] bằng cách thay đổi IV[i]
    4. Oracle leak: padding valid khi P[i] == i hoặc P[i] == i^1
    """
    C = target_ciphertext
    D = [None] * 16
    
    print("[*] Efficient negative indexing attack...")
    print("[*] Exploiting: message[-16 + (X%16)] with single block\n")
    
    # Step 1: Tìm D[15] bằng cách thử các giá trị làm cho padding valid
    print("[*] Finding D[15] (last byte)...")
    for guess_d15 in range(256):
        # Thử tạo P[15] = 15, P[15] phải bằng chính nó hoặc 14
        # P[15] = D[15] ⊕ IV[15]
        # Để P[15] = 15: IV[15] = D[15] ⊕ 15
        
        IV = bytes([0]*15 + [guess_d15 ^ 15])
        if oracle_func(IV, C):
            # Verify: thử với giá trị khác
            test_IV = bytes([0]*15 + [guess_d15 ^ 14])
            if oracle_func(test_IV, C):
                # P[15] có thể là 14 hoặc 15
                pass
            else:
                # Chỉ P[15]=15 mới valid
                D[15] = guess_d15
                print(f"[+] D[15] = 0x{guess_d15:02x} (P[15] with original IV = {guess_d15 ^ 0:02x})")
                break
    
    if D[15] is None:
        print("[-] Failed to find D[15]")
        return None
    
    # Step 2: Tìm các byte D[0] đến D[14]
    for pos in range(15):
        print(f"[*] Finding D[{pos}]...")
        
        # Ta sẽ set P[15] = pos để _Y = P[pos]
        # Padding valid khi P[pos] == pos hoặc P[pos] == pos^1
        
        found = False
        for guess_d in range(256):
            # Tạo IV:
            # IV[15] = D[15] ⊕ pos  => P[15] = pos
            # IV[pos] = guess_d     => P[pos] = D[pos] ⊕ guess_d
            
            IV = [0] * 16
            IV[15] = D[15] ^ pos
            IV[pos] = guess_d
            
            if oracle_func(bytes(IV), C):
                # Oracle says valid!
                # This means: P[pos] == pos OR P[pos] == pos^1
                
                # Calculate P[pos] = D[pos] ⊕ guess_d
                # We need: D[pos] ⊕ guess_d == pos OR D[pos] ⊕ guess_d == pos^1
                
                # Try both cases:
                # Case 1: D[pos] = guess_d ⊕ pos
                candidate1 = guess_d ^ pos
                # Case 2: D[pos] = guess_d ⊕ (pos^1)
                candidate2 = guess_d ^ (pos ^ 1)
                
                # Verify with different IV
                for candidate in [candidate1, candidate2]:
                    verify_IV = [1] * 16
                    verify_IV[15] = D[15] ^ pos
                    verify_IV[pos] = candidate ^ 1  # Different value
                    
                    if not oracle_func(bytes(verify_IV), C):
                        D[pos] = candidate
                        print(f"[+] D[{pos}] = 0x{candidate:02x}")
                        found = True
                        break
                
                if found:
                    break
    
    return D


def recover_plaintext_with_original_iv(D, original_iv):
    """
    Sau khi có D, khôi phục plaintext gốc
    P = D ⊕ IV_original
    """
    if None in D:
        print("[-] Cannot recover: some D values are missing")
        return None
    
    plaintext = bytes([d ^ iv for d, iv in zip(D, original_iv)])
    return plaintext


# Example usage
if __name__ == "__main__":
    # Simulate a real scenario
    key = os.urandom(16)
    original_plaintext = b"SECRET_FLAG_HERE"
    original_iv = os.urandom(16)
    
    cipher = AES.new(key, AES.MODE_CBC, original_iv)
    ciphertext_block = cipher.encrypt(original_plaintext)
    
    print(f"Original plaintext: {original_plaintext}")
    print(f"Original IV: {original_iv.hex()}")
    print(f"Ciphertext: {ciphertext_block.hex()}")
    
    # Tạo oracle function
    def oracle(iv, ct):
        return simulate_oracle(iv, ct, key)
    
    # Attack!
    # D = attack_single_block(oracle, ciphertext_block)
    # print(f"\n[*] Recovered D values: {[f'0x{d:02x}' if d else None for d in D]}")
    
    # Với D và original_iv, ta khôi phục plaintext:
    # P = D ⊕ original_iv
    
    print("\n" + "="*60)
    print("Key Insight:")
    print("="*60)
    print("Khi block_count = 1:")
    print("  _Y = message[-16 + (X%16)] = message[X%16]")
    print("  => _Y và X cùng trong 1 block!")
    print("  => Ta có thể tạo plaintext với X tùy ý")
    print("  => Kiểm tra P[i] bằng cách set X = i")
    print("  => Oracle leak: P[i] == i hoặc P[i] == i^1")
    print("="*60)