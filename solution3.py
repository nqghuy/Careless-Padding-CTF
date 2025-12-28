from pwn import *
import json
from time import sleep

BLOCK_SIZE = 16
known_blocks = [b'{"key": "hitcon{'[:16]]
#until_now = b'{"key": "hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8'
#known_blocks = [until_now[i*16:(i+1)*16] for i in range(5)]

def get_X_and_Y_IV(soc, base_iv, base_cipher_block_1, base_cipher_block_2):
    X = None
    Y_iv = None
    for possible_X in range(BLOCK_SIZE):
        ivs = []
        for iv_value in range(256):
            iv = base_iv[:possible_X] + bytes([iv_value]) + base_iv[(possible_X+1):]
            assert(len(iv) == BLOCK_SIZE)
            ivs.append(iv)

        payload = [(iv + base_cipher_block_1 + base_cipher_block_2).hex() for iv in ivs]
        assert(len(payload[0]) == 2 * 3 * BLOCK_SIZE)
        soc.send(('\n'.join(payload) + '\n').encode())
        for i in range(256):
            line = soc.recvline()
            if not b'weirdo' in line:
                X = possible_X
                Y_iv = i
        if X is not None:
            return X, Y_iv
    raise ValueError("Could not find potential X")
    
soc = process(['python3', 'chal.py'])
soc.recvuntil(b"Anyway, here's your encrypted key: ")
data = bytes.fromhex(soc.recvline().strip().decode())
blocks_number = len(data) // BLOCK_SIZE + (len(data) % BLOCK_SIZE != 0)
soc.close()

def reset(block_to_guess_index):
    soc = process(['python3', 'chal.py'])
    soc.recvuntil(b"Anyway, here's your encrypted key: ")
    data = bytes.fromhex(soc.recvline().strip().decode())
    soc.recvline() # *********
    soc.recvline() # empty line
    base_iv = data[BLOCK_SIZE*(block_to_guess_index-1):BLOCK_SIZE*block_to_guess_index]
    base_cipher_blocks = [data[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)] for i in range(block_to_guess_index, len(data) // BLOCK_SIZE)]
    first_cipher_block = base_cipher_blocks[0]
    second_cipher_block = base_cipher_blocks[1]
    return soc, base_iv, first_cipher_block, second_cipher_block

for block_to_guess_index in range(1, blocks_number):
#for block_to_guess_index in range(5, blocks_number):

    # Reset socket so we have time to get another byte before timeout
    soc, base_iv, first_cipher_block, second_cipher_block = reset(block_to_guess_index)
    current_guessing = [0]*len(second_cipher_block) # Guessing of current block
    # Get the potential last two values for the block
    Xmod16, Y_iv = get_X_and_Y_IV(
        soc, 
        base_iv,
        base_cipher_block_1=first_cipher_block, 
        base_cipher_block_2=second_cipher_block
    )
    Y = known_blocks[-1][Xmod16] ^ Y_iv ^ base_iv[Xmod16]
    possibilities = [(Xmod16 + 16*i, Y) for i in range(16)] + [(Xmod16 + 16*i, Y^1) for i in range(16)]
    for possibility in possibilities:
        if not (48 <= possibility[0] <= 126) or not (48 <= possibility[1] <= 126):
            continue
        print(f"Trying {chr(possibility[0])}{chr(possibility[1])}")
        potentialX_1, _ = get_X_and_Y_IV(
            soc,
            base_iv,
            base_cipher_block_1=first_cipher_block[:-1] + bytes([possibility[0] ^ first_cipher_block[-1] ^ possibility[1]]),
            base_cipher_block_2=second_cipher_block
        )
        potentialX_2, _ = get_X_and_Y_IV(
            soc,
            base_iv,
            base_cipher_block_1=first_cipher_block[:-2] + bytes([possibility[0] ^ first_cipher_block[-2] ^ possibility[1]]) + first_cipher_block[-1:],
            base_cipher_block_2=second_cipher_block
        )
        if potentialX_1 == potentialX_2:
            print(f"Couple {possibility} looks good with X={potentialX_1}")
            current_guessing[-1] = possibility[1]
            current_guessing[-2] = possibility[0]
            potential_X = potentialX_1
            break
    else:
        if block_to_guess_index == 4:
            current_guessing[-1] = ord('8')
            current_guessing[-2] = ord('e')
            potential_X = 8
        elif block_to_guess_index == 5:
            current_guessing[-1] = ord('8')
            current_guessing[-2] = ord('8')
            potential_X = ord('}') % 16 
        else:
            raise ValueError(f"Could not find valid possibility in {possibilities}")
    
    # Now that we know the last two bytes, continue to leak bytes one by one
    for byte_index_to_guess in range(len(second_cipher_block) - 3, -1, -1):
        # Reset socket so we have time to get another byte before timeout
        soc, base_iv, first_cipher_block, second_cipher_block = reset(block_to_guess_index)
        
        possibilities = [potential_X + 16*i for i in range(16)]
        for possibility in possibilities:
            if not (48 <= possibility <= 126):
                continue
            current_guessing[byte_index_to_guess] = possibility
            # Set all last bytes to the potential value of X that we try to confirm
            block = bytes([possibility ^ first_cipher_block[i] ^ current_guessing[i] for i in range(byte_index_to_guess+1, BLOCK_SIZE, 1)])
            potentialX_1, _ = get_X_and_Y_IV(
                soc,
                base_iv,
                base_cipher_block_1=first_cipher_block[:byte_index_to_guess+1] + block,
                base_cipher_block_2=second_cipher_block
            )
            block = bytes([current_guessing[-1] ^ first_cipher_block[i] ^ current_guessing[i] for i in range(byte_index_to_guess, BLOCK_SIZE-1, 1)])
            potentialX_2, _ = get_X_and_Y_IV(
                soc,
                base_iv,
                base_cipher_block_1=first_cipher_block[:byte_index_to_guess] + block + bytes([first_cipher_block[-1]]),
                base_cipher_block_2=second_cipher_block
            )
            block = bytes([current_guessing[5] ^ first_cipher_block[i] ^ current_guessing[i] for i in range(byte_index_to_guess, BLOCK_SIZE, 1)])
            potentialX_3, _ = get_X_and_Y_IV(
                soc,
                base_iv,
                base_cipher_block_1=first_cipher_block[:byte_index_to_guess] + block,
                base_cipher_block_2=second_cipher_block
            )
            if potentialX_1 == potentialX_2 and potentialX_1 == potentialX_3:
                print(f"Possibility {possibility} looks good with X={potentialX_1}")
                current_guessing[byte_index_to_guess] = possibility
                potential_X = potentialX_1
                break
        else:
            # If we did not find a valid candidate, 
            # this means that the byte just before the one we are trying to is the same as the on we are trying to guess.
            # Or the same as the last one of the block
            print(f'Whoops, two bytes are equals {block_to_guess_index}')
            if block_to_guess_index == 3:
                if byte_index_to_guess == 8:
                    current_guessing[byte_index_to_guess] = ord('a')
                    potential_X = 1
                elif byte_index_to_guess == 7:
                    current_guessing[byte_index_to_guess] = ord('a')
                    potential_X = 7
                elif byte_index_to_guess == 6:
                    current_guessing[byte_index_to_guess] = ord('7')
                    potential_X = 1
                else:
                    raise ValueError(f"Could not find candidate fitting within {possibilities}")
            elif block_to_guess_index == 5:
                if byte_index_to_guess > 5:
                    current_guessing[byte_index_to_guess] = ord('8')
                    potential_X = ord('}') % 16
                elif byte_index_to_guess == 5:
                    current_guessing[byte_index_to_guess] = ord('}')
                    potential_X = ord('"') % 16
                elif byte_index_to_guess == 4:
                    current_guessing[byte_index_to_guess] = ord('"')
                    potential_X = ord('}') % 16
                else:
                    known_blocks.append(bytes(current_guessing))
                    print(''.join(block.decode() for block in known_blocks))
                    raise ValueError("Could not find candidate")
    

    known_blocks.append(bytes(current_guessing))
    print(''.join(block.decode() for block in known_blocks))