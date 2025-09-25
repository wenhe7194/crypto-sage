from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.finite_field_constructor import GF

R_poly, x_poly_var = PolynomialRing(GF(2), 'x_poly_var').objgen()

AES_modulus_poly = x_poly_var**8 + x_poly_var**4 + x_poly_var**3 + x_poly_var + 1
GF256_AES = GF(2**8, name='a_aes_gen', modulus=AES_modulus_poly)


def compute_sbox_dynamically():
    sbox_list = [0] * 256
    affine_transformation_constant = 0x63

    for i in range(256):
        if i == 0:
            inv_byte = 0
        else:
            field_element = GF256_AES.fetch_int(i)
            inverse_field_element = field_element**(-1)
            inv_byte = inverse_field_element.integer_representation()
        
        b = inv_byte
        transformed_byte = 0
        for bit_index in range(8):
            val = 0
            val = val ^^ ((b >> bit_index) & 1) \
                  ^^ ((b >> ((bit_index + 4) % 8)) & 1) \
                  ^^ ((b >> ((bit_index + 5) % 8)) & 1) \
                  ^^ ((b >> ((bit_index + 6) % 8)) & 1) \
                  ^^ ((b >> ((bit_index + 7) % 8)) & 1)
            val = val ^^ ((affine_transformation_constant >> bit_index) & 1)
            if val == 1:
                transformed_byte = transformed_byte | (1 << bit_index)
        sbox_list[i] = transformed_byte
    return sbox_list

Sbox = compute_sbox_dynamically()

def pkcs7_pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len) 
    return data + padding 

def xtime(a):
    return ((a << 1) ^^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

def gf_mul(a, b):
    res = 0
    for _ in range(8):
        if (b & 1):
            res = res ^^ a
        a = xtime(a)
        b >>= 1
    return res

Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91
]

def sub_bytes(state):
    return [[Sbox[byte_val] for byte_val in row] for row in state]

def shift_rows(state):
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][(c + r) % 4]
    return new_state

def mix_columns(state):
    res = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        res[0][c] = gf_mul(0x02, col[0]) ^^ gf_mul(0x03, col[1]) ^^ col[2]  ^^ col[3]
        res[1][c] = col[0] ^^ gf_mul(0x02, col[1]) ^^ gf_mul(0x03, col[2]) ^^ col[3]
        res[2][c] = col[0] ^^ col[1] ^^ gf_mul(0x02, col[2]) ^^ gf_mul(0x03, col[3])
        res[3][c] = gf_mul(0x03, col[0]) ^^ col[1] ^^ col[2] ^^ gf_mul(0x02, col[3])
    return res

def add_round_key(state, round_key_matrix):
    return [[state[r][c] ^^ round_key_matrix[r][c] for c in range(4)] for r in range(4)]

def bytes2matrix(text_bytes):
    matrix = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            matrix[r][c] = text_bytes[c*4 + r]
    return matrix

def matrix2bytes(matrix):
    byte_list = [0] * 16
    for r in range(4):
        for c in range(4):
            byte_list[c*4 + r] = matrix[r][c]
    return bytes(byte_list)

def key_expansion(key_bytes, key_size_in_bits):
    Nk = key_size_in_bits // 32
    if Nk == 4: Nr = 10
    elif Nk == 6: Nr = 12
    elif Nk == 8: Nr = 14
    Nb = 4
    w = [[0]*4 for _ in range(Nb * (Nr + 1))]
    for i in range(Nk):
        w[i] = list(key_bytes[4*i : 4*(i+1)])
    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(w[i-1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [Sbox[b] for b in temp]
            temp[0] = temp[0] ^^ Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = [Sbox[b] for b in temp]
        w[i] = [w[i-Nk][j] ^^ temp[j] for j in range(4)]
    round_keys_matrices = []
    for round_num in range(Nr + 1):
        round_key_matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            word_from_w = w[round_num * Nb + c]
            for r in range(4):
                round_key_matrix[r][c] = word_from_w[r]
        round_keys_matrices.append(round_key_matrix)
    return round_keys_matrices

def aes_encrypt_block(plaintext_block_bytes, key_bytes, key_size_in_bits=128):
    state = bytes2matrix(plaintext_block_bytes)
    round_keys = key_expansion(key_bytes, key_size_in_bits)
    if key_size_in_bits == 128: Nr = 10
    elif key_size_in_bits == 192: Nr = 12
    elif key_size_in_bits == 256: Nr = 14
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    return matrix2bytes(state)

def aes_cbc_encrypt(plaintext_bytes, key_bytes, iv_bytes, key_size_in_bits=128):
    padded_plaintext = pkcs7_pad(plaintext_bytes, 16)
    ciphertext = bytearray()
    previous_cipher_block = iv_bytes
    for i in range(0, len(plaintext_bytes), 16):
        current_plain_block = plaintext_bytes[i : i+16]
        block_to_encrypt = bytes([p_byte ^^ c_byte for p_byte, c_byte in zip(current_plain_block, previous_cipher_block)])
        encrypted_block = aes_encrypt_block(block_to_encrypt, key_bytes, key_size_in_bits)
        ciphertext.extend(encrypted_block)
        previous_cipher_block = encrypted_block
    return bytes(ciphertext)

def aes_ctr_encrypt(plaintext_bytes, key_bytes, nonce_bytes, key_size_in_bits=128):
    from copy import deepcopy
    ciphertext = bytearray()
    counter_block = bytearray(nonce_bytes)
    for i in range(0, len(plaintext_bytes), 16):
        keystream_block = aes_encrypt_block(bytes(counter_block), key_bytes, key_size_in_bits)
        plain_segment = plaintext_bytes[i : i + len(keystream_block)]
        actual_keystream_segment = keystream_block[:len(plain_segment)]
        cipher_segment = bytes([p_byte ^^ k_byte for p_byte, k_byte in zip(plain_segment, actual_keystream_segment)])
        ciphertext.extend(cipher_segment)
        for j in range(15, 7, -1):
            counter_block[j] = (counter_block[j] + 1) & 0xFF
            if counter_block[j] != 0:
                break
    return bytes(ciphertext)

def hexstr_to_bytes(hex_string):
    cleaned_hex_string = hex_string.replace(' ', '').replace('\n', '')
    return bytes.fromhex(cleaned_hex_string)

if __name__ == '__main__':
    pt_hex = (
        "6BC1BEE2 2E409F96 E93D7E11 7393172A" 
        "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
        "30C81C46 A35CE411 E5FBC119 1A0A52EF" 
        "F69F2445 DF4F9B17 AD2B417B E66C3710"
    )
    plaintext = hexstr_to_bytes(pt_hex)
    key_128_hex = "2B7E1516 28AED2A6 ABF71588 09CF4F3C"
    key_128 = hexstr_to_bytes(key_128_hex)
    key_128_bits = 128
    iv_hex = "00010203 04050607 08090A0B 0C0D0E0F"
    iv = hexstr_to_bytes(iv_hex)
    print("--- AES-128 CBC Encryption ---")
    ciphertext_cbc = aes_cbc_encrypt(plaintext, key_128, iv, key_size_in_bits=key_128_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_cbc), 16):
        print(ciphertext_cbc[i:i+16].hex().upper())

    print("\n--- AES-192 CBC Encryption ---")
    key_192_hex = (
        "8E73B0F7 DA0E6452 C810F32B 809079E5"
        "62F8EAD2 522C6B7B"
    )
    key_192 = hexstr_to_bytes(key_192_hex)
    key_192_bits = 192
    ciphertext_cbc_192 = aes_cbc_encrypt(plaintext, key_192, iv, key_size_in_bits=key_192_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_cbc_192), 16):
        print(ciphertext_cbc_192[i:i+16].hex().upper())

    print("\n--- AES-256 CBC Encryption ---")
    key_256_hex = (
        "603DEB1015CA71BE2B73AEF0857D7781"
        "1F352C073B6108D72D9810A30914DFF4"
    )
    key_256 = hexstr_to_bytes(key_256_hex)
    key_256_bits = 256
    ciphertext_cbc_256 = aes_cbc_encrypt(plaintext, key_256, iv, key_size_in_bits=key_256_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_cbc_256), 16):
        print(ciphertext_cbc_256[i:i+16].hex().upper())

    print("\n--- AES-128 CTR Encryption ---")
    ctr_hex = "F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF"
    nonce_ctr = hexstr_to_bytes(ctr_hex)
    ciphertext_ctr = aes_ctr_encrypt(plaintext, key_128, nonce_ctr, key_size_in_bits=key_128_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_ctr), 16):
        print(ciphertext_ctr[i:i+16].hex().upper())

    print("\n--- AES-192 CTR Encryption ---")
    ciphertext_ctr = aes_ctr_encrypt(plaintext, key_192, nonce_ctr, key_size_in_bits=key_192_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_ctr), 16):
        print(ciphertext_ctr[i:i+16].hex().upper())

    print("\n--- AES-256 CTR Encryption ---")
    ciphertext_ctr = aes_ctr_encrypt(plaintext, key_256, nonce_ctr, key_size_in_bits=key_256_bits)
    print("\nCiphertext:")
    for i in range(0, len(ciphertext_ctr), 16):
        print(ciphertext_ctr[i:i+16].hex().upper())
