def generate_rsa_keys(security_param_bits=1024): 
    half_bit_length = security_param_bits // 2
    p = random_prime(2^half_bit_length - 1, lbound=2^(half_bit_length - 1)) 
    q = random_prime(2^half_bit_length - 1, lbound=2^(half_bit_length - 1))
    while p == q: 
        q = random_prime(2^half_bit_length - 1, lbound=2^(half_bit_length - 1))

    N = p * q 
    phi_N = (p - 1) * (q - 1) 

    e = 65537 
    while gcd(e, phi_N) != 1:
        e = Primes().next(e) 

    d = power_mod(e, -1, phi_N) 

    return N, e, d, p, q


def key_gen(security_param_bits=1024):
    N, e, d, _p, _q = generate_rsa_keys(security_param_bits)
    public_key_pk = (N, e) 
    private_key_sk = (N, d) 
    return public_key_pk, private_key_sk


def encrypt_message(public_key_pk, message_m):
    N, e = public_key_pk
    c = power_mod(message_m, e, N) 
    return c


def decrypt_message(private_key_sk, ciphertext_c):
    N, d = private_key_sk
    plaintext_m = power_mod(ciphertext_c, d, N) 
    return plaintext_m

if __name__ == '__main__':
    security_bits = 512
    N_val, e_val, d_val, p_val, q_val = generate_rsa_keys(security_bits)


    print(f"  生成的素数 p: {p_val}")
    print(f"  生成的素数 q: {q_val}")
    pk, sk = key_gen(security_bits)
    print(f"  公钥 pk = (N, e): ({pk[0]}, {pk[1]})")
    print(f"  私钥 sk = (N, d): ({sk[0]}, {sk[1]})\n") 

    message = 1735810597190959215777958288558961757861370453241733818758202488338288285568449331489

    if message >= pk[0]: 
        print("消息整数太大")
    else:
        ciphertext = encrypt_message(pk, message)
        print(f"  消息 m = {message}")
        print(f"  计算得到的密文 c = [m^e mod N] = {ciphertext}\n")

        decrypted_message = decrypt_message(sk, ciphertext)
        print(f"  计算得到的明文 m' = [c^d mod N] = {decrypted_message}\n")

        if message == decrypted_message:
            print("成功")
        else:
            print("失败")
