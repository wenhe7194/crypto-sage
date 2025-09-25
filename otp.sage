import random, os

def generate_fixed_key(length):
    return bytes(random.getrandbits(8) for _ in range(length))

def seed_generate_fixed_key(seed,length):
    random.seed(seed)
    return bytes(random.getrandbits(8) for _ in range(length))


def otp_encrypt(plaintext, key):
    pt = plaintext.encode("utf-8")
    if len(pt) != len(key):
        raise ValueError("密钥长度必须与明文长度一致！")
    return bytes(b ^^ k for b, k in zip(pt, key))

def otp_decrypt(ciphertext, key):
    if len(ciphertext) != len(key):
        raise ValueError("密钥长度必须与密文长度一致！")
    pt_bytes = bytes(c ^^ k for c, k in zip(ciphertext, key))
    return pt_bytes.decode("utf-8")


if __name__ == "__main__":
    msg = "HELLO SageMath OTP!"

    k1  = generate_fixed_key(len(msg))
    ct1 = otp_encrypt(msg, k1)
    pt1 = otp_decrypt(ct1, k1)
    print("无seed")
    print("明文 :", msg)
    print("密钥 :", k1.hex())
    print("密文 :", ct1.hex())
    print("解密 :", pt1)
    print()
    
    seed = 24
    k2  = seed_generate_fixed_key(seed,len(msg))
    ct2 = otp_encrypt(msg, k2)
    pt2 = otp_decrypt(ct2, k2)
    print("seed=24")
    print("明文 :", msg)
    print("密钥 :", k2.hex())
    print("密文 :", ct2.hex())
    print("解密 :", pt2)
    print()
