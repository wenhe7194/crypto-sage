import hashlib
def hmac_sha256(key, msg):
    block_size = 64
    key = bytes(key)
    msg = bytes(msg)

    o_key_pad = bytes([x ^^ 0x5c for x in key])
    i_key_pad = bytes([x ^^ 0x36 for x in key])
    inner_hash = hashlib.sha256(i_key_pad + msg).digest()
    return hashlib.sha256(o_key_pad + inner_hash).digest()

if __name__ == '__main__':
    input_data_hex = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"
    test_message = hexstr_to_bytes(input_data_hex)

    # 密钥 (64字节)
    test_key_hex = (
        "000102030405060708090A0B0C0D0E0F"
        "101112131415161718191A1B1C1D1E1F"
        "202122232425262728292A2B2C2D2E2F"
        "303132333435363738393A3B3C3D3E3F"
    )
    test_key = hexstr_to_bytes(test_key_hex)
    computed_tag = hmac_sha256(test_key, test_message)
    print(f"计算得到的 HMAC-SHA256 标签 (32字节, 十六进制): {computed_tag.hex().upper()}")
