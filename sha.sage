from sage.all import Integer

def _mask(w):
    return (Integer(1) << w) - 1


def _u32(x):
    return Integer(int(x) & 0xFFFFFFFF)


def _u64(x):
    return Integer(int(x) & 0xFFFFFFFFFFFFFFFF)


def _rotr(x, n, width):
    n %= width
    m = _mask(width)
    x = Integer(x)
    return ((x >> n) | ((x << (width - n)) & m)) & m


def _band(x, y):
    return Integer(int(x) & int(y))


def _bnot(x, width):
    return Integer(~int(x) & _mask(width))


def _chunks(data, size):
    for i in range(0, len(data), size):
        yield data[i : i + size]

# ────────────────────────────────────────────────
#CLASS 1: SHA‑224 / SHA‑256  
# ────────────────────────────────────────────────
class SHA224or256:
    __slots__ = ("_H", "_out_words")

    _IV_256 = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    _IV_224 = [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
               0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4]
    _K32 = [
        0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
        0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
        0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
        0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
        0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
        0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
        0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2]

    def __init__(self, version=256):
        if int(version) == 256:
            self._H = [Integer(x) for x in self._IV_256]
            self._out_words = 8
        elif int(version) == 224:
            self._H = [Integer(x) for x in self._IV_224]
            self._out_words = 7
        else:
            raise ValueError("SHA2 version must be 256 or 224")

    # 填充 (512‑bit 块)
    @staticmethod
    def _pad(msg: bytes) -> bytes:
        ml_bits = _u64(len(msg) << 3)
        buf = bytearray(msg)
        buf.append(0x80)
        pad_len = (56 - len(buf) % 64) % 64
        buf.extend(b"\x00" * pad_len)
        buf.extend(int(ml_bits).to_bytes(8, "big"))
        return bytes(buf)

    def _compress(self, chunk: bytes):
        a,b,c,d,e,f,g,h = self._H
        W = [Integer(int.from_bytes(chunk[i:i+4], "big")) for i in range(0,64,4)] + [Integer(0)]*48
        for i in range(16,64):
            s0 = _rotr(W[i-15],7,32) ^^ _rotr(W[i-15],18,32) ^^ (W[i-15]>>3)
            s1 = _rotr(W[i-2],17,32) ^^ _rotr(W[i-2],19,32) ^^ (W[i-2]>>10)
            W[i] = _u32(W[i-16]+s0+W[i-7]+s1)
        for i in range(64):
            """
		待完成
	    """
        self._H = [_u32(x+y) for x,y in zip(self._H,[a,b,c,d,e,f,g,h])]

    def hash(self, msg: bytes) -> bytes:
        for blk in _chunks(self._pad(msg),64):
            self._compress(blk)
        return b"".join(int(h).to_bytes(4,"big") for h in self._H[:self._out_words])

    def hash_digest(self, msg: bytes)->str:
        return self.hash(msg).hex()

# ────────────────────────────────────────────────
# CLASS 2: SHA‑384 / SHA‑512 
# ────────────────────────────────────────────────
class SHA384or512:
    __slots__ = ("_H","_out_words")
    _IV_512 = [0x6A09E667F3BCC908,0xBB67AE8584CAA73B,0x3C6EF372FE94F82B,0xA54FF53A5F1D36F1,0x510E527FADE682D1,0x9B05688C2B3E6C1F,0x1F83D9ABFB41BD6B,0x5BE0CD19137E2179]
    _IV_384 = [0xCBBB9D5DC1059ED8,0x629A292A367CD507,0x9159015A3070DD17,0x152FECD8F70E5939,0x67332667FFC00B31,0x8EB44A8768581511,0xDB0C2E0D64F98FA7,0x47B5481DBEFA4FA4]

    _K64 = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,0x9BDC06A725C71235,0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,0x19A4C116B8D2D0C8, 0x1E376C085141AB53,0x2748774CDF8EEB99,0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,0x748F82EE5DEFB2FC,0x78A5636F43172F60,0x84C87814A1F0AB72,0x8CC702081A6439EC,0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817, ]

    def __init__(self, version=512):
        if int(version)==512:
            self._H=[Integer(x) for x in self._IV_512]; self._out_words=8
        elif int(version)==384:
            self._H=[Integer(x) for x in self._IV_384]; self._out_words=6
        else: raise ValueError

    @staticmethod
    def _pad(msg:bytes)->bytes:
        ml_bits=_u64(len(msg)<<3)
        buf=bytearray(msg); buf.append(0x80)
        pad_len=(112-len(buf)%128)%128; buf.extend(b"\x00"*pad_len)
        buf.extend(b"\x00"*8); buf.extend(int(ml_bits).to_bytes(8,"big"))
        return bytes(buf)

    def _compress(self,chunk:bytes):
        a,b,c,d,e,f,g,h=self._H
        W=[Integer(int.from_bytes(chunk[i:i+8],"big")) for i in range(0,128,8)]+[Integer(0)]*64
        for i in range(16,80):
            s0=_rotr(W[i-15],1,64) ^^ _rotr(W[i-15],8,64) ^^ (W[i-15]>>7)
            s1=_rotr(W[i-2],19,64) ^^ _rotr(W[i-2],61,64) ^^ (W[i-2]>>6)
            W[i]=_u64(W[i-16]+s0+W[i-7]+s1)
        for i in range(80):
            """
		待完成
	    """
        self._H=[_u64(x+y) for x,y in zip(self._H,[a,b,c,d,e,f,g,h])]

    def hash(self,msg:bytes)->bytes:
        for blk in _chunks(self._pad(msg),128):
            self._compress(blk)
        return b"".join(int(h).to_bytes(8,"big") for h in self._H[:self._out_words])
    def hash_digest(self,msg:bytes)->str: return self.hash(msg).hex()

# ────────────────────────────────────────────────
# CLASS 3: SHA‑512/224 & SHA‑512/256
# ────────────────────────────────────────────────
class SHA512t:
    __slots__=("_H","_out_bytes")
    _IV_512_224 = [
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
    0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
    ]
    _IV_512_256 = [
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2,
        0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
        0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    ]
    
    _K64 = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
    0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
    0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
    0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
    0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
    0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
    0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ]

    def __init__(self,t=224):
        if t==224:
            self._H=[Integer(x) for x in self._IV_512_224]; self._out_bytes=28
        elif t==256:
            self._H=[Integer(x) for x in self._IV_512_256]; self._out_bytes=32
        else: raise ValueError

    @staticmethod
    def _pad(msg:bytes)->bytes:
        ml=_u64(len(msg)<<3); buf=bytearray(msg); buf.append(0x80)
        pad_len=(112-len(buf)%128)%128; buf.extend(b"\x00"*pad_len)
        buf.extend(b"\x00"*8); buf.extend(int(ml).to_bytes(8,"big")); return bytes(buf)

    def _compress(self,chunk:bytes):
        a,b,c,d,e,f,g,h=self._H; W=[Integer(int.from_bytes(chunk[i:i+8],"big")) for i in range(0,128,8)]+[Integer(0)]*64
        for i in range(16,80):
            s0=_rotr(W[i-15],1,64) ^^ _rotr(W[i-15],8,64) ^^ (W[i-15]>>7)
            s1=_rotr(W[i-2],19,64) ^^ _rotr(W[i-2],61,64) ^^ (W[i-2]>>6)
            W[i]=_u64(W[i-16]+s0+W[i-7]+s1)
        for i in range(80):
            """
		待完成
	    """
        self._H=[_u64(s+w) for s,w in zip(self._H,[a,b,c,d,e,f,g,h])]

    def hash(self,msg:bytes)->bytes:
        for blk in _chunks(self._pad(msg),128):
            self._compress(blk)
        full=b"".join(int(h).to_bytes(8,"big") for h in self._H)
        return full[:self._out_bytes]
    def hash_digest(self,msg:bytes)->str: return self.hash(msg).hex()

# ────────────────────────────────────────────────
# Convenience factory
# ────────────────────────────────────────────────

def SHA2(mode=256):
    """Return an instance of the requested SHA-2 variant."""
    if mode in (224,256):
        return SHA224or256(mode)
    if mode in (384,512):
        return SHA384or512(mode)
    if mode=="512/224":
        return SHA512t(224)
    if mode=="512/256":
        return SHA512t(256)

if __name__ == "__main__":
    m = b"abc"
    print(SHA2(224).hash_digest(m))
    print(SHA2(256).hash_digest(m))      
    print(SHA2(384).hash_digest(m))
    print(SHA2(512).hash_digest(m))
    print(SHA2("512/224").hash_digest(m))
    print(SHA2("512/256").hash_digest(m))
