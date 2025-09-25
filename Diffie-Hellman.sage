# P-256
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
K = GF(p) 
a = K(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC)
b = K(0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)
E = EllipticCurve(K, (a, b))
G = E(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296, 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
E.set_order(n * 1) 

# 投影坐标下的无穷远点
O_proj = (K(0), K(1), K(0)) 


def proj_to_affine(P_proj):
    X, Y, Z = P_proj
    if Z == 0:
        return E(0)
    Z_inv = Z^(-1)
    x = X * Z_inv
    y = Y * Z_inv
    return E(x, y)

def proj_add(P1, P2):
    X1, Y1, Z1 = P1; X2, Y2, Z2 = P2
    if Z1 == 0: return P2
    if Z2 == 0: return P1
    u1, u2 = Y2*Z1, Y1*Z2;
    v1, v2 = X2*Z1, X1*Z2
    if v1 == v2:
        if u1 == u2: return proj_double(P1)
        else: return O_proj
    u = u1-u2; 
    v = v1-v2; 
    w= u^2*Z1*Z2 - v^3 - 2*v^2*v2
    X3 = v*w 
    Y3 = u*(v^2*v2 - w)-v^3*u2; 
    Z3 = v^3*Z1*Z2
    return (X3, Y3, Z3)

def proj_double(P):
    X1, Y1, Z1 = P
    if Z1 == 0 or Y1 == 0: return O_proj
    w_ = a*Z1^2 + 3*X1^2; 
    s = Y1*Z1; 
    B = X1*Y1*s
    h = w_^2 - 8*B; 
    X3 = 2*h*s
    Y3 = w_*(4*B - h) - 8*(Y1*s)^2; 
    Z3 = 8*s^3
    return (X3, Y3, Z3)

def proj_scalarmult(n, P):
    Q = O_proj
    if n == 0: return Q
    n_bin = bin(n)[2:]
    for bit in n_bin:
        Q = proj_double(Q)
        if bit == '1': Q = proj_add(Q, P)
    return Q


P_affine = G
g_proj = (G.xy()[0], G.xy()[1], K(1))
x = 65537 
print(f"Alicet x: {x}")
h_A_proj = proj_scalarmult(x, g_proj)
h_A_affine = proj_to_affine(h_A_proj)
print(f"h_A: （{hex(h_A_affine.xy()[0])[:]},{hex(h_A_affine.xy()[1])[:]}）")

y = 24100
print(f"Bob y: {y}")
h_B_proj = proj_scalarmult(y, g_proj)
h_B_affine = proj_to_affine(h_B_proj)
print(f"h_B: （{hex(h_B_affine.xy()[0])[:]},{hex(h_B_affine.xy()[1])[:]}）")

h_B_proj_received = (h_B_affine.xy()[0], h_B_affine.xy()[1], K(1))
k_A_proj = proj_scalarmult(x, h_B_proj_received)
k_A_affine = proj_to_affine(k_A_proj)
print(f"k_A: （{hex(k_A_affine.xy()[0])[:]},{hex(k_A_affine.xy()[1])[:]}）")

h_A_proj_received = (h_A_affine.xy()[0], h_A_affine.xy()[1], K(1))
k_B_proj = proj_scalarmult(y, h_A_proj_received)
k_B_affine = proj_to_affine(k_B_proj)
print(f"k_B: （{hex(k_B_affine.xy()[0])[:]},{hex(k_B_affine.xy()[1])[:]}）")


print("验证")
are_keys_equal = (k_A_affine == k_B_affine)
print(are_keys_equal)
