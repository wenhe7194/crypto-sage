p = 0xEEFC0B79D5FF2502BA4BC0C1BF86293C1B0495086E25C075C1391EC8DD3B1961
K = GF(p)
g = K(5)

m = 2147483648
x = 65539
y = 2^32
h = g^x
c1 = g^y
c2 = h^y*m
print(f"c1:{c1}")
print(f"c2:{c2}")

c1x = c1^x
m_dec = c2/c1x
print(f"m:{m_dec}")
