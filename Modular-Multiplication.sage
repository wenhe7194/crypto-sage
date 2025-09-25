def extended_euclidean_algorithm(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_s, old_t, old_r



def karatsuba_multiply(x, y):
    x = x
    y = y

    if x == 0 or y == 0:
        return 0
    
    len_x = x.nbits()
    len_y = y.nbits()

    if len_x < 10 or len_y < 10:
        return x * y 

    m = max(len_x, len_y) // 2
    x1 = x >> m  
    x0 = x & (1 << m) - 1
    y1 = y >> m  
    y0 = y & (1 << m) - 1

    z2 = karatsuba_multiply(x1, y1)      
    z0 = karatsuba_multiply(x0, y0)      
    z1_intermediate = karatsuba_multiply(x1 + x0, y1 + y0) 
    z1 = z1_intermediate - z2 - z0
    
    term_z2 = z2 << (2 * m)
    term_z1 = z1 << m
    return term_z2 + term_z1 + z0

def montgomery_multiply_pure(x_bar, y_bar, N, R, N_prime, R_bits_param):
    z = karatsuba_multiply(x_bar, y_bar) 
    m = ((z & (R - 1)) * N_prime) & (R - 1)
    t_val = (z + m * N) >> R_bits_param

    if t_val >= N:
        return t_val - N
    else:
        return t_val

def to_montgomery_form(x, R_sq_mod_N, N, R, N_prime, R_bits_param):
    """将 x 转换为蒙哥马利形式 (xR mod N)"""
    return montgomery_multiply_pure(x, R_sq_mod_N, N, R, N_prime, R_bits_param)

def from_montgomery_form(x_bar, N, R, N_prime, R_bits_param):
    """将蒙哥马利形式的 x_bar 转换回普通形式 (x_bar * R^-1 mod N)"""
    return montgomery_multiply_pure(x_bar, 1, N, R, N_prime, R_bits_param)


def mod_exp_r2l_montgomery(base, exponent, N, R, N_prime, R_bits_param, R_sq_mod_N):
    mont_mul_count = 0
    e = exponent

    one_mont = to_montgomery_form(1, R_sq_mod_N, N, R, N_prime, R_bits_param)
    current_power_mont = to_montgomery_form(base, R_sq_mod_N, N, R, N_prime, R_bits_param)
    result_mont = one_mont

    if e == 0:
        return from_montgomery_form(one_mont, N, R, N_prime, R_bits_param), 0

    while e > 0:
        if (e & 1) == 1: 
            result_mont = montgomery_multiply_pure(result_mont, current_power_mont, N, R, N_prime, R_bits_param)
            mont_mul_count += 1
        
        current_power_mont = montgomery_multiply_pure(current_power_mont, current_power_mont, N, R, N_prime, R_bits_param)
        mont_mul_count += 1
        e = e >> 1
        
    final_result = from_montgomery_form(result_mont, N, R, N_prime, R_bits_param)
    return final_result, mont_mul_count


def mod_exp_l2r_montgomery(base, exponent, N, R, N_prime, R_bits_param, R_sq_mod_N):
    mont_mul_count = 0
    e = exponent

    one_mont = to_montgomery_form(1, R_sq_mod_N, N, R, N_prime, R_bits_param)
    base_mont = to_montgomery_form(base, R_sq_mod_N, N, R, N_prime, R_bits_param)
    result_mont = one_mont

    if e == 0:
        return from_montgomery_form(one_mont, N, R, N_prime, R_bits_param), 0
    
    num_bits_exponent = e.nbits()

    for i in range(num_bits_exponent - 1, -1, -1):
        result_mont = montgomery_multiply_pure(result_mont, result_mont, N, R, N_prime, R_bits_param)
        mont_mul_count += 1
        if (e >> i) & 1:
            result_mont = montgomery_multiply_pure(result_mont, base_mont, N, R, N_prime, R_bits_param)
            mont_mul_count += 1
            
    final_result = from_montgomery_form(result_mont, N, R, N_prime, R_bits_param)
    return final_result, mont_mul_count


if __name__ == '__main__':
    BIT_LENGTH = 512
    N_mod = 9362401673895901382264903610523354601456852099226312665898567072098392891520913328993655625175656383592959651404974082331578282250033937538127122420354679
    R_bits_val = BIT_LENGTH 
    R_val = 1 << R_bits_val
    print(f"Montgomery R = 2^{R_bits_val}:\n{R_val}\n")

    N_inv_mod_R_coeff, _, _ = extended_euclidean_algorithm(N_mod, R_val)
    N_prime_val = (-N_inv_mod_R_coeff) % R_val
    print(f"-N^-1 mod R:\n{N_prime_val}\n")

    R_sq_mod_N_val = power_mod(R_val, 2, N_mod)
    print(f"R^2 mod N:\n{R_sq_mod_N_val}\n")

    mont_params_dict = {
        "N": N_mod,
        "R": R_val,
        "N_prime": N_prime_val,
        "R_bits_param": R_bits_val,
        "R_sq_mod_N": R_sq_mod_N_val
    }

    exponents_to_test = {
        "e = 3": 3,
        "e = 65537 (2^16+1)": 65537,
        "e(512bit)": 8031230142162650809448846321154030104166415654231330434700087784964782485797349841517913702787471458760273501561717142986220293142723679738510444322886100
    }

    for desc, exp_val_original in exponents_to_test.items():

        base_val = 8692781202237292463746262155979997292022367028219872905192201661495618217503909930450955848906198338649019561998150890645094316701449238319817934689890013

        print(f"  参数: {desc}")
        print(f"  指数: {exp_val_original}") 
        print(f"  底数: {base_val}")

        res_r2l, count_r2l = mod_exp_r2l_montgomery(base_val, exp_val_original, **mont_params_dict)
        print(f"  R2L: {res_r2l}")
        print(f"  模乘次数: {count_r2l}")

        res_l2r, count_l2r = mod_exp_l2r_montgomery(base_val, exp_val_original, **mont_params_dict)
        print(f"  L2R: {res_l2r}")
        print(f"  模乘次数: {count_l2r}")

        expected_res = power_mod(base_val, exp_val_original, N_mod)
        print(f"  对比结果: {expected_res}")

        
        if res_r2l == expected_res:
            print("  R2L Verification: CORRECT")
        else:
            print("  R2L Verification: INCORRECT")
        
        if res_l2r == expected_res:
            print("  L2R Verification: CORRECT")
        else:
            print("  L2R Verification: INCORRECT")
