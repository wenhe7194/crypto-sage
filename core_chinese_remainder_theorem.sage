def core_chinese_remainder_theorem(residues, moduli):  
    is_all_zeros = all(x == 0 for x in residues)
    if is_all_zeros:
        ans = 1
        for i in range(len(moduli)):
            if ans % moduli[i] !=0:
                ans = ans * moduli[i]
        return ans
    N_prod = product(moduli)
    total_sum = 0
    for i in range(len(moduli)):
        a_i = residues[i]
        n_i = moduli[i]
        M_i = N_prod // n_i 
        y_i = inverse_mod(M_i, n_i)    
        total_sum += a_i * M_i * y_i
        
    # 结果模 N
    return total_sum % N_prod

residues1 = [0,0]
moduli1 = [11,23]
solution1 = core_chinese_remainder_theorem(residues1, moduli1)
print(f"方程组 ({residues1}, {moduli1}) 的解 x = {solution1}")


residues2 = [1, 2, 3,2]
moduli2 = [2, 3, 5,7]
solution2 = core_chinese_remainder_theorem(residues2, moduli2)
print(f"方程组 ({residues2}, {moduli2}) 的解 x = {solution2}")
