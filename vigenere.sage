def calculate_index_of_coincidence(str1):
    IC = 0
    result = {}  # 定义一个空字典
    total = len(str1)
 
    # 遍历输入字符串，并将其存储在字典中作为键值对
    for char in str1:
        result[char] = str1.count(char)
 
    for char in result:
        IC += (result[char] / total) * ((result[char] - 1) / (total - 1))
 
    return IC
 
# 此函数将密文列表分成m组，每组n个元素
def divide_list_into_groups(m, n, c):
    grouped_list = []
 
    for i in range(m):
        for j in range(n):
            grouped_list.append(c[i + j * m])
 
    return grouped_list
 
# 此函数记录列表中字母出现的频率
def count_frequency(unicode, lst):
    length = len(lst)
    count = 0
 
    for i in range(length):
        if chr(unicode) == lst[i]:
            count += 1
 
    return count
 
def calculate_ic_difference(str1, n):
    total = len(str1)
    substrings = []
    IC_values = []
 
    for i in range(n):
        substring = ""
        for j in range(total):
            if j % n == i:
                substring += str1[j]
        substrings.append(substring)
        ic_value = calculate_index_of_coincidence(substrings[i])
        IC_values.append(ic_value)
 
    total_ic = sum(IC_values)
    avg_IC = total_ic / n
    difference = abs(avg_IC - 0.065)
 
    print("当密钥长度为", n, "时，子字符串的IC值为：", IC_values, "平均IC值为：", avg_IC)
    return difference
 
def determine_key_length(ciphertext, n):
    min_difference = 1000
    key_length = 1
 
    for i in range(1, n + 1):
        if i == 1:
            min_difference = calculate_ic_difference(ciphertext, i)
        else:
            difference = calculate_ic_difference(ciphertext, i)
            if difference < min_difference:
                min_difference = difference
                key_length = i
 
    print("密钥长度为：", key_length)
 
    # 获取密钥长度，现在让我们找到密钥
    num_groups = int((len(ciphertext) - len(ciphertext) % key_length) / key_length)
    grouped_list = divide_list_into_groups(key_length, num_groups, ciphertext)
 
    # 字母ABC...的可能频率列表
    usual_frequencies = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002, 0.008, 0.040, 0.024,
                         0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 0.020, 0.001]
 
    secret_key = []
 
    for i in range(key_length):
        frequencies = []
 
        for j in range(26):
            unicode_j = ord('A') + j
            frequencies.append(count_frequency(unicode_j, grouped_list[i * num_groups:(i * num_groups + num_groups)]))
 
        for g in range(26):
            sum_frequencies = 0
 
            for p in range(26):
                sum_frequencies += usual_frequencies[p] * frequencies[(p + g) % 26]
 
            M = abs((sum_frequencies / num_groups) - 0.065)
 
            if g == 0:
                t = M
                secret = 0
            elif g != 0:
                if M <= t:
                    t = M
                    secret = g
 
        secret_key.append(secret)
 
    key_str = ""
 
    for i in range(key_length):
        key_str += chr(ord('A') + secret_key[i])
 
    print("密钥为：", key_str)
 
    return key_str
 
def alpha(cipher): #预处理,去掉空格以及回车 
    c = ''
    for i in range(len(cipher)):
        if(cipher[i].isalpha()):
            c += cipher[i]
    c = c.upper()
    return c   
    
ciphertext = ""
ciphertext = alpha(ciphertext)
determine_key_length(ciphertext, 7)
