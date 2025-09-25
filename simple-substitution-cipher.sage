mapping = {
    'A': 'Q',
    'B': 'W',
    'C': 'E',
    'D': 'R',
    'E': 'T',
    'F': 'Y',
    'G': 'U',
    'H': 'I',
    'I': 'O',
    'J': 'P',
    'K': 'A',
    'L': 'S',
    'M': 'D',
    'N': 'F',
    'O': 'G',
    'P': 'H',
    'Q': 'J',
    'R': 'K',
    'S': 'L',
    'T': 'Z',
    'U': 'X',
    'V': 'C',
    'W': 'V',
    'X': 'B',
    'Y': 'N',
    'Z': 'M'
}

from collections import Counter

def count_and_sort_letters(text):
    """
    统计文本中每个字母出现的次数，并按出现次数从高到低排序。
    :param text: 输入文本字符串
    :return: 按出现次数排序后的列表，每项为 (字母, 次数)
    """
    # 将文本转换为小写，并只保留字母
    filtered_text = ''.join(ch for ch in text.lower() if ch.isalpha())
    
    # 使用 Counter 统计每个字母的出现次数
    letter_counts = Counter(filtered_text)
    
    # 对字母计数结果按出现次数进行排序（降序）
    sorted_letters = sorted(letter_counts.items(), key=lambda item: item[1], reverse=True)
    
    return sorted_letters

if __name__ == "__main__":
    text = input("请输入文本：")
    sorted_counts = count_and_sort_letters(text)
    
    print("各字母出现次数（按出现次数排序）：")
    for letter, count in sorted_counts:
        print(f"{letter}: {count}")
