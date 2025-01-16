import struct


# Константы для RC6
P32 = 0xB7E15163  # Константа для расширения ключа
Q32 = 0x9E3779B9  # Константа для расширения ключа


# Циклический сдвиг влево
def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


# Циклический сдвиг вправо
def right_rotate(value, shift):
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def rc6_key_schedule(key):
    # Преобразуем ключ в массив 32-битных слов
    c = len(key) // 4
    L = [0] * c
    for i in range(c):
        L[i] = int.from_bytes(key[i * 4:(i + 1) * 4], byteorder='little')

    # Инициализация массива S
    t = 2 * 20 + 4  # Количество раундов (20) + 4
    S = [0] * t
    S[0] = P32
    for i in range(1, t):
        S[i] = (S[i - 1] + Q32) & 0xFFFFFFFF

    # Перемешивание ключа
    A = B = i = j = 0
    v = 3 * max(t, c)
    for _ in range(v):
        A = S[i] = left_rotate((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = L[j] = left_rotate((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 0x1F)
        i = (i + 1) % t
        j = (j + 1) % c

    return S

# Шифрование RC6
def rc6_encrypt(block, S):
    A, B, C, D = struct.unpack('<4I', block)

    B = (B + S[0]) & 0xFFFFFFFF
    D = (D + S[1]) & 0xFFFFFFFF

    for i in range(1, 21):  # 20 раундов
        t = left_rotate((B * (2 * B + 1)) & 0xFFFFFFFF, 5)
        u = left_rotate((D * (2 * D + 1)) & 0xFFFFFFFF, 5)
        A = (left_rotate(A ^ t, u & 0x1F) + S[2 * i]) & 0xFFFFFFFF
        C = (left_rotate(C ^ u, t & 0x1F) + S[2 * i + 1]) & 0xFFFFFFFF
        A, B, C, D = B, C, D, A

    A = (A + S[42]) & 0xFFFFFFFF
    C = (C + S[43]) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)

# Дешифрование RC6
def rc6_decrypt(block, S):
    A, B, C, D = struct.unpack('<4I', block)

    C = (C - S[43]) & 0xFFFFFFFF
    A = (A - S[42]) & 0xFFFFFFFF

    for i in range(20, 0, -1):  # 20 раундов в обратном порядке
        A, B, C, D = D, A, B, C
        u = left_rotate((D * (2 * D + 1)) & 0xFFFFFFFF, 5)
        t = left_rotate((B * (2 * B + 1)) & 0xFFFFFFFF, 5)
        C = (right_rotate((C - S[2 * i + 1]) & 0xFFFFFFFF, t & 0x1F) ^ u) & 0xFFFFFFFF
        A = (right_rotate((A - S[2 * i]) & 0xFFFFFFFF, u & 0x1F) ^ t) & 0xFFFFFFFF

    D = (D - S[1]) & 0xFFFFFFFF
    B = (B - S[0]) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)


if __name__ == "__main__":
    key = b"supersecretkey123"  # 128-битный ключ (16 байт)
    str_input = input("Enter data: ")
    data = str_input.encode('utf-8')

    # Дополнение данных до размера, кратного 16 байтам
    padding_length = 16 - (len(data) % 16)
    extended_data = data
    extended_data += bytes([padding_length] * padding_length)

    # Расширение ключа
    S = rc6_key_schedule(key)

    encrypted_data = bytearray()
    for i in range(0, len(extended_data), 16):
        block = extended_data[i:i + 16]
        encrypted_block = rc6_encrypt(block, S)
        encrypted_data.extend(encrypted_block)

    # Дешифрование
    decrypted_data = bytearray()
    for i in range(0, len(encrypted_data), 16):
        block = encrypted_data[i:i + 16]
        decrypted_block = rc6_decrypt(block, S)
        decrypted_data.extend(decrypted_block)

    # Удаление дополнения
    decrypted_data = decrypted_data[:-decrypted_data[-1]]

    print(f"Input data: {data.decode('utf-8')}")
    print(f"Encrypted data: {encrypted_data.hex()}")
    print(f"Decrypted data: {decrypted_data.decode('utf-8')}")