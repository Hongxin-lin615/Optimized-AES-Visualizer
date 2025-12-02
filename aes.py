import copy
import sys
import numpy as np
from constants import round_constants, s_box, inverted_s_box, const_matrix, const_matrix_inv

no_of_rounds = 10
overflow = 0x100
modulus = 0x11B

answer = {}
round_answers = {}

AES_CONFIG = {
    128: (4, 10),
    192: (6, 12),
    256: (8, 14)
}


def convert_to_matrix(ascii_array):
    ascii_matrix = np.zeros((4, 4))
    for i in range(16):
        ascii_matrix[i % 4][int(i / 4)] = ascii_array[i]
    return ascii_matrix


def unwrap_matrix(matrix):
    ascii_array = np.zeros(16)
    for i in range(4):
        for j in range(4):
            ascii_array[4 * i + j] = matrix[j][i]
    return ascii_array


def text_to_ascii(text, expected_len=16):
    ascii_array = []
    for char in text:
        ascii_array.append(ord(char))
    if len(ascii_array) < expected_len:
        ascii_array = ascii_array + [0x00] * (expected_len - len(ascii_array))
    return np.array(ascii_array)


def ascii_to_text(ascii_array):
    text = ""
    for num in ascii_array:
        text = text + chr(int(num))
    return text


def key_expansion(key_array, nk):
    nr = AES_CONFIG[int(nk * 32)][1]
    expanded_key_size = 4 * (nr + 1)

    words = np.zeros((expanded_key_size, 4))

    for i in range(nk):
        words[i] = [key_array[4 * i], key_array[4 * i + 1], key_array[4 * i + 2], key_array[4 * i + 3]]

    for i in range(nk, expanded_key_size):
        temp = copy.deepcopy(words[i - 1])

        if i % nk == 0:
            temp = shift_rows(temp)
            temp = sub_byte(temp)

            r_con_val = round_constants[int(i / nk) - 1]
            r_con_arr = np.array([r_con_val, 0, 0, 0])
            temp = xor_matrix(temp, r_con_arr)

        elif nk > 6 and (i % nk == 4):
            temp = sub_byte(temp)

        words[i] = xor_matrix(words[i - nk], temp)

    round_keys = np.zeros((nr + 1, 16))
    for i in range(nr + 1):
        round_keys[i] = np.concatenate((words[4 * i], words[4 * i + 1], words[4 * i + 2], words[4 * i + 3]))

    return round_keys


def xor_matrix(first, second):
    first = copy.deepcopy(first)
    for i in range(4):
        first[i] = int(first[i]) ^ int(second[i])
    return first


def int_to_hex(number):
    hex_string = hex(number)
    f = hex_string[2]
    if f.isdigit():
        f = int(f)
    else:
        f = (ord(f) - ord('a')) + 10

    if len(hex_string) == 3:
        return [0, f]

    s = hex_string[3]
    if s.isdigit():
        s = int(s)
    else:
        s = (ord(s) - ord('a')) + 10
    return [f, s]


def sub_byte(row):
    new_row = copy.deepcopy(row)
    for i in range(4):
        row_num, col_num = int_to_hex(int(row[i]))
        new_row[i] = s_box[row_num][col_num]
    return new_row


def inv_sub_byte(row):
    new_row = copy.deepcopy(row)
    for i in range(4):
        row_num, col_num = int_to_hex(int(row[i]))
        new_row[i] = inverted_s_box[row_num][col_num]
    return new_row


def sub_byte_transformation(matrix):
    for i in range(4):
        matrix[i] = sub_byte(matrix[i])


def inv_sub_byte_transformation(matrix):
    for i in range(4):
        matrix[i] = inv_sub_byte(matrix[i])


def shift_rows(row, shift=1):
    new_row = copy.deepcopy(row)
    for i in range(4):
        new_row[i] = row[(i + shift) % 4]
    return new_row


def inv_shift_rows(row, shift=1):
    new_row = copy.deepcopy(row)
    for i in range(4):
        new_row[i] = row[(4 + i - shift) % 4]
    return new_row


def shift_rows_transformation(matrix):
    for i in range(4):
        matrix[i] = shift_rows(matrix[i], i)


def inv_shift_rows_transformation(matrix):
    for i in range(4):
        matrix[i] = inv_shift_rows(matrix[i], i)


def gf2n_multiply(a, b):
    sum = 0
    a = int(a)
    b = int(b)
    while (b > 0):
        if (b & 1):
            sum = int(sum) ^ int(a)
        b = int(b >> 1)
        a = int(a << 1)
        if (a & overflow):
            a = int(a) ^ int(modulus)
    return sum


def mix_col(col):
    new_col = np.zeros(4)
    for i in range(4):
        for j in range(4):
            new_col[i] = int(new_col[i]) ^ int(
                gf2n_multiply(const_matrix[i][j], col[j]))
    return new_col


def inv_mix_col(col):
    new_col = np.zeros(4)
    for i in range(4):
        for j in range(4):
            new_col[i] = int(new_col[i]) ^ int(
                gf2n_multiply(const_matrix_inv[i][j], col[j]))
    return new_col


def mix_column(matrix):
    for i in range(4):
        matrix[:, i] = mix_col(matrix[:, i])


def inv_mix_column(matrix):
    for i in range(4):
        matrix[:, i] = inv_mix_col(matrix[:, i])


def add_round_word(col, word):
    new_col = copy.deepcopy(col)
    for i in range(4):
        new_col[i] = int(word[i]) ^ int(col[i])
    return new_col


def add_round_key(matrix, keyword):
    word_mat = np.zeros((4, 4))
    for i in range(16):
        word_mat[i % 4][int(i / 4)] = keyword[i]

    for i in range(4):
        matrix[:, i] = add_round_word(matrix[:, i], word_mat[:, i])


def encrypt(plain_text_orig, round_keys):
    plain_text = copy.deepcopy(plain_text_orig)
    plain_text_matrix = convert_to_matrix(text_to_ascii(plain_text))

    round_answers["ascii_matrix"] = copy.deepcopy(plain_text_matrix)

    round_matrices = []
    add_round_key(plain_text_matrix, round_keys[0])
    each_round = {}
    each_round[3] = copy.deepcopy(plain_text_matrix)

    round_matrices.append(copy.deepcopy(each_round))

    for i in range(no_of_rounds - 1):
        each_round = {}
        sub_byte_transformation(plain_text_matrix)
        each_round[0] = copy.deepcopy(plain_text_matrix)

        shift_rows_transformation(plain_text_matrix)
        each_round[1] = copy.deepcopy(plain_text_matrix)

        mix_column(plain_text_matrix)
        each_round[2] = copy.deepcopy(plain_text_matrix)

        add_round_key(plain_text_matrix, round_keys[i + 1])
        each_round[3] = copy.deepcopy(plain_text_matrix)

        round_matrices.append(copy.deepcopy(each_round))

    each_round = {}
    sub_byte_transformation(plain_text_matrix)
    each_round[0] = copy.deepcopy(plain_text_matrix)

    shift_rows_transformation(plain_text_matrix)
    each_round[1] = copy.deepcopy(plain_text_matrix)

    add_round_key(plain_text_matrix, round_keys[len(round_keys) - 1])
    each_round[2] = copy.deepcopy(plain_text_matrix)

    round_matrices.append(copy.deepcopy(each_round))

    round_answers["rounds"] = copy.deepcopy(round_matrices)
    ciphertext = ascii_to_text(unwrap_matrix(plain_text_matrix))
    round_answers["cipher"] = copy.deepcopy(ciphertext)
    return ciphertext


def decrypt(cipher_text_orig, round_keys):
    cipher_text = copy.deepcopy(cipher_text_orig)
    cipher_text_matrix = convert_to_matrix(text_to_ascii(cipher_text))

    round_answers["ascii_matrix"] = copy.deepcopy(cipher_text_matrix)

    round_matrices = []

    add_round_key(cipher_text_matrix, round_keys[len(round_keys) - 1])
    each_round = {}
    each_round[3] = copy.deepcopy(cipher_text_matrix)

    round_matrices.append(copy.deepcopy(each_round))

    for i in range(no_of_rounds - 1, 0, -1):
        each_round = {}
        inv_shift_rows_transformation(cipher_text_matrix)
        each_round[0] = copy.deepcopy(cipher_text_matrix)

        inv_sub_byte_transformation(cipher_text_matrix)
        each_round[1] = copy.deepcopy(cipher_text_matrix)

        add_round_key(cipher_text_matrix, round_keys[i])
        each_round[2] = copy.deepcopy(cipher_text_matrix)

        inv_mix_column(cipher_text_matrix)
        each_round[3] = copy.deepcopy(cipher_text_matrix)

        round_matrices.append(copy.deepcopy(each_round))

    each_round = {}
    inv_shift_rows_transformation(cipher_text_matrix)
    each_round[0] = copy.deepcopy(cipher_text_matrix)

    inv_sub_byte_transformation(cipher_text_matrix)
    each_round[1] = copy.deepcopy(cipher_text_matrix)

    add_round_key(cipher_text_matrix, round_keys[0])
    each_round[2] = copy.deepcopy(cipher_text_matrix)

    round_matrices.append(copy.deepcopy(each_round))
    plaintext = ascii_to_text(unwrap_matrix(cipher_text_matrix))

    round_answers["rounds"] = copy.deepcopy(round_matrices)
    round_answers["plaintext"] = copy.deepcopy(plaintext)

    return plaintext


def input_to_encrypt(text, key, key_size=128):
    global no_of_rounds

    if key_size not in AES_CONFIG:
        raise ValueError("Invalid key size")

    nk, nr = AES_CONFIG[key_size]
    no_of_rounds = nr

    expected_key_bytes = key_size // 8
    key_ascii = text_to_ascii(key, expected_key_bytes)

    blocks = []
    for i in range(0, len(text), 16):
        last = i + 16 if i + 16 < len(text) else len(text)
        block_word = text[i:last]
        blocks.append(block_word)

    round_keys = key_expansion(key_ascii, nk)

    answer["blocks"] = copy.deepcopy(blocks)
    answer["key"] = copy.deepcopy(key)
    answer["key_matrix"] = copy.deepcopy(convert_to_matrix(key_ascii[:16]))
    answer["round_keys"] = copy.deepcopy(round_keys)

    ciphertext = ""
    for i in range(len(blocks)):
        round_answers.clear()
        ciphertext = ciphertext + encrypt(blocks[i], round_keys)
        answer[i] = copy.deepcopy(round_answers)

    return ciphertext


def input_to_decrypt(text, key, key_size=128):
    global no_of_rounds

    if key_size not in AES_CONFIG:
        raise ValueError("Invalid key size")

    nk, nr = AES_CONFIG[key_size]
    no_of_rounds = nr

    expected_key_bytes = key_size // 8
    key_ascii = text_to_ascii(key, expected_key_bytes)

    blocks = []
    for i in range(0, len(text), 16):
        last = i + 16 if i + 16 < len(text) else len(text)
        block_word = text[i:last]
        blocks.append(block_word)

    round_keys = key_expansion(key_ascii, nk)

    answer["blocks"] = copy.deepcopy(blocks)
    answer["key"] = copy.deepcopy(key)
    answer["key_matrix"] = copy.deepcopy(convert_to_matrix(key_ascii[:16]))
    answer["round_keys"] = copy.deepcopy(round_keys)

    plaintext = ""
    for i in range(len(blocks)):
        round_answers.clear()
        plaintext = plaintext + decrypt(blocks[i], round_keys)
        answer[i] = copy.deepcopy(round_answers)

    return plaintext


def encrypt_result(text, key, key_size=128):
    answer.clear()
    k_size = int(key_size)

    global no_of_rounds
    no_of_rounds = AES_CONFIG[k_size][1]

    answer["no_of_rounds"] = no_of_rounds
    input_to_encrypt(text, key, k_size)
    return answer


def decrypt_result(text, key, key_size=128):
    answer.clear()
    k_size = int(key_size)

    global no_of_rounds
    no_of_rounds = AES_CONFIG[k_size][1]

    answer["no_of_rounds"] = no_of_rounds
    input_to_decrypt(text, key, k_size)
    return answer