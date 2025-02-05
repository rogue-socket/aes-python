# input - 128bits -> 16bytes
# key - 128bits -> 16bytes
# no of rounds - 10
# round key size = 128bits
# no of keys - initial key + 10 keys

# Refer to: https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf
# for step by step, to compare and test

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def left_rotate(arr):
    return arr[1:] + [arr[0]]


def binary_to_hex(binary_str):
    """
    Converts a binary string to a properly padded hexadecimal string.
    Ensures the binary is padded to a multiple of 4 before conversion.

    :param binary_str: A string representing binary (e.g., "00001111").
    :return: A string representing hexadecimal (e.g., "0F").
    """
    n = len(binary_str)
    if n % 4 != 0:
        return "incomplete binary"
    else:
        n_h = n // 4
        num = int(binary_str, 2)
        str_ans = hex(num)[2:]
        return str_ans.zfill(n_h)


def hex_to_binary(hex_str):
    """
    Converts a hexadecimal string to a properly padded binary string.
    Ensures the binary output is exactly 4× the length of the hex input.

    :param hex_str: A string representing hexadecimal (e.g., "0F").
    :return: A string representing binary (e.g., "00001111").
    """
    try:
        decimal_value = int(hex_str, 16)  # Convert hexadecimal to decimal
        binary_value = bin(decimal_value)[2:]  # Convert decimal to binary and remove "0b" prefix
        binary_length = len(hex_str) * 4  # Ensure binary is padded to 4× the number of hex digits
        return binary_value.zfill(binary_length)
    except ValueError:
        return "Invalid hexadecimal string"


def xor_binary_strings(binary_str1, binary_str2):
    """
    Performs XOR operation on two binary strings of equal length.
    :param binary_str1: The first binary string (e.g., "1010").
    :param binary_str2: The second binary string (e.g., "1100").
    :return: A binary string representing the XOR result (e.g., "0110").
    """
    if len(binary_str1) != len(binary_str2):
        return "Error: Binary strings must have the same length."

    try:
        # Convert binary strings to integers, perform XOR, and convert back to binary string
        xor_result = int(binary_str1, 2) ^ int(binary_str2, 2)
        # Format result to keep leading zeros
        return format(xor_result, f'0{len(binary_str1)}b')
    except ValueError:
        return "Error: Invalid binary input."


def initial_transformation(arr, key):
    """
    does the first operation of the AES, a simple XOR
    :param arr: 4x4 grid of 1 byte each represented by hex
    :param key: 4x4 grid of 1 byte each represented by hex
    :return: 4x4 grid a result of the XOR function
    """
    ans = add_roundkey(arr, key)
    return ans


def substitute_bytes(arr):
    """
    :param arr: 4x4 array where each is 8bit hex. (e.g.  "A4")
    :return: 4x4 array where each is 8 bit hex. (e.g.  "A4")
    """

    ans = [['0'] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            v1 = hex(S_BOX[int(arr[i][j], 16)])[2:]
            v1 = v1.zfill(2)
            ans[i][j] = v1
    return ans


def shift_rows(arr):
    """
    Shifts the rows according to the 0LS, 1LS, 2LS, 3LS
    :param arr: list of 4 lists, each containing 4 elements
    :return: list of 4 lists, shifted
    """
    ans = []
    for i in range(4):
        j = 0
        plem = arr[i].copy()
        while j < i:
            plem = left_rotate(plem)
            j += 1
        ans.append(plem)
    return ans


def mix_columns(arr):
    mat1 = [[2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]]

    ans = [['0'] * 4 for _ in range(4)]

    def mul_hex_galois(a, b):
        """
        return the galois multiplication of a, b(given in hex)
        :param a: hex value -> will usually be 1, 2, 3
        :param b: hex value
        :return: binary string of 8
        """
        if a == "0x2":
            ans = hex_to_binary(b) + "0"
            if ans[0] == "0":
                ans = ans[1:]
            else:
                ans = xor_binary_strings(ans[1:], "00011011")
        elif a == "0x3":
            ans = hex_to_binary(b) + "0"
            if ans[0] == "0":
                ans = ans[1:]
            else:
                ans = xor_binary_strings(ans[1:], "00011011")
            ans = xor_binary_strings(ans, hex_to_binary(b))
        else:
            ans = hex_to_binary(b)
        return ans

    def matrix_mul_row_col(row, col):
        """
        multiples the row and the column using the mul_hex_galois() function
        :param row: list of 4 elems, each a hex -> from the fix matrix, 2, 3, 1, 1
        :param col: list of 4 elems, representing the column, each a hex
        :return: single hex value
        """
        ans = "00000000"
        for i in range(4):
            ans = xor_binary_strings(mul_hex_galois(hex(row[i]), col[i]), ans)
        return binary_to_hex(ans)

    for i in range(4):
        for j in range(4):
            ans[i][j] = matrix_mul_row_col(mat1[i], [elem[j] for elem in arr])
    return ans


def add_roundkey(arr, key):
    """
    do an XOR with the roundkey, which is also a 4x4 array of hex
    :param arr: 4x4 array
    :param key: 4x4 array
    :return: 4x4 array
    """
    ans = [['0'] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            ans[i][j] = binary_to_hex(xor_binary_strings(hex_to_binary(arr[i][j]), hex_to_binary(key[i][j])))
    return ans


def four_transformations(arr, key):
    """
    The function that represents the 4 ops -> sub_bytes, shift_rows, mix_columns, add_key
    :param key: the 128bit key for the add_roundkey() function
    :param arr: 4x4 of hex values
    :return: 4x4 of hex values with the 4 completed
    """
    arr = substitute_bytes(arr)
    arr = shift_rows(arr)
    arr = mix_columns(arr)
    arr = add_roundkey(arr, key)
    return arr


def three_transformations(arr, key):
    """
    The function that happens as the last step -> everything in four_transformations other than the mix_columns
    :param arr: 4x4 matrix
    :param key: 4x4 matrix -> key
    :return: 4x4 matrix -> final
    """
    arr = substitute_bytes(arr)
    arr = shift_rows(arr)
    arr = add_roundkey(arr, key)
    return arr


def round_key_generation(key_ip):
    """
    Generates the keys,
    11keys for 128bits
    12keys for 192bits
    13keys for 256bits
    :param key_ip: hex input of the key
    :return: array of the keys, where each key is a string of 32hex digits -> 128bits
    """
    key_list = []
    key_mat = [[0] * 4 for _ in range(4)]
    p = 0
    for j in range(4):
        for i in range(4):
            key_mat[i][j] = key_ip[p:p + 2]
            p += 2

    # Initial Key
    temp = ""
    for j in range(4):
        for i in range(4):
            temp += key_mat[i][j]
    key_list.append(temp)

    def g_key(w_last, round):
        """
        Apply the g() function on the last 4 bytes of the key
        :param round: gives the round number to choose the correct round key constant
        :param w_last: the last word -> 4 bytes as a continuous string
        :return: the g() transposed value of the 4bytes in a continuous string
        """
        ans = w_last

        #step1 - Left transpose
        ans = ans[2:] + ans[:2]

        #step2 - Sbox
        k = 0
        ans_t = ""
        while k < 7:
            lol = hex(S_BOX[int(ans[k:k + 2], 16)])[2:]
            ans_t += lol.zfill(2)
            k += 2
        #step3 - XOR with the round constant
        rcon = {1: "01", 2: "02", 3: "04", 4: "08", 5: "10", 6: "20", 7: "40", 8: "80", 9: "1B", 10: "36"}
        ans_t = binary_to_hex(xor_binary_strings(hex_to_binary(rcon[round]), hex_to_binary(ans_t[:2]))) + ans_t[2:]
        return ans_t

    # First key to 10th Key

    round_number = 1
    while round_number <= 10:
        last_key = key_list[-1]
        last_word = last_key[-8:]
        ans_temp = ""
        output_g = g_key(last_word, round_number)
        p = 0
        temp = output_g
        for i in range(4):
            temp = binary_to_hex(xor_binary_strings(hex_to_binary(temp), hex_to_binary(last_key[p:p + 8])))
            ans_temp += temp
            p += 8
        key_list.append(ans_temp)
        round_number += 1
    return key_list


def make_4by4(arr):
    """
    converts a string of 32hex codes to  a 4x4 grid of 2hex codes each
    :param arr: string of 32hex codes
    :return: a 4x4 array with 1 byte in each cell -> 2hex codes
    """
    ans = [[0] * 4 for _ in range(4)]
    for j in range(4):
        for i in range(4):
            ans[i][j] = arr[((8 * j) + (2 * i)): ((8 * j) + (2 * i)) + 2]

    return ans


def encryption(pt, key_list):
    """
    Encrypts the pt using the AES encryption
    :param pt: plaintext - 128bits, 32hex digits string
                    in the form of 32hex digits, 128bits, needs to be made into a 4x4 grid with each cell representing a byte
    :param key_list: list of 11 keys(128bit) for the initial + 10 rounds of execution
                    each element is a string of 32hex digits, not in the 4x4 format
    :return: the ciphertext -> 128bits, 32hex digits string
    """

    pt_mat = make_4by4(pt)
    ans = initial_transformation(pt_mat, make_4by4(key_list[0]))

    for i in range(1, 10):
        ans = four_transformations(ans, make_4by4(key_list[i]))
    ans = three_transformations(ans, make_4by4(key_list[10]))

    return ans


def print_text(arr):
    """
    prints from the array in a single string
    :param arr: 4x4 matrix with each cell representing a byte
    :return: a single string with byte separated values
    """
    temp = ""
    for j in range(4):
        for i in range(4):
            temp += arr[i][j] + " "

    print(temp)


keys = round_key_generation("5468617473206D79204B756E67204675")
print_text(encryption("29c3505f571420f6402299b31a02d73a", keys))
