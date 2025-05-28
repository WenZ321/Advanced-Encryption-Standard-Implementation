import math
import numpy as np

from encrypt import (
    keyExpansion,
    XOR2,
    XOR1, 
    convertState,
    printMatrix,
    fowardSBox,
    SubByte1D,
    AddRoundKey,
    galois_multiply,
)

inverseSBox = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]

def InverseRotWord(matrix, column):
    temp = []
    for i in range(len(matrix)):
        
        byte = matrix[(i - 1) % len(matrix)][column-1]
        temp.append(byte)
    return temp  

def InvSubByte1D(row):
    output = []
    for byte in row:
        if isinstance(byte, int):
            hex_byte = "{:02X}".format(byte)
        else:
            hex_byte = byte.upper()  

        row_idx = int(hex_byte[0], 16)
        col_idx = int(hex_byte[1], 16) 
        substituteByte = inverseSBox[row_idx][col_idx]
        output.append("{:02X}".format(substituteByte))
    return output  


def InvSubByte2D(matrix):
    temp = []
    for row in matrix:
        temp.append(InvSubByte1D(row))
    return temp


def InvShiftRows(matrix):
    P0 = np.array([[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]])
    P1 = np.array([[0,0,0,1],[1,0,0,0],[0,1,0,0],[0,0,1,0]])
    P2 = np.array([[0,0,1,0],[0,0,0,1],[1,0,0,0],[0,1,0,0]])
    P3 = np.array([[0,1,0,0],[0,0,1,0],[0,0,0,1],[1,0,0,0]])
    permutation_matrices = [P0, P1, P2, P3]

    shifted = []
    for row in matrix:
        int_row = [int(hex, 16) for hex in row]
        shifted.append(int_row)
    shifted = np.array(shifted)

    for i in range(4):
        shifted[i] = permutation_matrices[i] @ shifted[i] 

    final = []
    for row in shifted:
        final.append(["{:02X}".format(val) for val in row])
    return final


def InvMixColumns(matrix):
    fixed_matrix = [
        ["0E", "0B", "0D", "09"],
        ["09", "0E", "0B", "0D"],
        ["0D", "09", "0E", "0B"],
        ["0B", "0D", "09", "0E"]
    ]

    result = []
    for col in range(4):
        new_col = []
        for row in range(4):
            val = 0
            for k in range(4):
                product = galois_multiply(fixed_matrix[row][k], matrix[k][col])
                val = int(XOR2("{:02X}".format(val), product), 16)
            new_col.append("{:02X}".format(val))
        result.append(new_col)

    return np.transpose(result).tolist()


def decrypt(ciphertext, password):
    state = convertState(ciphertext)
    initialKey = convertState(password)
    keys = keyExpansion(initialKey)

    for i in range(10, -1, -1):
        if i == 10:
            state = AddRoundKey(state, keys[i])
            state = InvShiftRows(state)
            state = InvSubByte2D(state)
        elif i == 0:
            state = AddRoundKey(state, keys[i])
        else:
            state = AddRoundKey(state, keys[i])
            state = InvMixColumns(state)
            state = InvShiftRows(state)
            state = InvSubByte2D(state)

    return state


def hex_to_str(hex_string):
    return bytes.fromhex(hex_string).decode("latin1")  # latin1 preserves raw byte values

# Test vector from FIPS-197
key_hex = "00000000000000000000000000000000"
plaintext_hex = "0336763e966d92595a567cc9ce537f5e"
expected_ciphertext_hex = "f34481ec3cc627bacd5dc3fb08f273e6"

# Convert to strings
key_str = hex_to_str(key_hex)
plaintext_str = hex_to_str(plaintext_hex)

# Run encryption
cipher_matrix = decrypt(plaintext_str, key_str)

# Flatten result to a single hex string in column-major order
def flatten_state(matrix):
    return ''.join(matrix[row][col] for col in range(4) for row in range(4))

ciphertext = flatten_state(cipher_matrix)

# Show results
print("Your AES ciphertext:", ciphertext.upper())
print("Expected ciphertext :", expected_ciphertext_hex.upper())
print("Match?              :", ciphertext.upper() == expected_ciphertext_hex.upper())