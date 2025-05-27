# Advanced Encryption Standard
import math
import numpy as np


fowardSBox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

def printMatrix(matrix):
    if isinstance(matrix[0], str):
        print(" ".join(matrix))
    else:
        for row in matrix:
            print(" ".join(row))

def convertState(password):
    state = []
    if len(password) == 16:
        for i in range(16):
            state.append("{:02X}".format(ord(password[i])))
    nState = np.array(state)
    temp = nState.reshape(4,4)
    return np.transpose(temp)

def rotWord(matrix, column):
    matrix = np.array(matrix)
    matrix = np.transpose(matrix)
    
    row = []
    for hex in matrix[column - 1]:
        row.append(int(hex, 16))
    row = np.array(row)
    
    P_Rot = np.array([
        [0, 1, 0, 0],
        [0, 0, 1, 0],  
        [0, 0, 0, 1],
        [1, 0, 0, 0]
    ])
    
    shifted = P_Rot @ row
    final = []
    for val in shifted:
        final.append("{:02X}".format(val))
    
    return final

# Used in key generation
def SubByte1D(row):
    output = []
    for byte in row:
        # Ensure byte is a 2-digit hex string and formats into 0X[][] like 0XAB
        # These 2 digit hex strings are base 10 integers converted to base 16
        if isinstance(byte, int):
            hex_byte = "{:02X}".format(byte)
        else:
            hex_byte = byte.upper()  

        row_idx = int(hex_byte[0], 16) #Takes the first hex digit like A and converts it to its base 10 integer
        col_idx = int(hex_byte[1], 16) #Takes the second hex digit like B and converts it to its base 10 integer
        substituteByte = fowardSBox[row_idx][col_idx]
        output.append("{:02X}".format(substituteByte))
    return output  

# Used in main rounds of encryption
def SubByte2D(matrix):
    temp = []
    for row in matrix:
        temp.append(SubByte1D(row))
    return temp

def ShiftRows(matrix):
    
    ## Really just a permutation
    P0 = np.array([[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]])
    P1 = np.array([[0,1,0,0],[0,0,1,0],[0,0,0,1],[1,0,0,0]])
    P2 = np.array([[0,0,1,0],[0,0,0,1],[1,0,0,0],[0,1,0,0]])
    P3 = np.array([[0,0,0,1],[1,0,0,0],[0,1,0,0],[0,0,1,0]])
    permutation_matrices = [P0, P1, P2, P3]
    
    shifted = []
    for row in matrix:
        int_row = []
        for hex in row:
            int_row.append(int(hex, 16))
        shifted.append(int_row)
    shifted = np.array(shifted)
    
    for i in range(4):
        shifted[i] = permutation_matrices[i] @ shifted[i] 
    
    final = []
    for row in shifted:
        hex_row = []
        for val in row:
            hex_row.append("{:02X}".format(val))
        final.append(hex_row)
    
    return final

# In GF(2^8)
def galois_multiply(byte1, byte2):
    a = int(byte1, 16)
    b = int(byte2, 16)
    result = 0

    for i in range(8):
        if b & 1:
            result = int(XOR28("{:02X}".format(result), "{:02X}".format(a)), 16)
        carry = a & 0x80
        a <<= 1
        if carry:
            a = int(XOR28("{:02X}".format(a), "11B"), 16)
        a &= 0xFF
        b >>= 1

    return "{:02X}".format(result)

def XOR28(byte1, byte2):
    # Convert 2-character hex strings to binary
    a = int(byte1, 16)
    b = int(byte2, 16)
    
    # Perform bitwise XOR manually
    result = 0
    for i in range(8):
        bit1 = (a >> i) & 1
        bit2 = (b >> i) & 1
        xor_bit = (bit1 + bit2) % 2  
        result |= (xor_bit << i)

    return "{:02X}".format(result)

# XOR in GF(2)
def XOR2(byte1, byte2):
    # Convert hex strings to integers
    a = int(byte1, 16)
    b = int(byte2, 16)

    # Convert integers to 8-bit binary strings
    bin1 = "{:08b}".format(a)  
    bin2 = "{:08b}".format(b)  

    # Convert the two binary strings to two 1x8 matrices 
    vec1 = []
    for char in bin1:
        vec1.append(int(char))

    vec2 = []
    for char in bin2:
        vec2.append(int(char))

    # Add the two matrices and % 2 every element 
    result_vec = []
    for i in range(8):
        bit_sum = (vec1[i] + vec2[i]) % 2
        result_vec.append(bit_sum)

    # Convert matrix back to binary string
    result_bin = ""
    for bit in result_vec:
        result_bin += str(bit)

    # Convert binary string to integer to reformat back into hex 
    result_int = int(result_bin, 2)
    result_hex = "{:02X}".format(result_int)

    return result_hex


def MixColumns(matrix):
    ## predefined
    fixed_matrix = [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
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

    # Transpose back to maintain row-major format
    return np.transpose(result).tolist()


def AddRoundKey(matrix, key):
    newMatrix = []
    for i in range(len(matrix)):
        row = []
        for j in range(len(matrix[0])):
            row.append(XOR2(matrix[i][j], key[i][j]))
        newMatrix.append(row)
    return newMatrix

def keyExpansion(initialKey):
    RCON = [
        ["01", "00", "00", "00"],
        ["02", "00", "00", "00"],
        ["04", "00", "00", "00"],
        ["08", "00", "00", "00"],
        ["10", "00", "00", "00"],
        ["20", "00", "00", "00"],
        ["40", "00", "00", "00"],
        ["80", "00", "00", "00"],
        ["1B", "00", "00", "00"],
        ["36", "00", "00", "00"]
    ]

    # Start with the initial key
    key_schedule = initialKey.copy()  # 4x4 matrix

    # Transpose to work with column logic
    key_schedule_T = np.transpose(key_schedule).tolist()  # each row is a word now

    for i in range(4, 4 * (11)):
        prev_word = key_schedule_T[i - 1]

        if i % 4 == 0:
            # Temporarily convert back to 4x4 matrix to use rotWord()
            temp_matrix = np.transpose(key_schedule_T[i - 4:i]).tolist()
            rotated = rotWord(temp_matrix, 4)  # rotate last word (column 4)
            subbed = SubByte1D(rotated)
            rcon = RCON[(i // 4) - 1]
            temp = [XOR2(subbed[j], rcon[j]) for j in range(4)]
        else:
            temp = prev_word

        # XOR with word from 4 steps earlier
        new_word = [XOR2(temp[j], key_schedule_T[i - 4][j]) for j in range(4)]
        key_schedule_T.append(new_word)

    # Transpose each set of 4 words back to row-major 4x4 matrices
    round_keys = []
    for i in range(0, len(key_schedule_T), 4):
        round_matrix = np.transpose(key_schedule_T[i:i+4]).tolist()
        round_keys.append(round_matrix)

    return round_keys




#### Rounds ####

def firstRound(message, key):
    temp = AddRoundKey(message, key)
    return temp

def mainRounds(message, key):
    temp = SubByte2D(message)
    temp = ShiftRows(temp)
    temp = MixColumns(temp)
    temp = AddRoundKey(temp, key)
    return temp

def lastRound(message, key):
    temp = SubByte2D(message)
    temp = ShiftRows(temp)
    temp = AddRoundKey(temp, key)
    return temp


def encrypt(message, password):
    encryptedMessage = convertState(message)
    initialKey = convertState(password)

    keys = keyExpansion(initialKey)
    
    for i in range(11):
        
        if i == 0:
            encryptedMessage = firstRound(encryptedMessage, keys[i])
        elif i == 10:
            encryptedMessage = lastRound(encryptedMessage, keys[i])
        else:
            encryptedMessage = mainRounds(encryptedMessage, keys[i]) 
    return encryptedMessage



def hex_to_str(hex_string):
    return bytes.fromhex(hex_string).decode("latin1")  # latin1 preserves raw byte values



# Test vector from FIPS-197
key_hex = "00000000000000000000000000000000"
plaintext_hex = "f34481ec3cc627bacd5dc3fb08f273e6"
expected_ciphertext_hex = "0336763e966d92595a567cc9ce537f5e"

# Convert to strings
key_str = hex_to_str(key_hex)
plaintext_str = hex_to_str(plaintext_hex)

# Run encryption
cipher_matrix = encrypt(plaintext_str, key_str)

# Flatten result to a single hex string in column-major order
def flatten_state(matrix):
    return ''.join(matrix[row][col] for col in range(4) for row in range(4))

ciphertext = flatten_state(cipher_matrix)

# Show results
print("Your AES ciphertext:", ciphertext.upper())
print("Expected ciphertext :", expected_ciphertext_hex.upper())
print("Match?              :", ciphertext.upper() == expected_ciphertext_hex.upper())



