# Advanced Encryption Standard
import math
import numpy as np

## Predefined S-Box for AES
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

## Debugging purposes
def printMatrix(matrix):
    if isinstance(matrix[0], str):
        print(" ".join(matrix))
    else:
        for row in matrix:
            print(" ".join(row))

## Converts a string password into the 4x4 key state mentioned in the paper
def convertState(password):
    state = []
    if len(password) == 16:
        for i in range(16):
            ## Converts each char into its ascii values, and then formats it into a 2-digit hex string by 
            ## turning the ascii value (base 10) into hex (base 16)
            state.append("{:02X}".format(ord(password[i])))
    nState = np.array(state)
    temp = nState.reshape(4,4)
    return np.transpose(temp)

def rotWord(matrix, column):
    matrix = np.array(matrix)
    
    ## Since rotword is a column operation, we need to transpose the matrix to operate on columns easier
    matrix = np.transpose(matrix)
    
    row = []
    
    ## Appending the int values of the hex strings in the specified column for matrix multiplication (Cant multiply hex strings)
    ## The column is 1-indexed in the paper, so we subtract 1 to get the correct index
    for hex in matrix[column - 1]:
        row.append(int(hex, 16))
    row = np.array(row)
    
    ## Permutation matrix mentioned in the paper
    P_Rot = np.array([
        [0, 1, 0, 0],
        [0, 0, 1, 0],  
        [0, 0, 0, 1],
        [1, 0, 0, 0]
    ])
    
    ## @ here is just matrix multiplication
    shifted = P_Rot @ row
    final = []
    
    ## Reformatting the permuted values back into hex strings for the next operation
    for val in shifted:
        final.append("{:02X}".format(val))
    
    return final

# Used in key generation as well as rounds of encryption
def SubByte1D(row):
    output = []
    for byte in row:
        # Ensure byte is a 2-digit hex string and formats into 0X[][] like 0XAB
        if isinstance(byte, int):
            hex_byte = "{:02X}".format(byte)
        else:
            hex_byte = byte.upper()  

        row_idx = int(hex_byte[0], 16) #Takes the first hex digit like A and converts it to its base 10 integer
        col_idx = int(hex_byte[1], 16) #Takes the second hex digit like B and converts it to its base 10 integer
        
        # These ids are basically our indices in the S-Box
        substituteByte = fowardSBox[row_idx][col_idx]
        
        # Not needed but just for consistency, we format into uppercase hex
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
            ## Changing from hex to int just so we can do matrix multiplication 
            int_row.append(int(hex, 16))
        shifted.append(int_row)
    shifted = np.array(shifted)
    
    for i in range(4):
        ## Applying permutation matrices to each row
        shifted[i] = permutation_matrices[i] @ shifted[i] 
    
    final = []
    for row in shifted:
        hex_row = []
        for val in row:
            ## Reformatting the int values back into hex strings
            hex_row.append("{:02X}".format(val))
        final.append(hex_row)
    
    return final

# Multiply two bytes in GF(2^8) — used in AES (like in MixColumns)
def galois_multiply(byte1, byte2):
    a = int(byte1, 16)  # Convert hex string to integer 
    b = int(byte2, 16)  # Couldn't figure out a nice way to do this with binary and hex strings, so we use ints to use built in bit wise operations
    result = 0  # This will hold the final output

    for i in range(8):  # Repeat 8 times (for each bit in b)
        if b & 1:  # If the last bit of b is 1
            result = int(XOR1("{:02X}".format(result), "{:02X}".format(a)), 16)  # Add a to result (using XOR)

        carry = a & 0x80  # Check if a starts with a 1 (overflow if we shift)
        a = a << 1  # Shift a left (multiply by x)

        if carry:  # If we overflowed (a became 9 bits)
            a = int(XOR1("{:02X}".format(a), "11B"), 16)  # Reduce with AES polynomial 

        a = a & 0xFF  # Keep only the last 8 bits
        b = b >> 1  # Move to the next bit of b

    return "{:02X}".format(result)  # Return the result as a 2-digit hex string


## XOR for binary values longer than 8 bits
def XOR1(byte1, byte2):
    # Turn the hex strings into integers
    a = int(byte1, 16)
    b = int(byte2, 16)
    
    result = 0  
    for i in range(8):  # Go through each of the 8 bit positions
        bit1 = (a >> i) & 1  # Get the i-th bit of a
        bit2 = (b >> i) & 1  # Get the i-th bit of b
        xor_bit = (bit1 + bit2) % 2  # XOR the two bits (same as 1 if different, 0 if same)
        result |= (xor_bit << i)  # Put the result bit back in its correct position

    return "{:02X}".format(result)  # Convert the result back into a 2-digit uppercase hex string


# Less complicated XOR (for only 8 bit binatry values). More intuitive for understanding 
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
    ## Predefined matrix 
    fixed_matrix = [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
    ]

    result = []  

    for col in range(4):  # Go through each column of the input matrix
        new_col = [] 
        for row in range(4):  # Go through each row of the fixed matrix
            val = 0  # Start with 0
            for k in range(4):  # Galois Multiply and XOR each pair of elements
                product = galois_multiply(fixed_matrix[row][k], matrix[k][col])
                val = int(XOR2("{:02X}".format(val), product), 16)  # Accumulate result using XOR
            new_col.append("{:02X}".format(val))  # Convert to hex and add to new column
        result.append(new_col)  # Add the new column to the result

    # Transpose the result to match the original column-major layout
    return np.transpose(result).tolist()



def AddRoundKey(matrix, key):
    newMatrix = []
    for i in range(len(matrix)):
        row = []
        for j in range(len(matrix[0])):
            ## Corresponding elements of the matrix and key are XORed together
            row.append(XOR2(matrix[i][j], key[i][j]))
        newMatrix.append(row)
    return newMatrix

def keyExpansion(initialKey):
    # Round constants used to add variety in each round key (Rcon[i] for round i+1)
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

    key_schedule = initialKey.copy()  # Start with the initial 4x4 key matrix

    # AES stores keys column-wise, so we transpose: each row becomes a word (4 bytes)
    key_schedule_T = np.transpose(key_schedule).tolist()

    # Generate 44 words total (4 for each of the 11 rounds)
    for i in range(4, 4 * 11):  # Start from 4 since the first 4 words are from the original key
        prev_word = key_schedule_T[i - 1]  # Last word in current schedule

        if i % 4 == 0:
            # Every 4th word: apply key schedule core (RotWord + SubBytes + XOR with Rcon)

            # Grab the last 4 words and format into 4x4 to rotate the last column
            temp_matrix = np.transpose(key_schedule_T[i - 4:i]).tolist()
            
            # Rotate the last column up (e.g., [D4, BF, 5D, 30] → [BF, 5D, 30, D4])
            rotated = rotWord(temp_matrix, 4)

            # Apply S-box substitution to each byte
            subbed = SubByte1D(rotated)

            # Add the round constant (only affects the first byte)
            rcon = RCON[(i // 4) - 1]

            # XOR subbed word with Rcon to create a temp word
            temp = [XOR2(subbed[j], rcon[j]) for j in range(4)]
        else:
            # If not a multiple of 4, just use the previous word as-is
            temp = prev_word

        # XOR temp with the word 4 positions earlier to create the new word
        new_word = [XOR2(temp[j], key_schedule_T[i - 4][j]) for j in range(4)]

        # Add the new word to the key schedule
        key_schedule_T.append(new_word)

    # Group every 4 words into a 4x4 matrix and transpose to match AES column-major layout
    round_keys = []
    for i in range(0, len(key_schedule_T), 4):
        round_matrix = np.transpose(key_schedule_T[i:i+4]).tolist()
        round_keys.append(round_matrix)

    return round_keys  # Returns 11 round keys: one for each AES round (0–10)






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



