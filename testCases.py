import math
import numpy as np
from encrypt import encrypt
from decrypt import decrypt

# Test cases are hex values of a string formatted in one line
def hex_to_str(hex_string):
    return bytes.fromhex(hex_string).decode("latin1")  # latin1 preserves raw byte values


def state_to_hex(matrix):
    result = ''
    col = 0
    while col < 4:
        row = 0
        while row < 4:
            result = result + matrix[row][col]
            row = row + 1
        col = col + 1
    return result

input_file = open("encrInput.txt", "r")
inputs = []
line = input_file.readline()
while line:
    inputs.append(line.strip().upper())
    line = input_file.readline()
input_file.close()

output_file = open("encrOutput.txt", "r")
expected_outputs = []
line = output_file.readline()
while line:
    expected_outputs.append(line.strip().upper())
    line = output_file.readline()
output_file.close()

key = "00000000000000000000000000000000"
key_str = hex_to_str(key)

def encryptTest():
    i = 0
    while i < len(inputs):
        plaintext_hex = inputs[i]
        expected_hex = expected_outputs[i]

        plaintext = hex_to_str(plaintext_hex)
        encrypted = encrypt(plaintext, key_str)
        result_hex = state_to_hex(encrypted)

        if result_hex == expected_hex:
            print("Test " + str(i + 1) + ": ✅ PASS")
        else:
            print("Test " + str(i + 1) + ": ❌ FAIL")
            print("  Input:    " + plaintext_hex)
            print("  Expected: " + expected_hex)
            print("  Got:      " + result_hex)

        i = i + 1
        
        
def decryptTest():
    i = 0
    while i < len(inputs):
        plaintext_hex = expected_outputs[i]
        expected_hex = inputs[i]

        plaintext = hex_to_str(plaintext_hex)
        encrypted = decrypt(plaintext, key_str)
        result_hex = state_to_hex(encrypted)

        if result_hex == expected_hex:
            print("Test " + str(i + 1) + ": ✅ PASS")
        else:
            print("Test " + str(i + 1) + ": ❌ FAIL")
            print("  Input:    " + plaintext_hex)
            print("  Expected: " + expected_hex)
            print("  Got:      " + result_hex)

        i = i + 1
        

# encryptTest()
# decryptTest()