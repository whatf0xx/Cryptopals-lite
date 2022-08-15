import functions
import sys

"""
Decrypt a file or string using a range of basic encrytion methods. By default, will try and encrpyt a file unless '-s' argument is passed.

Standard use: py encrypt.py (-s) filename (string) key
"""

inputs = sys.argv

match inputs[1:]:
    case ["-s", string, key]:
        print(functions.byte_XOR_decrypt(string, key))
    case [filename, key]:
        with open(filename, 'r') as f:
            string = "".join(s for s in f)
        with open("dec-" + filename, 'w') as f:
            f.write(functions.byte_XOR_decrypt(string, key))
    case _:
        raise Exception("Couldn't make sense of the input.")