import base64
import pickle
from typing import List, Tuple
from itertools import cycle

def to_bytes(s: str, encoding: str = "hex") -> List[str]:
    match encoding:
        case "hex":
            return [hex(i) for i in bytes.fromhex(s)]
        case "b64":
            return [hex(i) for i in base64.b64decode(s)]
        case "plaintext":
            return [hex(i) for i in s.encode()]
        case _:
            raise ValueError("Encoding not recognised.")

def to_plaintext(b: List[str]) -> str:
    return "".join([bytes.fromhex(i[2:]).decode() for i in b])

def to_hex(b: List[str]) -> str:
    return "".join(i[2:] for i in b)

def to_b64(b: List[str]) -> str:
    return base64.b64encode(bytes.fromhex(to_hex(b))).decode()

def hex_XOR(s: str, t: str) -> str:
    """
    Take 2 hex-encoded bytes and return the hex-encoded byte corresponding to their logical XOR.
    """
    return hex(int(s, 16) ^ int(t, 16))

def key_XOR(buffer: List[str], key: List[str]) -> List[str]:
    return  [hex_XOR(p, k) for p, k in zip(buffer, cycle(key))]

def byte_XOR_encrypt(s: str, c: str, output_encoding="b64") -> str:
    """
    Encrypts 's', a plaintext string, using the single byte key, 'c'. 'c' should be passed as a string-represented hexadecimal number between 0 and 255, inclusive, obviously.
    """
    string_buffer = to_bytes(s, 'plaintext')
    
    output_buffer = key_XOR(string_buffer, [c])

    output_dict = {"b64": to_b64(output_buffer),
                    "hex": to_hex(output_buffer)}
    
    return output_dict[output_encoding]

def byte_XOR_decrypt(s: str, c: str, input_encoding="b64"):
    input_dict = {"b64" : to_bytes(s, "b64"),
                    "hex" : to_bytes(s)}
    
    cipher_buffer = input_dict[input_encoding]

    output_buffer = key_XOR(cipher_buffer, [c])

    return to_plaintext(output_buffer)

def get_frequencies(s: str, spaces=True):
    alphabet = "abcdefgijklmnopqrstuvwxyz"
    if spaces:
        alphabet += " "

    frequency_dict =  {a:s.count(a) for a in alphabet}
    return {a:frequency_dict[a] / sum(frequency_dict.values()) for a in alphabet}  # normalisation

def byte_XOR_break(s: str):
    with open("frequency_dict_spaces.pkl", 'rb') as f:
        frequency_dict_spaces = pickle.load(f)

    keys = [("0" * (2-len(hex(a)[2:])) + hex(a)[2:]).encode() for a in range(256)] # all possible byte keys
    for k in keys:
        print(k)
        guess_text = byte_XOR_decrypt(s, k)

if __name__ == "__main__":
    buffer = to_bytes("Hello", "plaintext")
    key = to_bytes("AB", "plaintext")
    print(key_XOR(buffer, key))