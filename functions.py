import base64
import pickle
from typing import List, Tuple

class types:
    def __init__(self) -> None:
        self.int = int
        self.str = str
        self.bytes = bytes
    
def key_to_hex(key, length: int) -> str:
    """
    Take a byte input as a string, integer or byte object and process it to a hex string, to be used as a key.
    """
    t = types()
    match type(key):
        case t.str | t.int:
            c_hex = base64.b16encode(key.encode()).decode()
            if len(c_hex) != 2:
                raise Exception("Input must be a single byte")
            return c_hex * length

        case t.bytes:
            return key.decode()

        case _:
            raise "Couldn't recognise the key type."


    s_hex = base64.b64decode(s.encode()).decode()
    print(s_hex)
    c_hex = key_to_hex(c, len(s_hex) // 2)
    
    out_hex = hex_XOR(s_hex, c_hex)

    match output_encoding:
        case "plaintext":
            return base64.b16decode(out_hex.encode(), casefold=True).decode()
        case "hex":
            return out_hex
        case _:
            raise Exception("Output encoding type not recognised.")

def get_frequencies(s: str, spaces=True):
    alphabet = "abcdefgijklmnopqrstuvwxyz "
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

def vig_encrypt(s: str, key: str, output_encoding: str="base64") -> str:
    return None

def to_bytes(s: str, encoding: str = "hex") -> List[str]:
    match encoding:
        case "hex":
            return [hex(i) for i in bytes.fromhex(s)]
        case "64":
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

def byte_XOR_encrypt(s: str, c: str, output_encoding="base64") -> str:
    """
    Encrypts 's', a plaintext string, using the single byte key, 'c'. 'c' should be passed either as an ascii character, or as a bytes object of a single byte. 'output_encoding' can be 'base64' or 'hex', if the output message should be left as a hex-encoded string, as opposed to the standard behaviour of a base64-encoded string.
    """
    s_hex = base64.b16encode(s.encode()).decode()
    c_hex = key_to_hex(c, len(s_hex) // 2)
    
    out_hex = hex_XOR(s_hex, c_hex)
    print(out_hex + "\n")

    match output_encoding:
        case "base64":
            return base64.b64encode(out_hex.encode()).decode()
        case "hex":
            return out_hex
        case _:
            raise Exception("Output encoding type not recognised.")

def byte_XOR_decrypt(s: str, c: str, output_encoding="plaintext"):
    pass
