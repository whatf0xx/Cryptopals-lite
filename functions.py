import base64
import pickle
from typing import Dict, List, Tuple
from itertools import cycle
from scipy.stats import chisquare
from numpy import inf

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
    return "".join([bytes.fromhex("0" * (2-len(i[2:])) + i[2:]).decode() for i in b])

def to_hex(b: List[str]) -> str:
    return "".join("0" * (2-len(i[2:])) + i[2:] for i in b)

def to_b64(b: List[str]) -> str:
    return base64.b64encode(bytes.fromhex(to_hex(b))).decode()

def encode_output(buffer: List[str], encoding="hex"):

    output_dict = {"b64": to_b64(buffer),
                    "hex": to_hex(buffer)}
    
    return output_dict[encoding]

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
    
    return encode_output(output_buffer)

def byte_XOR_decrypt(s: str, c: str, input_encoding="b64") -> str:
    
    cipher_buffer = to_bytes(s, input_encoding)

    output_buffer = key_XOR(cipher_buffer, [c])

    return to_plaintext(output_buffer)

def get_frequencies(s: str, spaces=True) -> Dict:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    if spaces:
        alphabet += " "

    frequency_dict =  {a:s.count(a) for a in alphabet}
    if sum(frequency_dict.values()) == 0:
        raise ValueError("No letters detected at all!")

    return {a:frequency_dict[a] / sum(frequency_dict.values()) for a in alphabet}  # normalisation

def byte_XOR_break(s: str) -> Tuple[str, str, float]:
    best_guess = None
    best_key = None
    inf_ch_sq = inf
    with open("frequency_dict_spaces.pkl", 'rb') as f:
        true_freqs = pickle.load(f)

    keys = [hex(a) for a in range(256)] # all possible byte keys
    for k in keys:
        try:
            guess_text = byte_XOR_decrypt(s, k, input_encoding='hex')
        except:
            continue

        try:
            guess_freqs = get_frequencies(guess_text)
            ch_sq = chisquare(list(guess_freqs.values()), list(true_freqs.values()))[0]
        except:
            ch_sq = inf
        if ch_sq < inf_ch_sq:
            best_guess = guess_text
            best_key = k
            inf_ch_sq = ch_sq
        

    return (best_key, best_guess, inf_ch_sq)

def vig_encrypt(p: str, k: str, output_encoding='hex') -> str:
    
    plaintext_buffer = to_bytes(p, 'plaintext')
    key_buffer = to_bytes(k, 'plaintext')

    return encode_output(key_XOR(plaintext_buffer, key_buffer), output_encoding)

if __name__ == "__main__":
    pass