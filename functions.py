import base64
import pickle
from statistics import mean
from typing import Dict, List, Tuple
from itertools import cycle
from scipy.stats import chisquare
from numpy import inf
from hexhamming import hamming_distance_string

def to_bytes(s: str, encoding: str = "hex") -> bytes:
    match encoding:
        case "hex":
            return base64.b16decode(s, casefold=True)
        case "b64":
            return base64.b64decode(s, casefold=True)
        case "plaintext":
            return s.encode()
        case _:
            raise ValueError("Encoding not recognised.")

def to_plaintext(b: bytes) -> str:
    return b.decode()

def to_hex(b: bytes) -> str:
    return base64.b16encode(b).decode().lower()

def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def encode_output(buffer: List[str], encoding="hex"):

    output_dict = {"b64": to_b64(buffer),
                    "hex": to_hex(buffer)}
    
    return output_dict[encoding]

def eq_buffer_XOR(a: bytes, b: bytes) -> bytes:
    """
    Take 2 equal length buffers and return their logical XOR.
    """
    assert len(a) == len(b), "Byte buffers must be of equal length."
    return bytes([i^j for i, j in zip(a, b)])

def pad_buffer(buffer: bytes, pad: bytes, length: int) -> bytes:
    return pad * length + buffer

def hex_XOR(s: str, t: str) -> str:
    """
    Take 2 hex-encoded bytes and return the hex-encoded byte corresponding to their logical XOR.
    """
    return hex(int(s, 16) ^ int(t, 16))

def key_XOR(buffer: bytes, key: bytes) -> bytes:
    return  bytes([p ^ k for p, k in zip(buffer, cycle(key))])

def byte_XOR_encrypt(s: str, c: bytes, output_encoding="b64") -> str:
    """
    Encrypts 's', a plaintext string, using the single byte key, 'c'.
    """
    string_buffer = to_bytes(s, 'plaintext')
    
    output_buffer = key_XOR(string_buffer, c)
    
    return encode_output(output_buffer, output_encoding)

def byte_XOR_decrypt(s: str, c: str, input_encoding="b64") -> str:
    
    cipher_buffer = to_bytes(s, input_encoding)

    output_buffer = key_XOR(cipher_buffer, c)

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

def vig_decrypt(c: str, k: str, input_encoding='b64') -> str:
    cipher_buffer = to_bytes(c, input_encoding)
    key_buffer = to_bytes(k, 'plaintext')

    return to_plaintext(key_XOR(cipher_buffer, key_buffer))

def norm_hamming_dist(s: str, l: int) -> float:
    """
    Find the Hamming distance between successive groups of bytes, of length l, in the string, s, taken to be hex-encoded.
    """
    string_buffer = to_bytes(s)
    repeats = len(string_buffer) // l - 1
    distances = [0] * repeats
    for i in range(repeats):
        buffer1 = string_buffer[i*l:(i+1)*l]
        buffer2 = string_buffer[(i+1)*l:(i+2)*l]

        distances[i] = hamming_distance_string(to_hex(buffer1), to_hex(buffer2)) / l

    return mean(distances)

def crack_key_length(c: str, max_length=100) -> int:
    pass

if __name__ == "__main__":
    string = """1D421F4D0B0F021F4F134E3C1A69651F491C0E4E13010B074E1B01164536001E01496420541D1D4333534E6552060047541C"""
    with open('lotr.txt', 'r') as lotr:
        lines_to_read = 1000
        text = ""
        for line in lotr:
            lines_to_read -= 1
            if lines_to_read < 0:
                break
            else:
                for char in line:
                    text += char

    print(norm_hamming_dist(to_hex(to_bytes(text, 'plaintext')), 1))