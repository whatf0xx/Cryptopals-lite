import base64
import pickle

def hex_XOR(s: str, t: str) -> str:
    """
    Take 2 hex-encoded strings and return the value of their XOR. Assumes 's' is a text and 't' is key-like, so if len(t) < len(s) will repeat t until it pads the whole text. If len(t) > len(s), t is truncated. Both strings must be of even length and be hex-decodeable.
    """
    match (len(s) % 2, len(t) % 2):
        case (1, 0):
            raise "'s' is of odd length"

        case (0, 1):
            raise "'t' is of odd length"

        case (1, 1):
            raise "Both strings of odd length"
        
        case _:
            pass

    
    if len(t) < len(s):
        t *= (len(s) // len(t) + 1)
    
    if len(t) > len(s):
        t = t[:len(s)]

    result = hex(int(s, 16) ^ int(t, 16))[2:]
    padding = len(s) - len(result)
    return "0" * padding + result

def byte_XOR_encrypt(s: str, c: str, output_encoding="base64") -> str:
    s_hex = base64.b16encode(s.encode()).decode()
    c_hex = base64.b16encode(c.encode()).decode()
    if len(c_hex) != 2:
        raise Exception("Input must be a single byte")
    c_hex *= len(s_hex) // 2

    if c_hex == s_hex:
        return "0" * (len(s_hex) // 2)
    
    out_hex = hex( int(s_hex, 16) ^ int(c_hex, 16) )[2:]
    if len(out_hex) % 2 == 1:
        out_hex = "0" + out_hex

    match output_encoding:
        case "base64":
            return base64.b64encode(out_hex.encode()).decode()
        case "hex":
            return out_hex
        case _:
            raise Exception("Output encoding type not recognised.")

def byte_XOR_decrypt(s: str, c: str, output_encoding="plaintext"):
    # print(s)
    s_hex = base64.b64decode(s.encode()).decode()
    # print(s_hex)
    c_hex = base64.b16encode(c.encode()).decode()
    if len(c_hex) != 2:
        raise Exception("Input must be a single byte")
    c_hex *= len(s_hex) // 2

    if c_hex == s_hex:
        return "0" * (len(s_hex) // 2)
    
    out_hex = hex( int(s_hex, 16) ^ int(c_hex, 16) )[2:]
    if len(out_hex) % 2 == 1:
        out_hex = "0" + out_hex

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

    keys = ["0" * (2-len(hex(a)[2:])) + hex(a)[2:] for a in range(256)] # all possible byte keys
    for k in keys:
        print(k)
        guess_text = byte_XOR_decrypt(s, k)


def vig_encrypt(s: str, key: str, output_encoding: str="base64") -> str:
    return None

if __name__ == "__main__":
    print(hex_XOR("AAAAAA", "00"))
