import binascii
import base64

def string_to_bytes(s: str) -> bytes:
    """
    Takes a plaintext string and returns the corresponding bytes.
    """
    return s.encode()

def bytes_to_string(b: bytes) -> str:
    """
    Takes a set of bytes and returns the corresponding plaintext.
    """
    return b.decode()

def hex_to_bytes(h: str) -> bytes:
    """
    Takes a hex-encoded string and returns the corresponding bytes.
    """
    return binascii.a2b_hex(h)

def bytes_to_hex(b: bytes) -> str:
    return binascii.b2a_hex(b).decode()

def string_to_hex(s: str) -> str:
    """
    Takes a plaintext string and returns the corresponding hex-encoded string.
    """
    return bytes_to_hex(string_to_bytes(s))

def hex_to_string(h: str) -> str:
    """
    Takes a hex-encoded string and returns the corresponding plaintext.
    """
    return bytes_to_string(hex_to_bytes(h))

def hex_to_base64(h: str) -> str:
    """
    Takes a hex-encoded string and returns the associated base 64-encoded string.
    """
    hex_bytes = binascii.a2b_hex(h)
    return base64.encodebytes(hex_bytes)[:-1].decode()

def hex_XOR_combo(a: str, b: str) -> str:
    """
    Takes two hex-encoded strings and returns their XOR-combo, as a hex-encoded string.
    """
    a_int = int(a, 16)
    b_int = int(b, 16)
    result = hex(a_int ^ b_int)[2:]
    if len(result) % 2 == 0:
        return result
    return "0" + result

def single_byte_XOR(a: str, character: str) -> str:
    """
    Takes a plaintext string and returns its XOR against a single character.
    """
    if len(character) != 1:
        raise ValueError(f"'character' ('{character}') not a single character")
    
    buffer = string_to_hex(character * len(a))
    return hex_XOR_combo(string_to_hex(a), buffer)