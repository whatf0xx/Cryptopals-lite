import binascii
import base64

def string_to_hex(s: str) -> str:
    """
    Takes a plaintext string and returns the corresponding hex-encoded string.
    """
    return binascii.b2a_hex(s.encode()).decode()

def hex_to_string(h: str) -> str:
    """
    Takes a hex-encoded string and returns the corresponding plaintext.
    """
    return binascii.a2b_hex(h).decode()

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
    return hex(a_int ^ b_int)[2:]

def single_byte_XOR(a: str, character: str) -> str:
    """
    Takes a single byte, passed as a utf-8 character, and a hex-encoded string
    """
    if len(character) != 1:
        raise ValueError(f"character ('{character}') not a single byte")
    
    buffer = binascii.b2a_hex(character.encode()) * len(a)
    return hex_XOR_combo(a, buffer)