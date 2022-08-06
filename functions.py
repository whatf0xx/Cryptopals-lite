import binascii
import base64

def hex_to_base64(h: str) -> str:
    hex_bytes = binascii.a2b_hex(h)
    return base64.encodebytes(hex_bytes)[:-1].decode()

def XOR_combo(a: str, b: str) -> str:
    a_int = int(a, 16)
    b_int = int(b, 16)
    return hex(a_int ^ b_int)[2:]