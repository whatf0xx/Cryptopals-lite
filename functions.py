import binascii
import base64

def hex_to_base64(h: str) -> str:
    hex_bytes = binascii.a2b_hex(h)
    return base64.encodebytes(hex_bytes)[:-1].decode()

def main() -> None:
    print(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

if __name__ == "__main__":
    main()