from functions import *

def test_conversion():
    assert to_bytes('Hello', 'plaintext') == ['0x48', '0x65', '0x6c', '0x6c', '0x6f']
    assert to_plaintext(to_bytes('Hello', 'plaintext')) == 'Hello'
    assert to_hex(to_bytes('48656c6c6f', 'hex')) == '48656c6c6f'
    assert to_b64(to_bytes('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d', 'hex')) == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    As that test passed, we have also passed Task 1 of the Cryptopals challenges!
    """

def test_XOR():
    buffer1 = to_bytes('1c0111001f010100061a024b53535009181c')
    buffer2 = to_bytes('686974207468652062756c6c277320657965')
    XOR_product = [hex_XOR(a, b) for a, b in zip(buffer1, buffer2)]
    assert to_hex(XOR_product) == '746865206b696420646f6e277420706c6179'
    """
    That's Task 2!
    """

