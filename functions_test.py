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

def test_sbXOR():
    plaintext = "Cooking MC's like a pound of bacon"
    key = "X"
    assert byte_XOR_encrypt(plaintext, hex(ord(key)), output_encoding="hex") == "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    """
    That just proves that the function works, it's not actually equivalent to breaking the cipher!
    """

def test_sbXOR_dec():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key = "X"
    assert byte_XOR_decrypt(ciphertext, hex(ord(key)), input_encoding="hex") == "Cooking MC's like a pound of bacon"
    """
    This does what it should, could the functon be refactored in terms of the encryption function?
    """

def test_vig():
    plaintext = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key = "ICE"
    correct_ciphertext = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""

    assert vig_encrypt(plaintext, key) == correct_ciphertext
    assert vig_decrypt(correct_ciphertext, key, 'hex') == plaintext