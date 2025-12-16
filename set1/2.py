INPUT_STR = "1c0111001f010100061a024b53535009181c"
XOR_KEY = "686974207468652062756c6c277320657965"

def xor_equal_length(hex_str1: str, hex_str2: str) -> str:
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    xored_bytes = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    return xored_bytes.hex()

if __name__ == "__main__":
    result = xor_equal_length(INPUT_STR, XOR_KEY)
    print(result)