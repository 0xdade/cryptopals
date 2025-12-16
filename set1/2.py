INPUT_STR = "1c0111001f010100061a024b53535009181c"
XOR_KEY = "686974207468652062756c6c277320657965"

def fixed_length_xor(bytes1: bytes, bytes2: bytes) -> str:
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)).hex()

if __name__ == "__main__":
    result = fixed_length_xor(bytes.fromhex(INPUT_STR), bytes.fromhex(XOR_KEY))
    print(result)
    EXPECTED_RESULT = "746865206b696420646f6e277420706c6179"
    print(f"Match: {result == EXPECTED_RESULT}")