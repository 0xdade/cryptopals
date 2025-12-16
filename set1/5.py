INPUT_STR = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
XOR_KEY = "ICE"

def fixed_length_xor(bytes1: bytes, bytes2: bytes) -> str:
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)).hex()

def expand_repeating_xor_key(key: bytes, length: int) -> bytes:
    expanded_key = bytearray()
    for i in range(length):
        expanded_key.append(key[i % len(key)])
    return bytes(expanded_key)

if __name__ == "__main__":
    key = expand_repeating_xor_key(XOR_KEY.encode(), len(INPUT_STR))
    result = fixed_length_xor(INPUT_STR.encode(), key)
    print(result)
    EXPECTED_RESULT = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    print(f"Match: {result == EXPECTED_RESULT}")