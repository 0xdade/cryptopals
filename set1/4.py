from binascii import hexlify
import string

def xor_equal_length(hex_str1: str, hex_str2: str) -> str:
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    xored_bytes = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    return xored_bytes.hex()

def score_printable_ascii(instr: bytes) -> int:
    return sum([1 for x in instr if x in bytes(string.ascii_letters + " ,.\"'", "ascii")])

def find_xor_key(input_str: str) -> list[tuple[bytes, int, bytes]]:
    val = bytes.fromhex(input_str)
    scores = []
    for i in range(0xff):
        key = bytes([i] * len(val))
        result = xor_equal_length(input_str, hexlify(key).decode())
        score = score_printable_ascii(bytes.fromhex(result))
        scores.append((key, score, bytes.fromhex(result)))
    return scores


if __name__ == "__main__":
    with open("4.txt", "r") as f:
        input_lines = f.readlines()
    high_scores = []
    for input_str in input_lines:
        scores = find_xor_key(input_str.strip())
        sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
        high_scores.append(sorted_scores[0])
    sorted_high_scores = sorted(high_scores, key=lambda x: x[1], reverse=True)
    print(sorted_high_scores[0:4])