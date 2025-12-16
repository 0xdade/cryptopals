from binascii import hexlify
import string
from typing import NamedTuple

INPUT_STR = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

class KeyScore(NamedTuple):
    key: bytes
    score: int
    output: bytes

def xor_equal_length(hex_str1: str, hex_str2: str) -> str:
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    xored_bytes = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    return xored_bytes.hex()

def score_printable_ascii(instr: bytes) -> int:
    return sum([1 for x in instr if x in bytes(string.ascii_letters + " ,.\"'", "ascii")])

def find_xor_key(input_str: str) -> list[KeyScore]:
    val = bytes.fromhex(input_str)
    scores = []
    for i in range(0xff):
        key = bytes([i] * len(val))
        result = xor_equal_length(INPUT_STR, hexlify(key).decode())
        score = score_printable_ascii(bytes.fromhex(result))
        scores.append(KeyScore(key, score, bytes.fromhex(result)))
    return scores


if __name__ == "__main__":
    scores = find_xor_key(INPUT_STR)
    sorted_scores = sorted(scores, key=lambda x: x.score, reverse=True)
    print(sorted_scores[0:4])