"""RFC 1751 - A Convention for Human-Readable 128-bit Keys (S/Key heritage).

Encodes raw key bytes as words directly: no KDF, no seed derivation layer.
64-bit blocks -> 6 words each, with 2 parity bits per block.
Wordlist extracted from the RFC's own Appendix A (2048 words, 1-4 chars).
Verified against all three examples in the RFC text, both directions.
"""
import os

WORDS = open(os.path.join(os.path.dirname(__file__), "rfc1751-words.txt")).read().split()
assert len(WORDS) == 2048 and len(set(WORDS)) == 2048


def _parity(bits64: str) -> int:
    return sum(int(bits64[i:i + 2], 2) for i in range(0, 64, 2)) & 0b11


def encode(data: bytes) -> list:
    """Any multiple of 8 bytes -> 6 words per block."""
    assert len(data) % 8 == 0
    out = []
    for off in range(0, len(data), 8):
        bits = "".join(f"{b:08b}" for b in data[off:off + 8])
        bits += f"{_parity(bits):02b}"
        out += [WORDS[int(bits[i:i + 11], 2)] for i in range(0, 66, 11)]
    return out


def decode(words: list) -> bytes:
    assert len(words) % 6 == 0
    out = b""
    for n in range(0, len(words), 6):
        bits = "".join(f"{WORDS.index(w.upper()):011b}" for w in words[n:n + 6])
        data = bits[:64]
        if bits[64:] != f"{_parity(data):02b}":
            raise ValueError(f"parity error in block {n // 6 + 1} (words {n + 1}-{n + 6})")
        out += bytes(int(data[i:i + 8], 2) for i in range(0, 64, 8))
    return out
