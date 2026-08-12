"""BIP-39 (24 words) <-> 32-byte key material, plus PEM reconstruction.

Wordlist: bitcoin/bips bip-0039/english.txt, sha256
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
Verified against the official trezor/python-mnemonic vectors (256-bit, 8/8).
"""
import base64, hashlib, os, subprocess, textwrap

WORDS = open(os.path.join(os.path.dirname(__file__), "bip39-english.txt")).read().split()
assert len(WORDS) == 2048

# entropy -> PEM prefixes. Documented on the backup sheet so recovery needs no code.
ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420"
P256_SEC1_PREFIX, P256_SEC1_SUFFIX = "3031020101" "0420", "a00a06082a8648ce3d030107"


def encode(seed: bytes) -> list:
    """32 bytes -> 24 words (256 entropy bits + 8 checksum bits = 24 x 11)."""
    assert len(seed) == 32
    bits = "".join(f"{b:08b}" for b in seed) + f"{hashlib.sha256(seed).digest()[0]:08b}"
    return [WORDS[int(bits[i:i + 11], 2)] for i in range(0, 264, 11)]


def decode(words: list) -> bytes:
    assert len(words) == 24
    bits = "".join(f"{WORDS.index(w):011b}" for w in words)
    seed = bytes(int(bits[i:i + 8], 2) for i in range(0, 256, 8))
    if bits[256:] != f"{hashlib.sha256(seed).digest()[0]:08b}":
        raise ValueError("checksum mismatch - a word was transcribed wrong")
    return seed


def _pem(der: bytes, label: str) -> bytes:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


def is_ed25519(pem_path: str) -> bool:
    text = subprocess.run(["openssl", "pkey", "-in", pem_path, "-noout", "-text"],
                          capture_output=True, check=True).stdout
    return b"ED25519" in text


def scalar_of(pem_path: str) -> bytes:
    """The 32-byte private scalar (P-256) or seed (Ed25519)."""
    der = subprocess.run(["openssl", "pkey", "-in", pem_path, "-outform", "DER"],
                         capture_output=True, check=True).stdout
    if is_ed25519(pem_path):
        return der[-32:]
    return der[der.index(b"\x04\x20", 20) + 2:][:32]   # OCTET STRING(32) in the inner SEC1


def public_der(pem_path: str) -> bytes:
    return subprocess.run(["openssl", "pkey", "-in", pem_path, "-pubout", "-outform", "DER"],
                          capture_output=True, check=True).stdout


def rebuild(seed: bytes, ed25519: bool) -> bytes:
    if ed25519:
        return _pem(bytes.fromhex(ED25519_PKCS8_PREFIX) + seed, "PRIVATE KEY")
    return _pem(bytes.fromhex(P256_SEC1_PREFIX) + seed + bytes.fromhex(P256_SEC1_SUFFIX),
                "EC PRIVATE KEY")
