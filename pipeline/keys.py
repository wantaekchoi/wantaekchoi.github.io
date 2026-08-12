"""개인키(base64 PEM, 환경변수) 로드와 DID 공개키 표현(JWK/Multikey) 변환."""
import base64
import os
import subprocess

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    n = 0
    for c in text:
        n = n * 58 + B58_ALPHABET.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + body


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def load_private_pem(env_name: str) -> bytes:
    raw = os.environ.get(env_name)
    if not raw:
        raise SystemExit(f"missing env: {env_name}")
    return base64.b64decode(raw)


def public_spki_der(private_pem: bytes) -> bytes:
    return subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"],
        input=private_pem, capture_output=True, check=True,
    ).stdout




def ed25519_public_multibase(private_pem: bytes) -> str:
    der = public_spki_der(private_pem)
    return "z" + b58encode(bytes.fromhex("ed01") + der[-32:])
