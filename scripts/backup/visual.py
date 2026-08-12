"""Anti-confusion rendering helpers for key material on paper.

Three independent signals so a mis-transcription or a swapped character shows up:
  chunk_color  - background hue derived from the chunk's own bytes; change one
                 character and the colour changes, so a substituted string no
                 longer matches the sheet even if it looks similar.
  randomart    - OpenSSH's Drunken Bishop walk over the public key. A gestalt
                 shape, readable in black and white, that no near-miss reproduces.
  HOMOGLYPHS   - the character pairs a handwritten copy actually confuses.
"""
import hashlib

HOMOGLYPHS = ["0 O o", "1 l I", "5 S", "8 B", "2 Z", "rn m", "vv w"]
# base58btc omits 0 O I l by design; base64url does not, so it needs more care.
ALPHABET_NOTE = {
    "base58btc": "base58btc omits 0 O I l by design - homoglyph-safe",
    "base64url": "base64url contains 0 O I l 1 - compare colours, not shapes",
    "hex": "hex is 0-9 a-f - only 0/O and 1/l can be confused",
}


def chunk(s: str, n: int = 4) -> list:
    return [s[i:i + n] for i in range(0, len(s), n)]


def chunk_color(text: str, pos: int) -> str:
    """Deterministic pastel background. Depends on content AND position."""
    h = hashlib.sha256(f"{pos}:{text}".encode()).digest()
    return f"hsl({h[0] * 360 // 256}deg 72% 88%)"


def randomart(digest: bytes, title: str = "") -> str:
    """OpenSSH Drunken Bishop (ssh-keygen -lv). 17x9 field, two bits per step.

    Walk the key FINGERPRINT, not the key itself: a longer input saturates the
    grid and every key starts to look alike.
    """
    w, h = 17, 9
    grid = [[0] * w for _ in range(h)]
    x, y = w // 2, h // 2
    start = (x, y)
    for byte in digest:
        for s in range(4):
            p = (byte >> (2 * s)) & 0b11
            x = min(w - 1, max(0, x + (1 if p & 0b01 else -1)))
            y = min(h - 1, max(0, y + (1 if p & 0b10 else -1)))
            grid[y][x] += 1
    chars = " .o+=*BOX@%&#/^"
    rows = ["".join(chars[min(c, len(chars) - 1)] for c in row) for row in grid]
    rows[start[1]] = rows[start[1]][:start[0]] + "S" + rows[start[1]][start[0] + 1:]
    rows[y] = rows[y][:x] + "E" + rows[y][x + 1:]
    cap = f"[{title}]".center(w, "-")[:w]
    return "\n".join(["+" + cap + "+"] + [f"|{r}|" for r in rows] + ["+" + "-" * w + "+"])
