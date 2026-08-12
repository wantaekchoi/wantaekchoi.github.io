#!/usr/bin/env python3
"""Re-read a generated sheet and prove it recovers the keys. Prints no secrets.

  python3 verify_sheet.py DIR <pem>:<label> [<pem>:<label> ...]
"""
import os, re, subprocess, sys, tempfile
import bip39, rfc1751

WORD_CELL = re.compile(r'<td class="w">(?:<b>)?([A-Za-z]+)(?:</b>)?([a-z]*)</td>')


def _pub(path):
    return subprocess.run(["openssl", "pkey", "-in", path, "-pubout"],
                          capture_output=True, check=True).stdout


def verify(directory: str, pem: str, label: str) -> None:
    txt = open(os.path.join(directory, "backup.txt")).read()
    htm = open(os.path.join(directory, "backup.html")).read()
    ed = bip39.is_ed25519(pem)

    blk = txt.split(f"[{label}]")[1].split("-" * 72)[0]
    words = {}
    for name, marker in (("rfc", "RFC 1751"), ("bip", "BIP-39")):
        seg = blk.split(marker)[1].split("\n\n")[0]
        words[name] = [w for _, w in re.findall(r"(\d+)\.([A-Za-z]+)", seg)][:24]
        assert len(words[name]) == 24, f"{label}/{name}: {len(words[name])} words in backup.txt"

    hex_seg = blk.split("private scalar (hex)")[1].split("RFC")[0]
    seeds = {"hex": bytes.fromhex("".join(re.findall(r"[0-9a-f]{4}", hex_seg))),
             "rfc": rfc1751.decode(words["rfc"]),
             "bip": bip39.decode(words["bip"])}
    assert len(set(seeds.values())) == 1, f"{label}: encodings disagree ({list(seeds)})"

    hblk = htm.split(f">{label} ", 1)[1].split("</section>")[0]
    hw = [a + b for a, b in WORD_CELL.findall(hblk)]
    assert len(hw) == 48, f"{label}: {len(hw)} word cells in backup.html, expected 48"
    assert [w.upper() for w in hw[:24]] == words["rfc"], f"{label}: html/txt RFC 1751 differ"
    assert hw[24:] == words["bip"], f"{label}: html/txt BIP-39 differ"

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(bip39.rebuild(seeds["rfc"], ed))
        tmp = f.name
    same = _pub(tmp) == _pub(pem)
    os.unlink(tmp)
    assert same, f"{label}: rebuilt key does not match the original public key"
    print(f"{label}: hex = RFC 1751 = BIP-39, html = txt, rebuilt public key matches")


if __name__ == "__main__":
    d = os.path.expanduser(sys.argv[1])
    for spec in sys.argv[2:]:
        p, l = spec.rsplit(":", 1)
        verify(d, os.path.expanduser(p), l)
    print("sheet verified")
