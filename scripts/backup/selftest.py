#!/usr/bin/env python3
"""Wordlist and codec self-test. Uses only the vectors published in the specs."""
import hashlib, os, sys
import bip39, rfc1751, visual

here = os.path.dirname(os.path.abspath(__file__))

# BIP-39 wordlist provenance
digest = hashlib.sha256(open(os.path.join(here, "bip39-english.txt"), "rb").read()).hexdigest()
assert digest == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", digest
assert len({w[:4] for w in bip39.WORDS}) == 2048, "4-letter prefixes must stay unique"

# BIP-39 official vectors (trezor/python-mnemonic), 256-bit entries only
BIP39_VECTORS = [
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon art"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank year wave "
     "sausage worth useful legal winner thank year wave sausage worth title"),
    ("8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
     "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo vote"),
]
for ent, mnemonic in BIP39_VECTORS:
    raw = bytes.fromhex(ent)
    assert " ".join(bip39.encode(raw)) == mnemonic, ent
    assert bip39.decode(mnemonic.split()) == raw, ent

# RFC 1751 vectors, straight from the RFC text
RFC_VECTORS = [
    ("EB33F77EE73D4053", "TIDE ITCH SLOW REIN RULE MOT"),
    ("CCAC2AED591056BE4F90FD441C534766",
     "RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE"),
    ("EFF81F9BFBC65350920CDD7416DE8009",
     "TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL"),
]
for hexval, mnemonic in RFC_VECTORS:
    raw = bytes.fromhex(hexval)
    assert " ".join(rfc1751.encode(raw)) == mnemonic, hexval
    assert rfc1751.decode(mnemonic.split()) == raw, hexval

# Corrupted transcriptions must be rejected, not silently decoded
for bad, codec in ((["TIDE", "ITCH", "SLOW", "REIN", "RULE", "TIDE"], rfc1751),
                   (BIP39_VECTORS[0][1].split()[:23] + ["zoo"], bip39)):
    try:
        codec.decode(bad)
        raise AssertionError(f"{codec.__name__} accepted a corrupted word list")
    except ValueError:
        pass

# A substituted homoglyph must change the colour, or the sheet proves nothing
assert visual.chunk_color("U0Mc", 0) != visual.chunk_color("UOMc", 0)
assert visual.randomart(b"\x00" * 32) != visual.randomart(b"\x01" * 32)

print(f"selftest OK - BIP-39 {len(BIP39_VECTORS)} vectors, RFC 1751 {len(RFC_VECTORS)} vectors, "
      "corruption rejected, colour and randomart discriminate")
