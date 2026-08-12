"""Render the unsigned DIF Domain Linkage Credential from config.json.

The signed result proves the key named in assertionMethod is actually held, rather
than merely listed. For did:web that is nearly a tautology - whoever controls the
origin controls the DID document - so this file is completeness, not a payoff.

The dates appear twice, under both specs' names. DIF requires issuanceDate and
expirationDate; VC 2.0 renamed them to validFrom and validUntil and defines neither
old name, and its context carries no @vocab - so writing the DIF names alone drops
them silently from the signed graph, the exact data loss Data Integrity 1.0 tells a
processor to reject. Defining the two old terms inline restores them: 9 quads,
safe mode clean, every date cryptographically protected. Ugly, but a DIF verifier
rejects the entry outright without them, and a VC 2.0 one ignores what it does not
know.

The dates come from config.json, never from the clock, so an unchanged config
re-renders byte for byte and the workflow has nothing to commit.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RESOURCE_CONTEXT = "https://identity.foundation/.well-known/did-configuration/v1"

# Inline, so there is no fourth file to pin and nothing to fetch while signing.
# VC 2.0 leaves both names undefined, and an undefined term is dropped, not signed.
VC11_DATES = {
    "issuanceDate": {"@id": "https://www.w3.org/2018/credentials#issuanceDate",
                     "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "expirationDate": {"@id": "https://www.w3.org/2018/credentials#expirationDate",
                       "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
}


def build(config: dict) -> dict:
    did = f"did:web:{config['domain']}"
    linkage = config["domain_linkage"]
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            RESOURCE_CONTEXT,
            VC11_DATES,
        ],
        # No "id": DIF says it MUST NOT be present.
        "type": ["VerifiableCredential", "DomainLinkageCredential"],
        # A plain string, not a Profile object - DIF verifiers compare issuer,
        # subject and credentialSubject.id for equality.
        "issuer": did,
        "validFrom": linkage["valid_from"],
        "validUntil": linkage["valid_until"],
        # The same instants under the names DIF's MUSTs use.
        "issuanceDate": linkage["valid_from"],
        "expirationDate": linkage["valid_until"],
        "credentialSubject": {
            "id": did,
            # WHATWG origin serialisation: scheme + host, no trailing slash, no path.
            "origin": f"https://{config['domain']}",
        },
    }


def wrap(credential: dict) -> dict:
    """The served resource. DIF: additional members MUST NOT be present."""
    return {"@context": RESOURCE_CONTEXT, "linked_dids": [credential]}


def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wrap", metavar="SIGNED", type=Path,
                    help="wrap an already signed credential into "
                         ".well-known/did-configuration.json")
    args = ap.parse_args()
    if args.wrap:
        _write_json(ROOT / ".well-known" / "did-configuration.json",
                    wrap(json.loads(args.wrap.read_text())))
        return
    config = json.loads((ROOT / "config.json").read_text())
    credential = build(config)
    _write_json(ROOT / "build" / "did-configuration.unsigned.json", credential)
    # Same handshake as generate_badge.py, but its own file: that one opens
    # build/params.env with "w" and would truncate whatever we left there.
    # CREATED is the config-supplied validFrom, so re-running changes nothing.
    env = ROOT / "build" / "domain-linkage.env"
    env.write_text(
        f"VERIFICATION_METHOD=did:web:{config['domain']}#{config['keys']['ed25519']['id']}\n"
        f"CREATED={credential['validFrom']}\n")
    print(f"wrote {env}")


if __name__ == "__main__":
    main()
