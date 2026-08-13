"""Signed credential -> credentials/contributions.svg, an Open Badges 3.0 baked badge.

Baking (OB 3.0 section 5.3.2) puts the credential inside the image, so the proof
travels wherever the file is copied instead of only resolving from this domain.
The proof is embedded rather than VC-JWT, so per the specification the JSON goes
in the body of a single <openbadges:credential> tag wrapped in CDATA, and the
verify attribute is omitted.

Baking happens after signing and never touches the credential: whatever comes out
of the signer is what goes in, byte for byte. verify() takes it back out the way
section 5.3.2.2 says a reader would and fails the run on any difference, because
an image carrying a credential that no longer verifies is worse than no image.

The picture itself carries no counts. The credential inside is the record, and a
number painted on the outside is a second copy that can disagree with it.
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OB_NS = "https://purl.imsglobal.org/ob/v3p0"
CREDENTIAL_TAG = f"{{{OB_NS}}}credential"

# index.html's stack. No @font-face: a baked badge is copied around and must not
# depend on fetching anything.
FONT = "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif"


# Rough advance width of a sans-serif glyph as a fraction of the font size. Only
# used to shrink text that would otherwise run past the edge, so an estimate is
# enough and erring wide is the safe direction.
GLYPH_RATIO = 0.58
TEXT_BOX = 432


def fit(text: str, preferred: int) -> int:
    """Largest size at or below preferred that keeps text inside TEXT_BOX.

    The achievement name comes from badge.json and the issuer name from a GitHub
    profile, so neither has a length this file can assume."""
    if not text:
        return preferred
    return max(11, min(preferred, int(TEXT_BOX / (len(text) * GLYPH_RATIO))))


def render(credential: dict, payload: str) -> str:
    achievement = credential["credentialSubject"]["achievement"]
    name = achievement["name"]
    issuer = credential["issuer"]["name"]
    domain = credential["id"].split("/")[2]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:openbadges="{OB_NS}"
     viewBox="0 0 512 512" width="512" height="512"
     role="img" aria-label="{_esc(name)}, issued to {_esc(issuer)}">
<openbadges:credential><![CDATA[{payload}]]></openbadges:credential>
<title>{_esc(name)}</title>
<rect width="512" height="512" rx="72" fill="#12161a"/>
<circle cx="256" cy="196" r="86" fill="none" stroke="#4a5560" stroke-width="6"/>
<circle cx="256" cy="196" r="12" fill="#8b96a2"/>
<text x="256" y="352" text-anchor="middle" fill="#e8ecf0"
      font-family="{FONT}" font-size="{fit(name, 36)}">{_esc(name)}</text>
<text x="256" y="398" text-anchor="middle" fill="#8b96a2"
      font-family="{FONT}" font-size="{fit(issuer, 24)}">{_esc(issuer)}</text>
<text x="256" y="446" text-anchor="middle" fill="#5d6874"
      font-family="{FONT}" font-size="{fit(domain, 19)}">{_esc(domain)}</text>
</svg>
"""


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def extract(svg: str) -> str:
    """Read the credential back out, as OB 3.0 section 5.3.2.2 describes."""
    root = ET.fromstring(svg)
    found = root.findall(CREDENTIAL_TAG)
    if len(found) != 1:
        # "There MUST be only one <openbadges:credential> tag in an SVG."
        raise ValueError(f"expected exactly one {CREDENTIAL_TAG}, found {len(found)}")
    if list(root)[0] is not found[0]:
        # "Directly after the <svg> tag, add an <openbadges:credential> tag."
        raise ValueError("openbadges:credential is not the first child of <svg>")
    return found[0].text or ""


def bake(credential: dict, payload: str) -> str:
    if "]]>" in payload:
        # CDATA has no escape for its own terminator, so a payload containing one
        # would close the section early and silently truncate the credential.
        raise ValueError("credential contains ]]> and cannot be wrapped in CDATA")
    svg = render(credential, payload)
    recovered = extract(svg)
    if recovered != payload:
        raise ValueError("credential does not survive a bake/extract round trip")
    return svg


def main() -> None:
    signed = ROOT / "credentials" / "contributions.json"
    payload = signed.read_text()
    out = ROOT / "credentials" / "contributions.svg"
    out.write_text(bake(json.loads(payload), payload))
    print(f"wrote credentials/contributions.svg ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
