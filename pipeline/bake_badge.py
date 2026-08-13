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
import base64
import json
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OB_NS = "https://purl.imsglobal.org/ob/v3p0"
CREDENTIAL_TAG = f"{{{OB_NS}}}credential"

# index.html's stack. No @font-face: a baked badge is copied around and must not
# depend on fetching anything.
FONT = "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif"

# The avatar is drawn from bytes, not from its URL. A baked badge is meant to be
# copied, and an <image href="https://..."> would render as a hole everywhere the
# copy is opened offline or by a renderer that refuses remote references. 256 is
# the smallest size that still covers the 172px circle on a 2x display.
AVATAR_SIZE = 256


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


def render(credential: dict, payload: str, avatar: str) -> str:
    achievement = credential["credentialSubject"]["achievement"]
    name = achievement["name"]
    issuer = credential["issuer"]["name"]
    domain = credential["id"].split("/")[2]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:openbadges="{OB_NS}"
     viewBox="0 0 512 512" width="512" height="512"
     role="img" aria-label="{_esc(name)}, issued to {_esc(issuer)}">
<openbadges:credential><![CDATA[{payload}]]></openbadges:credential>
<title>{_esc(name)}</title>
<defs><clipPath id="avatar"><circle cx="256" cy="192" r="96"/></clipPath></defs>
<rect width="512" height="512" rx="72" fill="#12161a"/>
<image x="160" y="96" width="192" height="192" clip-path="url(#avatar)"
       preserveAspectRatio="xMidYMid slice"
       href="{avatar}" xlink:href="{avatar}"/>
<circle cx="256" cy="192" r="96" fill="none" stroke="#4d5966" stroke-width="3"/>
<circle cx="256" cy="192" r="104" fill="none" stroke="#232b33" stroke-width="2"/>
<text x="256" y="360" text-anchor="middle" fill="#e8ecf0"
      font-family="{FONT}" font-size="{fit(name, 36)}">{_esc(name)}</text>
<text x="256" y="404" text-anchor="middle" fill="#8b96a2"
      font-family="{FONT}" font-size="{fit(issuer, 24)}">{_esc(issuer)}</text>
<text x="256" y="450" text-anchor="middle" fill="#5d6874"
      font-family="{FONT}" font-size="{fit(domain, 19)}">{_esc(domain)}</text>
</svg>
"""


def fetch_avatar(credential: dict) -> str:
    """The issuer image the credential already names, as a data URI.

    Asking for the URL in the credential rather than rebuilding it keeps the
    picture and the proof pointing at the same thing."""
    url = f"{credential['issuer']['image']['id']}?size={AVATAR_SIZE}"
    req = urllib.request.Request(url, headers={"User-Agent": "well-known-pipeline"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        media = resp.headers.get("Content-Type", "image/png").split(";")[0].strip()
        return f"data:{media};base64,{base64.b64encode(resp.read()).decode()}"


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


def bake(credential: dict, payload: str, avatar: str) -> str:
    if "]]>" in payload:
        # CDATA has no escape for its own terminator, so a payload containing one
        # would close the section early and silently truncate the credential.
        raise ValueError("credential contains ]]> and cannot be wrapped in CDATA")
    svg = render(credential, payload, avatar)
    recovered = extract(svg)
    if recovered != payload:
        raise ValueError("credential does not survive a bake/extract round trip")
    return svg


def main() -> None:
    signed = ROOT / "credentials" / "contributions.json"
    payload = signed.read_text()
    out = ROOT / "credentials" / "contributions.svg"
    credential = json.loads(payload)
    out.write_text(bake(credential, payload, fetch_avatar(credential)))
    print(f"wrote credentials/contributions.svg ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
